// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package httpcallout

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// fakeClient records what it was asked and answers with a canned decision.
type fakeClient struct {
	calls     []Invocation
	decide    func(inv Invocation) (Decision, error)
	callCount int
}

func (f *fakeClient) Call(_ context.Context, _ Config, inv Invocation) (Decision, error) {
	f.calls = append(f.calls, inv)
	f.callCount++
	if f.decide == nil {
		return Decision{
			Version:   ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    actionPtr(ActionContinue),
		}, nil
	}
	return f.decide(inv)
}

// newFilter builds one filter the way the engine does, per direction.
func newFilter(t *testing.T, cfg Config, client Client) filter.Filter {
	t.Helper()
	effective := testConfig(t, cfg)
	return NewDescriptor(Deps{Client: client}).New(filter.RuleConfig[Config]{
		ID:  testUnitID(),
		Cfg: effective,
	})
}

func TestDescriptorDeclaresEveryPhase(t *testing.T) {
	d := NewDescriptor(Deps{Client: &fakeClient{}})
	if d.Name != FilterName {
		t.Errorf("name = %q, want %q", d.Name, FilterName)
	}
	want := filter.PhaseRequestHeaders | filter.PhaseRequestBody |
		filter.PhaseResponseHeaders | filter.PhaseResponseBody
	if d.Phases != want {
		t.Errorf("phases = %08b, want %08b", d.Phases, want)
	}
	// Build enforces the header/body implications; going through Define proves
	// the descriptor is actually registrable.
	if _, err := filter.Build(NewDefinition(Deps{Client: &fakeClient{}})); err != nil {
		t.Fatalf("Build: %v", err)
	}
}

// TestDescriptorFailurePolicyIsInverted pins the polarity: FailOpen is the
// explicit opt-out, so the default zero value must fail closed.
func TestDescriptorFailurePolicyIsInverted(t *testing.T) {
	d := NewDescriptor(Deps{Client: &fakeClient{}})
	if d.OnError == nil {
		t.Fatal("descriptor declared no OnError, which would default to FailClosed by accident rather than on purpose")
	}
	if got := d.OnError(Config{Request: &PhaseConfig{Body: true}}); got != filter.FailClosed {
		t.Errorf("OnError(default) = %v, want FailClosed", got)
	}
	if got := d.OnError(Config{Request: &PhaseConfig{Body: true}, FailOpen: true}); got != filter.FailOpen {
		t.Errorf("OnError(FailOpen) = %v, want FailOpen", got)
	}
}

// TestDescriptorSubscribesOnlyWhenTheResponsePhaseIsEnabled is the phase-
// subscription bite: without SubscribesOf the response walk skips the pair
// entirely and the whole response half is dead code, and returning a non-zero
// phase for a request-only config makes those requests pay ResponseHeaderMode
// SEND for nothing.
func TestDescriptorSubscribesOnlyWhenTheResponsePhaseIsEnabled(t *testing.T) {
	d := NewDescriptor(Deps{Client: &fakeClient{}})
	if d.SubscribesOf == nil {
		t.Fatal("descriptor declared no SubscribesOf, so the response walk would never dispatch it")
	}
	if got := d.SubscribesOf(Config{Request: &PhaseConfig{Body: true}}); got != 0 {
		t.Errorf("SubscribesOf(request only) = %08b, want 0", got)
	}
	if got := d.SubscribesOf(Config{Response: &PhaseConfig{Body: true}}); got != filter.PhaseResponseHeaders {
		t.Errorf("SubscribesOf(response) = %08b, want PhaseResponseHeaders", got)
	}
	// A bodyless response phase still runs in the response-headers phase, so the
	// subscription is about the phase existing, not about buffering.
	if got := d.SubscribesOf(Config{Response: &PhaseConfig{}}); got != filter.PhaseResponseHeaders {
		t.Errorf("SubscribesOf(bodyless response) = %08b, want PhaseResponseHeaders", got)
	}
	if got := d.SubscribesOf(Config{Request: &PhaseConfig{Body: true}, Response: &PhaseConfig{Body: true}}); got != filter.PhaseResponseHeaders {
		t.Errorf("SubscribesOf(both) = %08b, want PhaseResponseHeaders", got)
	}
}

func TestFilterRequestHeadersAsksForTheBodyOnlyWhenThePhaseCollectsOne(t *testing.T) {
	ctx := context.Background()
	st := testStream()

	t.Run("request enabled with body collection", func(t *testing.T) {
		f := newFilter(t, Config{Request: &PhaseConfig{Body: true}}, &fakeClient{})
		act, err := f.OnRequestHeaders(ctx, st)
		if err != nil {
			t.Fatalf("OnRequestHeaders: %v", err)
		}
		if act.Kind() != filter.KindNeedBody {
			t.Fatalf("kind = %v, want KindNeedBody", act.Kind())
		}
	})

	t.Run("response only", func(t *testing.T) {
		f := newFilter(t, Config{Response: &PhaseConfig{Body: true}}, &fakeClient{})
		act, err := f.OnRequestHeaders(ctx, st)
		if err != nil {
			t.Fatalf("OnRequestHeaders: %v", err)
		}
		if !act.Equal(filter.Continue()) {
			t.Fatalf("action = %#v, want a bare Continue", act)
		}
	})
}

func TestFilterResponseHeadersAsksForTheBodyOnlyWhenThePhaseCollectsOne(t *testing.T) {
	ctx := context.Background()
	st := testStream()

	t.Run("response enabled with body collection", func(t *testing.T) {
		f := newFilter(t, Config{Response: &PhaseConfig{Body: true}}, &fakeClient{})
		act, err := f.OnResponseHeaders(ctx, st)
		if err != nil {
			t.Fatalf("OnResponseHeaders: %v", err)
		}
		if act.Kind() != filter.KindNeedBody {
			t.Fatalf("kind = %v, want KindNeedBody", act.Kind())
		}
	})

	t.Run("request only", func(t *testing.T) {
		f := newFilter(t, Config{Request: &PhaseConfig{Body: true}}, &fakeClient{})
		act, err := f.OnResponseHeaders(ctx, st)
		if err != nil {
			t.Fatalf("OnResponseHeaders: %v", err)
		}
		if !act.Equal(filter.Continue()) {
			t.Fatalf("action = %#v, want a bare Continue", act)
		}
	})
}

// TestFilterBodylessPhaseCallsOutFromTheHeadersPhase is the dispatch-point bite.
// Returning NeedBody for a phase that never reads the body would make Envoy
// buffer the whole message for nothing, which is exactly what Body: false exists
// to avoid — so the callout has to move into the headers phase instead.
func TestFilterBodylessPhaseCallsOutFromTheHeadersPhase(t *testing.T) {
	ctx := context.Background()

	t.Run("request", func(t *testing.T) {
		value := "true"
		client := &fakeClient{decide: func(inv Invocation) (Decision, error) {
			return Decision{
				Version:   ProtocolVersion,
				Phase:     inv.Phase,
				RequestID: inv.Request.ID,
				Action:    actionPtr(ActionContinue),
				Request: &RequestMutation{Headers: []HeaderMutation{
					{Operation: HeaderSet, Name: "X-Reviewed", Value: &value},
				}},
			}, nil
		}}
		f := newFilter(t, Config{Request: &PhaseConfig{}}, client)

		act, err := f.OnRequestHeaders(ctx, testStream())
		if err != nil {
			t.Fatalf("OnRequestHeaders: %v", err)
		}
		if act.Kind() == filter.KindNeedBody {
			t.Fatal("a bodyless request phase asked for the body, so Envoy would buffer for a callout that never reads it")
		}
		if client.callCount != 1 {
			t.Fatalf("the client was called %d times, want 1 from the headers phase", client.callCount)
		}
		if client.calls[0].Phase != PhaseRequest {
			t.Errorf("invocation phase = %q, want %q", client.calls[0].Phase, PhaseRequest)
		}
		want := filter.Continue(filter.SetHeader("x-reviewed", "true"))
		if !act.Equal(want) {
			t.Fatalf("action = %#v, want %#v", act.Mutations(), want.Mutations())
		}
	})

	t.Run("response", func(t *testing.T) {
		client := &fakeClient{}
		f := newFilter(t, Config{Response: &PhaseConfig{}}, client)

		act, err := f.OnResponseHeaders(ctx, testStream())
		if err != nil {
			t.Fatalf("OnResponseHeaders: %v", err)
		}
		if act.Kind() == filter.KindNeedBody {
			t.Fatal("a bodyless response phase asked for the body")
		}
		if client.callCount != 1 {
			t.Fatalf("the client was called %d times, want 1 from the headers phase", client.callCount)
		}
		if client.calls[0].Phase != PhaseResponse {
			t.Errorf("invocation phase = %q, want %q", client.calls[0].Phase, PhaseResponse)
		}
	})
}

// TestFilterHeadersPhaseRespondBlocks pins that terminating from the headers
// phase works in both directions. A bodyless request-phase respond is the whole
// point: it short-circuits before the body is ever read.
func TestFilterHeadersPhaseRespondBlocks(t *testing.T) {
	ctx := context.Background()
	status := 403
	respond := func(inv Invocation) (Decision, error) {
		return Decision{
			Version:   ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    actionPtr(ActionRespond),
			Reason:    "denied at headers",
			Response:  &ResponseMutation{StatusCode: &status},
		}, nil
	}

	for _, tc := range []struct {
		name   string
		cfg    Config
		invoke func(filter.Filter) (filter.Action, error)
	}{
		{
			name: "request",
			cfg:  Config{Request: &PhaseConfig{}},
			invoke: func(f filter.Filter) (filter.Action, error) {
				return f.OnRequestHeaders(ctx, testStream())
			},
		},
		{
			name: "response",
			cfg:  Config{Response: &PhaseConfig{}},
			invoke: func(f filter.Filter) (filter.Action, error) {
				return f.OnResponseHeaders(ctx, testStream())
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFilter(t, tc.cfg, &fakeClient{decide: respond})
			act, err := tc.invoke(f)
			if err != nil {
				t.Fatalf("headers phase: %v", err)
			}
			reply, stopping := act.Reply()
			if !stopping {
				t.Fatalf("action = %#v, want a terminal Stop from the headers phase", act)
			}
			if !reflect.DeepEqual(reply, filter.Reply{Status: 403, Details: "denied at headers"}) {
				t.Fatalf("reply = %#v, want the callout's status and reason", reply)
			}
		})
	}
}

// TestFilterHeadersPhaseIsANoOpWhenTheDirectionIsDisabled keeps the guard honest
// now that the headers phase can call out: without it a request-only config would
// call the endpoint from the response-headers phase too.
func TestFilterHeadersPhaseIsANoOpWhenTheDirectionIsDisabled(t *testing.T) {
	ctx := context.Background()

	t.Run("request headers without the request phase", func(t *testing.T) {
		client := &fakeClient{}
		f := newFilter(t, Config{Response: &PhaseConfig{}}, client)
		act, err := f.OnRequestHeaders(ctx, testStream())
		if err != nil {
			t.Fatalf("OnRequestHeaders: %v", err)
		}
		if !act.Equal(filter.Continue()) {
			t.Fatalf("action = %#v, want a bare Continue", act)
		}
		if client.callCount != 0 {
			t.Fatalf("the client was called %d times, want 0", client.callCount)
		}
	})

	t.Run("response headers without the response phase", func(t *testing.T) {
		client := &fakeClient{}
		f := newFilter(t, Config{Request: &PhaseConfig{}}, client)
		act, err := f.OnResponseHeaders(ctx, testStream())
		if err != nil {
			t.Fatalf("OnResponseHeaders: %v", err)
		}
		if !act.Equal(filter.Continue()) {
			t.Fatalf("action = %#v, want a bare Continue", act)
		}
		if client.callCount != 0 {
			t.Fatalf("the client was called %d times, want 0", client.callCount)
		}
	})
}

// TestFilterBodyPhasesAreGuardedByConfig pins that a body callback the filter
// never asked for is a no-op. Config is the guard rather than a pending flag: a
// fresh Filter exists per direction, so no flag could carry across them anyway.
func TestFilterBodyPhasesAreGuardedByConfig(t *testing.T) {
	ctx := context.Background()
	st := testStream()
	body := filter.Body{Bytes: []byte("body"), Complete: true}

	t.Run("request body without the request phase", func(t *testing.T) {
		client := &fakeClient{}
		f := newFilter(t, Config{Response: &PhaseConfig{Body: true}}, client)
		act, err := f.OnRequestBody(ctx, st, body)
		if err != nil {
			t.Fatalf("OnRequestBody: %v", err)
		}
		if !act.Equal(filter.Continue()) {
			t.Fatalf("action = %#v, want a bare Continue", act)
		}
		if client.callCount != 0 {
			t.Fatalf("the client was called %d times, want 0", client.callCount)
		}
	})

	t.Run("response body without the response phase", func(t *testing.T) {
		client := &fakeClient{}
		f := newFilter(t, Config{Request: &PhaseConfig{Body: true}}, client)
		act, err := f.OnResponseBody(ctx, st, body)
		if err != nil {
			t.Fatalf("OnResponseBody: %v", err)
		}
		if !act.Equal(filter.Continue()) {
			t.Fatalf("action = %#v, want a bare Continue", act)
		}
		if client.callCount != 0 {
			t.Fatalf("the client was called %d times, want 0", client.callCount)
		}
	})
}

func TestFilterRequestBodyCallsOutAndAppliesTheDecision(t *testing.T) {
	value := "true"
	client := &fakeClient{decide: func(inv Invocation) (Decision, error) {
		return Decision{
			Version:   ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    actionPtr(ActionContinue),
			Request: &RequestMutation{Headers: []HeaderMutation{
				{Operation: HeaderSet, Name: "X-Reviewed", Value: &value},
			}},
		}, nil
	}}
	f := newFilter(t, Config{Request: &PhaseConfig{Body: true}}, client)

	act, err := f.OnRequestBody(context.Background(), testStream(),
		filter.Body{Bytes: []byte(`{"input":"hi"}`), Complete: true})
	if err != nil {
		t.Fatalf("OnRequestBody: %v", err)
	}
	want := filter.Continue(filter.SetHeader("x-reviewed", "true"))
	if !act.Equal(want) {
		t.Fatalf("action = %#v, want %#v", act.Mutations(), want.Mutations())
	}
	if len(client.calls) != 1 {
		t.Fatalf("the client saw %d invocations, want 1", len(client.calls))
	}
	got := client.calls[0]
	if got.Phase != PhaseRequest {
		t.Errorf("invocation phase = %q, want %q", got.Phase, PhaseRequest)
	}
	if got.Request.Body == nil || *got.Request.Body != `{"input":"hi"}` {
		t.Errorf("invocation body = %#v, want the buffered body", got.Request.Body)
	}
	if got.Policy != (PolicyContext{Scope: "default/profile", Rule: "inspect", Ordinal: 2}) {
		t.Errorf("invocation policy = %#v, want the rule identity", got.Policy)
	}
}

func TestFilterResponseBodyCallsOutAndAppliesTheDecision(t *testing.T) {
	status := 403
	client := &fakeClient{decide: func(inv Invocation) (Decision, error) {
		return Decision{
			Version:   ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    actionPtr(ActionRespond),
			Reason:    "secret in response",
			Response:  &ResponseMutation{StatusCode: &status},
		}, nil
	}}
	f := newFilter(t, Config{Response: &PhaseConfig{Body: true}}, client)

	act, err := f.OnResponseBody(context.Background(), testStream(),
		filter.Body{Bytes: []byte("leaked"), Complete: true})
	if err != nil {
		t.Fatalf("OnResponseBody: %v", err)
	}
	reply, stopping := act.Reply()
	if !stopping {
		t.Fatalf("action = %#v, want a terminal Stop", act)
	}
	if !reflect.DeepEqual(reply, filter.Reply{Status: 403, Details: "secret in response"}) {
		t.Fatalf("reply = %#v, want the callout's status and reason", reply)
	}
	if len(client.calls) != 1 || client.calls[0].Phase != PhaseResponse {
		t.Fatalf("client calls = %#v, want one response-phase invocation", client.calls)
	}
}

func TestFilterReturnsAnErrorForEveryFailureMode(t *testing.T) {
	ctx := context.Background()
	transportFailure := errors.New("dial tcp 10.1.2.3:443: connection refused")

	for _, tc := range []struct {
		name    string
		cfg     Config
		client  *fakeClient
		body    filter.Body
		wantErr string
	}{
		{
			name:    "client failure",
			cfg:     Config{Request: &PhaseConfig{Body: true}},
			client:  &fakeClient{decide: func(Invocation) (Decision, error) { return Decision{}, transportFailure }},
			body:    filter.Body{Complete: true},
			wantErr: "callout",
		},
		{
			name:    "body over the limit",
			cfg:     Config{Request: &PhaseConfig{Body: true}, MaxBodyBytes: 4},
			client:  &fakeClient{},
			body:    filter.Body{Bytes: []byte("more than four"), Complete: true},
			wantErr: "limit",
		},
		{
			name:    "non-utf8 body",
			cfg:     Config{Request: &PhaseConfig{Body: true}},
			client:  &fakeClient{},
			body:    filter.Body{Bytes: []byte{0xff}, Complete: true},
			wantErr: "utf-8",
		},
		{
			name: "decision that fails Validate",
			cfg:  Config{Request: &PhaseConfig{Body: true}},
			client: &fakeClient{decide: func(inv Invocation) (Decision, error) {
				// The echo names another exchange.
				return Decision{
					Version:   ProtocolVersion,
					Phase:     inv.Phase,
					RequestID: "req-999",
					Action:    actionPtr(ActionContinue),
				}, nil
			}},
			body:    filter.Body{Complete: true},
			wantErr: "request id",
		},
		{
			name: "decision for the wrong phase",
			cfg:  Config{Request: &PhaseConfig{Body: true}},
			client: &fakeClient{decide: func(inv Invocation) (Decision, error) {
				return Decision{
					Version:   ProtocolVersion,
					Phase:     PhaseResponse,
					RequestID: inv.Request.ID,
					Action:    actionPtr(ActionContinue),
				}, nil
			}},
			body:    filter.Body{Complete: true},
			wantErr: "phase",
		},
		{
			name: "decision mutating a forbidden header",
			cfg:  Config{Request: &PhaseConfig{Body: true}},
			client: &fakeClient{decide: func(inv Invocation) (Decision, error) {
				value := "0"
				return Decision{
					Version:   ProtocolVersion,
					Phase:     inv.Phase,
					RequestID: inv.Request.ID,
					Action:    actionPtr(ActionContinue),
					Request: &RequestMutation{Headers: []HeaderMutation{
						{Operation: HeaderSet, Name: "Content-Length", Value: &value},
					}},
				}, nil
			}},
			body:    filter.Body{Complete: true},
			wantErr: "framing",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFilter(t, tc.cfg, tc.client)
			act, err := f.OnRequestBody(ctx, testStream(), tc.body)
			if err == nil {
				t.Fatalf("OnRequestBody returned %#v, want an error for the framework to resolve", act)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
			// A failure must never hand-build its own deny: the framework
			// generates one from OnError, so the action stays zero.
			if _, stopping := act.Reply(); stopping {
				t.Errorf("action = %#v, want the zero Action rather than a hand-built deny", act)
			}
		})
	}
}

// TestFilterErrorsHideTheEndpointAndRemoteText mirrors tokentransform's
// blockReply hygiene: the deny body reaches an untrusted client, so nothing on
// this path may name the endpoint or quote the remote.
func TestFilterErrorsHideTheEndpointAndRemoteText(t *testing.T) {
	cfg := testConfig(t, Config{Request: &PhaseConfig{Body: true}})
	// The real HTTPClient scrubs the URL; this asserts the filter's own wrapping
	// does not put the endpoint back, which is the mistake a well-meaning
	// "include the URL so operators can debug it" edit would make.
	client := &fakeClient{decide: func(Invocation) (Decision, error) {
		return Decision{}, errors.New("connection refused")
	}}
	f := newFilter(t, Config{Request: &PhaseConfig{Body: true}}, client)

	_, err := f.OnRequestBody(context.Background(), testStream(), filter.Body{Complete: true})
	if err == nil {
		t.Fatal("OnRequestBody succeeded, want an error")
	}
	if strings.Contains(err.Error(), cfg.Endpoint) {
		t.Errorf("error = %q, want it to omit the endpoint URL", err.Error())
	}
	if strings.Contains(err.Error(), "scanner.example.com") {
		t.Errorf("error = %q, want it to omit the endpoint host", err.Error())
	}
	// The wrap still has to say which phase failed, or the log line is useless.
	if !strings.Contains(err.Error(), "request-phase") {
		t.Errorf("error = %q, want it to name the failing phase", err.Error())
	}
}
