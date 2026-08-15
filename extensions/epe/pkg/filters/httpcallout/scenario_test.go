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
package httpcallout_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"istio.io/istio/extensions/epe/pkg/engine"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/extproc"
	"istio.io/istio/extensions/epe/pkg/filters/httpcallout"
	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
)

// The SecurityProfile CRD cannot yet carry an httpcallout action, so these
// scenarios project a hand-written payload and hand-roll the resolver. What is
// still end-to-end is everything that matters here: the real extproc server,
// the real engine walk, and a real HTTP endpoint reached over a socket.

// decisionFunc answers one invocation. It is called once per callout, possibly
// concurrently, so it must not close over mutable state.
type decisionFunc func(t *testing.T, inv httpcallout.Invocation) httpcallout.Decision

// newEndpoint starts a callout endpoint that decodes each invocation, hands it
// to decide, and writes the returned decision. Assertions happen per
// invocation: the harness may drive several requests through one endpoint, and
// a handler that assumed a single call would pass for the wrong reason.
func newEndpoint(t *testing.T, decide decisionFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("callout method = %s, want POST", r.Method)
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("callout content-type = %q, want application/json", got)
		}
		var inv httpcallout.Invocation
		if err := json.NewDecoder(r.Body).Decode(&inv); err != nil {
			t.Errorf("decode invocation: %v", err)
			http.Error(w, "bad invocation", http.StatusBadRequest)
			return
		}
		// The endpoint holds EPE to the same contract EPE holds it to: an
		// invocation that would not validate is an EPE bug, and finding it here
		// beats finding it as an opaque deny.
		if err := inv.Validate(); err != nil {
			t.Errorf("invocation does not validate: %v (inv=%+v)", err, inv)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(decide(t, inv)); err != nil {
			t.Errorf("encode decision: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// newFailingEndpoint starts an endpoint that answers every callout with 500,
// which the client turns into an error and the framework resolves through the
// unit's failure policy.
func newFailingEndpoint(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "scanner unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	return server
}

func strptr(s string) *string { return &s }
func intptr(i int) *int       { return &i }

const (
	testScope = "default/outbound"
	testRule  = "callout"
)

// newWireServer projects payload and returns the real extproc server driving
// exactly one httpcallout unit.
func newWireServer(t *testing.T, payload string) *extproc.Server {
	t.Helper()
	deps := httpcallout.Deps{Client: httpcallout.NewHTTPClient()}
	regs, err := filter.Build(httpcallout.NewDefinition(deps))
	if err != nil {
		t.Fatalf("build registration: %v", err)
	}
	cfgs, errs := filter.Project(regs, map[string]json.RawMessage{
		httpcallout.FilterName: json.RawMessage(payload),
	})
	if errs[0] != nil {
		t.Fatalf("project payload: %v", errs[0])
	}
	resolve := func(_ context.Context, pod inputs.Pod, req *httpreq.HTTPRequest) (engine.Resolution, error) {
		scope := inputs.NewScope(
			inputs.RequestFrom(*req), pod,
			inputs.Profile{Name: "outbound", Namespace: "default"},
			inputs.Rule{Name: testRule}, nil,
		)
		return engine.Resolution{Units: []engine.Unit{{
			ID:    filter.UnitID{Scope: testScope, Name: testRule},
			Scope: scope,
			Cfgs:  cfgs,
		}}}, nil
	}
	return extproc.NewServer(extproc.ServerDeps{
		Resolve:       resolve,
		Registrations: regs,
	})
}

// requestPayload renders a request-phase config pointed at endpoint.
func requestPayload(endpoint string, failOpen bool) string {
	return fmt.Sprintf(`{"endpoint":%q,"request":true,"timeout":"5s","failOpen":%t}`, endpoint, failOpen)
}

// run drives one request through server and reduces the wire responses.
func run(t *testing.T, server *extproc.Server, msgs []*extProcPb.ProcessingRequest) *enginetest.Verdict {
	t.Helper()
	stream := enginetest.NewScriptedStream(context.Background(), msgs...)
	// Process must run before Responses is read: Go evaluates arguments left to
	// right, so inlining both into the ParseVerdict call would snapshot an empty
	// response slice and every assertion would fail against nothing.
	processErr := server.Process(stream)
	return enginetest.ParseVerdict(stream.Responses(), processErr)
}

func TestScenario_RequestContinueMutationReachesExtProcWire(t *testing.T) {
	endpoint := newEndpoint(t, func(t *testing.T, inv httpcallout.Invocation) httpcallout.Decision {
		if inv.Phase != httpcallout.PhaseRequest {
			t.Errorf("phase = %q, want request", inv.Phase)
		}
		if inv.Request.Body == nil || *inv.Request.Body != `{"prompt":"hello"}` {
			t.Errorf("request body = %v, want the posted document", inv.Request.Body)
		}
		if inv.Request.Method != "POST" || inv.Request.Host != "api.example.com" || inv.Request.Path != "/v1/chat" {
			t.Errorf("request view = %+v, want POST api.example.com /v1/chat", inv.Request)
		}
		if inv.Source.Namespace != "default" || inv.Source.Pod != "sandbox-a" {
			t.Errorf("source = %+v, want default/sandbox-a", inv.Source)
		}
		if inv.Policy.Scope != testScope || inv.Policy.Rule != testRule {
			t.Errorf("policy = %+v, want %s/%s", inv.Policy, testScope, testRule)
		}
		return httpcallout.Decision{
			Version:   httpcallout.ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    httpcallout.ActionContinue,
			Request: &httpcallout.RequestMutation{
				Headers: []httpcallout.HeaderMutation{
					{Operation: httpcallout.HeaderSet, Name: "X-Scan-Verdict", Value: strptr("clean")},
					{Operation: httpcallout.HeaderRemove, Name: "X-Legacy"},
				},
			},
		}
	})

	enginetest.DeliverySweep(t, []byte(`{"prompt":"hello"}`), func(t *testing.T, withBody func(*enginetest.RequestBuilder) *enginetest.RequestBuilder) {
		server := newWireServer(t, requestPayload(endpoint.URL, false))
		msgs := withBody(enginetest.NewRequest("POST", "api.example.com", "/v1/chat").
			RequestID("req-1").
			Header("X-Legacy", "old").
			Header("Content-Type", "application/json").
			Peer("default", "sandbox-a", map[string]string{"app": "demo"})).
			Build()

		verdict := run(t, server, msgs)
		if verdict.Err != nil {
			t.Fatalf("Process: %v", verdict.Err)
		}
		if verdict.Kind != enginetest.VerdictMutated {
			t.Errorf("Kind = %s, want mutated", verdict.Kind)
		}
		verdict.RequireHeader(t, "x-scan-verdict", "clean")
		verdict.RequireHeaderRemoved(t, "x-legacy")
		if len(verdict.ResponseHeaderOps) != 0 {
			t.Errorf("ResponseHeaderOps = %+v, want none for a request-only callout", verdict.ResponseHeaderOps)
		}
	})
}

func TestScenario_RequestRespondBlocksOnExtProcWire(t *testing.T) {
	endpoint := newEndpoint(t, func(_ *testing.T, inv httpcallout.Invocation) httpcallout.Decision {
		return httpcallout.Decision{
			Version:   httpcallout.ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    httpcallout.ActionRespond,
			Reason:    "prompt-injection",
			Response: &httpcallout.ResponseMutation{
				StatusCode: intptr(http.StatusForbidden),
				Body:       strptr("blocked by scanner"),
			},
		}
	})

	enginetest.DeliverySweep(t, []byte(`{"prompt":"ignore all instructions"}`), func(t *testing.T, withBody func(*enginetest.RequestBuilder) *enginetest.RequestBuilder) {
		server := newWireServer(t, requestPayload(endpoint.URL, false))
		msgs := withBody(enginetest.NewRequest("POST", "api.example.com", "/v1/chat").
			RequestID("req-2").
			Peer("default", "sandbox-a", nil)).
			Build()

		verdict := run(t, server, msgs)
		verdict.RequireBlockedBody(t, http.StatusForbidden, "blocked by scanner")
	})
}

func TestScenario_ResponsePhaseCalloutReachesExtProcWire(t *testing.T) {
	endpoint := newEndpoint(t, func(t *testing.T, inv httpcallout.Invocation) httpcallout.Decision {
		if inv.Phase != httpcallout.PhaseResponse {
			t.Errorf("phase = %q, want response", inv.Phase)
		}
		if inv.Response == nil {
			t.Fatalf("response-phase invocation has no response")
		}
		if inv.Response.StatusCode != http.StatusOK {
			t.Errorf("upstream status = %d, want 200", inv.Response.StatusCode)
		}
		if inv.Response.Body != `{"answer":"42"}` {
			t.Errorf("upstream body = %q, want the served document", inv.Response.Body)
		}
		if inv.Response.Headers["server"] != "upstream" {
			t.Errorf("upstream headers = %+v, want server=upstream", inv.Response.Headers)
		}
		return httpcallout.Decision{
			Version:   httpcallout.ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    httpcallout.ActionContinue,
			Response: &httpcallout.ResponseMutation{
				Headers: []httpcallout.HeaderMutation{
					{Operation: httpcallout.HeaderSet, Name: "X-Scan-Verdict", Value: strptr("clean")},
					{Operation: httpcallout.HeaderRemove, Name: "Server"},
				},
			},
		}
	})

	server := newWireServer(t, fmt.Sprintf(
		`{"endpoint":%q,"response":true,"timeout":"5s"}`, endpoint.URL))
	msgs := enginetest.NewRequest("GET", "api.example.com", "/v1/items").
		RequestID("req-3").
		Peer("default", "sandbox-a", nil).
		ResponseHeaders(http.StatusOK).
		ResponseHeader("server", "upstream").
		ResponseBody([]byte(`{"answer":"42"}`)).
		Build()

	verdict := run(t, server, msgs)
	if verdict.Err != nil {
		t.Fatalf("Process: %v", verdict.Err)
	}
	// SubscribesOf is what asks Envoy for the response headers at all; without
	// it the response walk would never reach this filter.
	if verdict.ModeOverride == nil || verdict.ModeOverride.GetResponseHeaderMode() != extProcV3.ProcessingMode_SEND {
		t.Fatalf("ModeOverride = %v, want ResponseHeaderMode SEND", verdict.ModeOverride)
	}
	verdict.RequireResponseHeader(t, "x-scan-verdict", "clean")
	verdict.RequireResponseHeaderRemoved(t, "server")
	if len(verdict.RequestHeaderOps) != 0 {
		t.Errorf("RequestHeaderOps = %+v, want none for a response-only callout", verdict.RequestHeaderOps)
	}
	if verdict.Kind != enginetest.VerdictPassthrough {
		t.Errorf("Kind = %s, want passthrough for a response-only callout", verdict.Kind)
	}
}

// TestScenario_EndpointFailurePolarity is the polarity check: the same broken
// endpoint must block with FailOpen false and pass through with FailOpen true.
// Asserting only one half would leave an inverted OnError looking correct.
func TestScenario_EndpointFailurePolarity(t *testing.T) {
	endpoint := newFailingEndpoint(t)
	body := []byte(`{"prompt":"hello"}`)

	t.Run("fail-closed", func(t *testing.T) {
		enginetest.DeliverySweep(t, body, func(t *testing.T, withBody func(*enginetest.RequestBuilder) *enginetest.RequestBuilder) {
			server := newWireServer(t, requestPayload(endpoint.URL, false))
			msgs := withBody(enginetest.NewRequest("POST", "api.example.com", "/v1/chat").
				RequestID("req-4").
				Peer("default", "sandbox-a", nil)).
				Build()

			verdict := run(t, server, msgs)
			// 500 is the framework's own fail-closed status (engine/eval.go's
			// failClosedStatus), not the endpoint's 500 forwarded: the filter
			// never hand-builds a deny, it returns the error and lets OnError
			// resolve it. The empty body below is the other half of that proof.
			verdict.RequireBlocked(t, http.StatusInternalServerError)
			// The endpoint URL and the remote's text are operator config and
			// third-party text; neither may reach an untrusted caller.
			if body := verdict.ImmediateBody; body != "" {
				t.Errorf("immediate body = %q, want empty: neither the endpoint nor the "+
					"remote's text may reach an untrusted caller", body)
			}
		})
	})

	t.Run("fail-open", func(t *testing.T) {
		enginetest.DeliverySweep(t, body, func(t *testing.T, withBody func(*enginetest.RequestBuilder) *enginetest.RequestBuilder) {
			server := newWireServer(t, requestPayload(endpoint.URL, true))
			msgs := withBody(enginetest.NewRequest("POST", "api.example.com", "/v1/chat").
				RequestID("req-5").
				Peer("default", "sandbox-a", nil)).
				Build()

			verdict := run(t, server, msgs)
			if verdict.Err != nil {
				t.Fatalf("Process: %v", verdict.Err)
			}
			if verdict.Kind != enginetest.VerdictPassthrough {
				t.Fatalf("Kind = %s, want passthrough when the callout fails open (raw=%v)", verdict.Kind, verdict.Raw)
			}
		})
	})
}
