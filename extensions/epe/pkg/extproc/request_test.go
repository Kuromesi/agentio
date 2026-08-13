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
package extproc

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	structpb "google.golang.org/protobuf/types/known/structpb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/extensions/epe/pkg/audit/accesslog"
	"istio.io/istio/extensions/epe/pkg/engine"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/extproc/attributes"
	"istio.io/istio/extensions/epe/pkg/filters/block"
	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
	"istio.io/istio/extensions/epe/pkg/policy/profilestore"
	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"
)

type responseHeadersProbe struct {
	filter.PassThrough
	calls int
	err   error
	// act overrides the returned action. The zero value is Continue; set it to a
	// kind the response phase forbids to exercise the engine's contract check.
	act *filter.Action
}

func (p *responseHeadersProbe) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	p.calls++
	if p.act != nil {
		return *p.act, p.err
	}
	return filter.Continue(), p.err
}

func responseHeadersState(p *responseHeadersProbe) (*Server, *streamState, *captureLogger) {
	cap := &captureLogger{}
	reg := filter.Registration{
		Name:    "response-observer",
		Phases:  filter.PhaseResponseHeaders,
		OnError: func(any) filter.FailurePolicy { return filter.FailClosed },
		Parse:   func(json.RawMessage) (any, error) { return struct{}{}, nil },
		New:     func(filter.ErasedRuleConfig) filter.Filter { return p },
		// The response phase dispatches to subscribing configs only, recomputed
		// from the units pinned on the stream; these tests stand in for a request
		// phase whose config subscribed.
		Subscribes: func(any) filter.Phase { return filter.PhaseResponseHeaders },
	}
	s := NewServer(ServerDeps{
		Registrations: []filter.Registration{reg},
		AuditLogger:   cap,
	})
	state := newStreamState()
	state.sawRequest = true
	id := filter.UnitID{Scope: "default/p1", Name: "observe"}
	state.units = []engine.Unit{{
		ID:   id,
		Cfgs: []any{struct{}{}},
	}}
	state.awaitResponseHeaders = true
	return s, state, cap
}

type bodylessDeadlineProbe struct {
	filter.PassThrough
	headerDeadline    time.Time
	bodyDeadline      time.Time
	headerHasDeadline bool
	bodyHasDeadline   bool
}

func (p *bodylessDeadlineProbe) OnRequestHeaders(ctx context.Context, _ *filter.Stream) (filter.Action, error) {
	p.headerDeadline, p.headerHasDeadline = ctx.Deadline()
	// Make a freshly-created body-phase budget observably later than the
	// headers-phase budget. A shared parent deadline remains exactly equal.
	time.Sleep(10 * time.Millisecond)
	return filter.NeedBody(), nil
}

func (p *bodylessDeadlineProbe) OnRequestBody(ctx context.Context, _ *filter.Stream, _ filter.Body) (filter.Action, error) {
	p.bodyDeadline, p.bodyHasDeadline = ctx.Deadline()
	return filter.Continue(), nil
}

// scopeCaptureFilter records each unit's identity and evaluation scope,
// standing in for a filter that consumes profile-scoped inputs.
type scopeCaptureFilter struct {
	filter.PassThrough
	profileScopes []string
	scopes        []inputs.Scope
}

func (p *scopeCaptureFilter) capture(rule filter.RuleConfig[struct{}]) filter.Filter {
	p.profileScopes = append(p.profileScopes, rule.ID.Scope)
	p.scopes = append(p.scopes, *rule.Scope)
	return p
}

// scopeCaptureReg registers the capture filter under the block name: the
// test rule carries a block action, so payloadsFor emits that key and the
// filter mounts with the unit's scope.
func scopeCaptureReg(p *scopeCaptureFilter) filter.Registration {
	return filter.Registration{
		Name:   block.FilterName,
		Phases: filter.PhaseRequestHeaders,
		Parse:  func(json.RawMessage) (any, error) { return struct{}{}, nil },
		New: func(cfg filter.ErasedRuleConfig) filter.Filter {
			return p.capture(filter.RuleConfig[struct{}]{ID: cfg.ID, Scope: cfg.Scope})
		},
	}
}

// blockRegistrations builds the production block filter registration set.
func blockRegistrations(t *testing.T) []filter.Registration {
	t.Helper()
	regs, err := filter.Build(block.Definition())
	if err != nil {
		t.Fatalf("build block: %v", err)
	}
	return regs
}

// White-box tests for internals that cannot be observed through the
// ext_proc wire (extractRequestID, stream-end bookkeeping, NewServer
// nil-logger defaulting, pass-through stubs). Full-chain behavior lives in
// the scenario_*_test.go files (package extproc_test), driven by the
// enginetest harness.

// makeRequestHeaders builds an extProcPb.HttpHeaders with the given
// pseudo-headers for testing.
func makeRequestHeaders(host, path, method string) *extProcPb.HttpHeaders {
	return &extProcPb.HttpHeaders{
		Headers: &corev3.HeaderMap{
			Headers: []*corev3.HeaderValue{
				{Key: ":authority", RawValue: []byte(host)},
				{Key: ":path", RawValue: []byte(path)},
				{Key: ":method", RawValue: []byte(method)},
			},
		},
	}
}

func TestExtractRequestID(t *testing.T) {
	tests := []struct {
		name    string
		headers *extProcPb.HttpHeaders
		want    string
	}{
		{
			name: "present",
			headers: &extProcPb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: "x-request-id", RawValue: []byte("abc-123")},
			}}},
			want: "abc-123",
		},
		{
			name: "case-insensitive match",
			headers: &extProcPb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: "X-Request-Id", RawValue: []byte("mixed-case")},
			}}},
			want: "mixed-case",
		},
		{
			name: "absent returns empty",
			headers: &extProcPb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: ":method", RawValue: []byte("GET")},
			}}},
			want: "",
		},
		{
			name:    "nil headers returns empty",
			headers: nil,
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractRequestID(tt.headers); got != tt.want {
				t.Errorf("extractRequestID() = %q, want %q", got, tt.want)
			}
		})
	}
}

// makeAttrsWithLabels constructs the structpb attrs that the handler reads
// from Envoy filter_state.
func makeAttrsWithLabels(namespace, name, labelsB64 string) map[string]*structpb.Struct {
	inner, _ := structpb.NewStruct(map[string]interface{}{
		attributes.FilterStateDownstreamPeerNamespace: namespace,
		attributes.FilterStateDownstreamPeerName:      name,
		attributes.FilterStateSandboxLabels:           labelsB64,
	})
	return map[string]*structpb.Struct{
		attributes.ExtProcAttrsKey: inner,
	}
}

// newProfile builds a SecurityProfile with the given selector and rules.
func newProfile(name, namespace string, selector map[string]string, rules []v1alpha1.SecurityRule) *v1alpha1.SecurityProfile {
	return &v1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: v1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{MatchLabels: selector},
			Rules:    rules,
		},
	}
}

// "app=blocked" base64-encoded, matching the format labels.ParseSandboxLabels expects.
const testLabelsB64 = "YXBwPWJsb2NrZWQ="

func TestHandleRequestHeaders_ArmsBodyAndResponseObligations(t *testing.T) {
	probe := &bodyProbe{}
	regs := []filter.Registration{fixedReg("body-observer", probe)}
	s := NewServer(ServerDeps{
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{Units: []engine.Unit{{
				ID:   filter.UnitID{Scope: "default/p1", Name: "body"},
				Cfgs: []any{struct{}{}},
			}}}, nil
		},
		Registrations:    regs,
		ObserveResponses: true,
	})
	state := newStreamState()

	if _, err := s.HandleRequestHeaders(context.Background(),
		makeRequestHeaders("api.example.com", "/x", "POST"),
		makeAttrsWithLabels("default", "pod", testLabelsB64), state); err != nil {
		t.Fatalf("HandleRequestHeaders: %v", err)
	}
	if state.eval == nil || !state.awaitRequestBody {
		t.Fatal("body evaluation did not arm its request-body obligation")
	}
	if !state.awaitResponseHeaders {
		t.Fatal("response observation did not arm its response-headers obligation")
	}
	if state.finalizeAfterSend {
		t.Fatal("non-terminal headers result armed finalization")
	}
}

func TestHandleRequestHeaders_TerminalResultsArmFinalization(t *testing.T) {
	tests := []struct {
		name   string
		action filter.Action
	}{
		{name: "blocked", action: filter.Stop(filter.Reply{Status: 403})},
		{name: "bypassed", action: filter.Bypass()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regs := []filter.Registration{fixedRegHeaders("terminal", tt.action)}
			s := NewServer(ServerDeps{
				Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
					return engine.Resolution{Units: []engine.Unit{{
						ID:   filter.UnitID{Scope: "default/p1", Name: "terminal"},
						Cfgs: []any{struct{}{}},
					}}}, nil
				},
				Registrations: regs,
			})
			state := newStreamState()

			if _, err := s.HandleRequestHeaders(context.Background(),
				makeRequestHeaders("api.example.com", "/x", "GET"),
				makeAttrsWithLabels("default", "pod", testLabelsB64), state); err != nil {
				t.Fatalf("HandleRequestHeaders: %v", err)
			}
			if !state.finalizeAfterSend {
				t.Fatal("terminal headers result did not arm finalization")
			}
		})
	}
}

func TestHandleRequestHeaders_BodylessContinuationSharesMessageDeadline(t *testing.T) {
	probe := &bodylessDeadlineProbe{}
	regs := []filter.Registration{fixedReg("deadline-probe", probe)}
	s := NewServer(ServerDeps{
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{Units: []engine.Unit{{
				ID:   filter.UnitID{Scope: "default/p1", Name: "body"},
				Cfgs: []any{struct{}{}},
			}}}, nil
		},
		Registrations: regs,
		PluginBudget:  time.Minute,
	})
	headers := makeRequestHeaders("api.example.com", "/x", "POST")
	headers.EndOfStream = true

	if _, err := s.HandleRequestHeaders(context.Background(), headers,
		makeAttrsWithLabels("default", "pod", testLabelsB64), newStreamState()); err != nil {
		t.Fatalf("HandleRequestHeaders: %v", err)
	}
	if !probe.headerHasDeadline || !probe.bodyHasDeadline {
		t.Fatalf("captured deadlines = headers:%v body:%v, want both present",
			probe.headerHasDeadline, probe.bodyHasDeadline)
	}
	if !probe.bodyDeadline.Equal(probe.headerDeadline) {
		t.Fatalf("body deadline = %v, headers deadline = %v; one request-header message must share one budget",
			probe.bodyDeadline, probe.headerDeadline)
	}
}

func TestHandleResponseHeaders_ConsumesObligationAfterSuccessfulObservation(t *testing.T) {
	probe := &responseHeadersProbe{}
	s, state, _ := responseHeadersState(probe)

	if _, err := s.HandleResponseHeaders(context.Background(), &extProcPb.HttpHeaders{
		Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
			{Key: ":status", RawValue: []byte("204")},
		}},
	}, state); err != nil {
		t.Fatalf("HandleResponseHeaders: %v", err)
	}
	if probe.calls != 1 {
		t.Fatalf("response observer ran %d times, want 1", probe.calls)
	}
	if state.awaitResponseHeaders {
		t.Fatal("response-headers obligation was not consumed")
	}
	if !state.finalizeAfterSend {
		t.Fatal("successful response observation did not arm finalization")
	}
}

func TestHandleResponseHeaders_ErrorKeepsObligationUncommitted(t *testing.T) {
	boom := errors.New("observe failed")
	probe := &responseHeadersProbe{err: boom}
	s, state, _ := responseHeadersState(probe)

	resp, err := s.HandleResponseHeaders(context.Background(), &extProcPb.HttpHeaders{
		Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
			{Key: ":status", RawValue: []byte("500")},
		}},
	}, state)
	if !errors.Is(err, boom) {
		t.Fatalf("HandleResponseHeaders error = %v, want %v", err, boom)
	}
	// This registration is FailClosed, so the engine synthesises a deny. That
	// deny is a decision and must travel with the error: Envoy holds the upstream
	// headers only until we answer, and sending nothing would hand the outcome to
	// failure_mode_allow instead. Contrast the fault case below, which must send
	// nothing.
	if len(resp) != 1 {
		t.Fatalf("responses = %d, want 1 synthesised deny", len(resp))
	}
	if resp[0].GetImmediateResponse() == nil {
		t.Fatalf("response = %T, want an ImmediateResponse carrying the deny", resp[0].GetResponse())
	}
	if !state.awaitResponseHeaders {
		t.Fatal("failed response observation consumed the outstanding obligation")
	}
	if state.finalizeAfterSend {
		t.Fatal("failed response observation armed successful finalization")
	}
}

// A contract violation is a fault, not a decision: the engine returns a
// zero-value passthrough result alongside its error. Translating that would emit
// a bare ack, and because Process sends a handler's responses before surfacing
// its error, the ack would release the UNMUTATED upstream response downstream
// and only then tear the stream down — turning a FailClosed rule into fail-open.
// Nothing may be sent; Envoy's failure_mode_allow owns the outcome.
func TestHandleResponseHeaders_ContractViolationSendsNothing(t *testing.T) {
	bypass := filter.Bypass()
	probe := &responseHeadersProbe{act: &bypass}
	s, state, _ := responseHeadersState(probe)

	resp, err := s.HandleResponseHeaders(context.Background(), &extProcPb.HttpHeaders{
		Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
			{Key: ":status", RawValue: []byte("200")},
		}},
	}, state)
	if err == nil {
		t.Fatal("HandleResponseHeaders succeeded, want the response phase to reject a Bypass action")
	}
	if len(resp) != 0 {
		t.Fatalf("responses = %d, want none: a fault must not release the upstream response", len(resp))
	}
}

func TestHandleResponseHeaders_MissingInputKeepsObligationAndAuditsError(t *testing.T) {
	tests := []struct {
		name    string
		headers *extProcPb.HttpHeaders
	}{
		{name: "nil message"},
		{name: "missing header map", headers: &extProcPb.HttpHeaders{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := &responseHeadersProbe{}
			s, state, cap := responseHeadersState(probe)

			_, err := s.HandleResponseHeaders(context.Background(), tt.headers, state)
			if err == nil {
				t.Fatal("missing response headers were accepted")
			}
			if probe.calls != 0 {
				t.Fatalf("response observer ran %d times, want 0", probe.calls)
			}
			if !state.awaitResponseHeaders || state.finalizeAfterSend {
				t.Fatalf("obligation state = await:%v finalize:%v, want true/false",
					state.awaitResponseHeaders, state.finalizeAfterSend)
			}

			s.finishStream(context.Background(), state, err)
			if len(cap.entries) != 1 || cap.entries[0].Outcome != "error" {
				t.Fatalf("accesslog = %+v, want one error entry", cap.entries)
			}
		})
	}
}

func TestHandleResponseHeaders_DuplicateDoesNotRerunObserverOrOverwriteAudit(t *testing.T) {
	probe := &responseHeadersProbe{}
	s, state, cap := responseHeadersState(probe)
	headers := &extProcPb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: ":status", RawValue: []byte("204")},
	}}}

	if _, err := s.HandleResponseHeaders(context.Background(), headers, state); err != nil {
		t.Fatalf("first HandleResponseHeaders: %v", err)
	}
	s.finishAfterSend(context.Background(), state)
	_, duplicateErr := s.HandleResponseHeaders(context.Background(), headers, state)
	if duplicateErr == nil {
		t.Fatal("duplicate response headers were accepted")
	}
	if probe.calls != 1 {
		t.Fatalf("response observer ran %d times, want exactly once", probe.calls)
	}
	s.finishStream(context.Background(), state, duplicateErr)
	if len(cap.entries) != 1 || cap.entries[0].Outcome != "passthrough" || cap.entries[0].Error != "" {
		t.Fatalf("accesslog = %+v, want one committed passthrough entry", cap.entries)
	}
}

// A blocked request finalizes as soon as its ImmediateResponse is sent, but the
// statically configured response-header mode can still deliver one message. It
// must be acknowledged without reopening observers or audit.
//
// This scenario used to be written with a *bypassed* stream. Under the
// response-mutation design a bypass with demand must survive into the response
// phase (see TestHandleResponseHeaders_BypassWithDemandStillDispatches), so the
// two cases are now separate tests: this one keeps the genuine
// "static mode outlives a terminal decision" behaviour with the terminal
// decision that really is terminal.
func TestHandleResponseHeaders_FinalizedStreamAcknowledgesFirstStaticMessageWithoutObserver(t *testing.T) {
	probe := &responseHeadersProbe{}
	s, state, cap := responseHeadersState(probe)
	state.awaitResponseHeaders = false
	state.stream.Info.Promote(filter.DispositionBlocked)
	s.finishStream(context.Background(), state, nil)
	headers := &extProcPb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: ":status", RawValue: []byte("204")},
	}}}

	responses, err := s.HandleResponseHeaders(context.Background(), headers, state)
	if err != nil {
		t.Fatalf("first static HandleResponseHeaders: %v", err)
	}
	if len(responses) != 1 || responses[0].GetResponseHeaders() == nil {
		t.Fatalf("responses = %+v, want one response-headers acknowledgement", responses)
	}
	if probe.calls != 0 {
		t.Fatalf("response observer ran %d times after terminal finalization, want 0", probe.calls)
	}
	if state.finalizeAfterSend {
		t.Fatal("already finalized stream armed another finalization")
	}
	if len(cap.entries) != 1 || cap.entries[0].Outcome != "blocked" {
		t.Fatalf("accesslog = %+v, want one committed blocked entry", cap.entries)
	}

	if _, err := s.HandleResponseHeaders(context.Background(), headers, state); err == nil {
		t.Fatal("duplicate static response headers were accepted")
	}
	if probe.calls != 0 || len(cap.entries) != 1 {
		t.Fatalf("duplicate changed observers/audit: observer calls=%d accesslog=%+v", probe.calls, cap.entries)
	}
}

func TestHandleRequestHeaders_MountsRecordedProfileInputsForFinalize(t *testing.T) {
	store := profilestore.MakeFakeStore()
	for _, tc := range []struct {
		name  string
		value string
	}{
		{name: "p1", value: "first"},
		{name: "p2", value: "second"},
	} {
		p := newProfile(tc.name, "default", map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{{
			Name:  "capture",
			Match: []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
			// The block action is what mounts the capture filter: a rule
			// with no actions emits no payloads and mounts nothing.
			Actions: v1alpha1.SecurityRuleActions{Block: &v1alpha1.BlockAction{StatusCode: 403}},
		}})
		p.Spec.Inputs = []v1alpha1.SecurityProfileInput{{
			Name:   "routing",
			Inline: map[string]string{"target": tc.value},
		}}
		store.ProfileSet(p)
	}

	capture := &scopeCaptureFilter{}
	regs := []filter.Registration{scopeCaptureReg(capture)}
	srv := NewServer(ServerDeps{
		Resolve:       securityprofile.NewResolver(store, regs, nil),
		Registrations: regs,
	})
	if _, err := srv.HandleRequestHeaders(
		context.Background(),
		makeRequestHeaders("api.example.com", "/", "GET"),
		makeAttrsWithLabels("default", "pod", testLabelsB64),
		newStreamState(),
	); err != nil {
		t.Fatalf("HandleRequestHeaders: %v", err)
	}

	if got := capture.profileScopes; !reflect.DeepEqual(got, []string{"default/p1", "default/p2"}) {
		t.Fatalf("captured unit scopes = %v, want profile order", got)
	}
	want := []map[string]any{
		{"routing": map[string]string{"target": "first"}},
		{"routing": map[string]string{"target": "second"}},
	}
	for i := range want {
		if !reflect.DeepEqual(capture.scopes[i].Inputs(), want[i]) {
			t.Fatalf("captured inputs[%d] = %#v, want %#v", i, capture.scopes[i].Inputs(), want[i])
		}
	}
}

func TestHandleRequestHeaders_SkipsInvalidInitialProfileWithUnresolvedInputs(t *testing.T) {
	store := profilestore.MakeFakeStore()
	p := newProfile("p1", "default", map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{{
		Name:    "match",
		Match:   []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
		Actions: v1alpha1.SecurityRuleActions{},
	}})
	p.Spec.Inputs = []v1alpha1.SecurityProfileInput{{
		Name:      "routing",
		ConfigMap: &v1alpha1.ConfigMapInputRef{Name: "missing"},
	}}
	store.ProfileSet(p)

	_, err := NewServer(ServerDeps{Resolve: securityprofile.NewResolver(store, nil, nil)}).HandleRequestHeaders(
		context.Background(),
		makeRequestHeaders("api.example.com", "/", "GET"),
		makeAttrsWithLabels("default", "pod", testLabelsB64),
		newStreamState(),
	)
	if err != nil {
		t.Fatalf("invalid initial profile should be absent from the effective snapshot: %v", err)
	}
}

// newServerWithBlockOnly constructs a Server wired only with the block filter.
func newServerWithBlockOnly(t *testing.T, store profilestore.Store) *Server {
	t.Helper()
	regs := blockRegistrations(t)
	return NewServer(ServerDeps{
		Resolve:       securityprofile.NewResolver(store, regs, nil),
		Registrations: regs,
	})
}

// capturedAuditLogger collects every audit Entry the handler submits so
// tests can assert on outcomes without depending on a real worker
// goroutine. Implements accesslog.Logger.
type capturedAuditLogger struct {
	mu      sync.Mutex
	entries []accesslog.Entry
}

func (c *capturedAuditLogger) Submit(e accesslog.Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, e)
}

func (c *capturedAuditLogger) last(t *testing.T) accesslog.Entry {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) == 0 {
		t.Fatal("expected at least one audit entry, got none")
	}
	return c.entries[len(c.entries)-1]
}

// Compile-time check that capturedAuditLogger implements accesslog.Logger.
var _ accesslog.Logger = (*capturedAuditLogger)(nil)

// newServerWithAudit returns a Server wired with the supplied registrations
// and a fresh capturedAuditLogger so the test can inspect the emitted entry.
func newServerWithAudit(t *testing.T, store profilestore.Store, regs []filter.Registration) (*Server, *capturedAuditLogger) {
	t.Helper()
	cap := &capturedAuditLogger{}
	srv := NewServer(ServerDeps{
		Resolve:       securityprofile.NewResolver(store, regs, nil),
		Registrations: regs,
		AuditLogger:   cap,
	})
	return srv, cap
}

// TestHandleRequestHeaders_NoPodIdentity verifies that when filter_state
// does not carry pod identity (e.g. the upstream metadata-exchange filter
// is misconfigured), the handler passes the request through unmodified
// instead of falling back to a hardcoded pod or failing the request.
func TestHandleRequestHeaders_NoPodIdentity(t *testing.T) {
	store := profilestore.MakeFakeStore()
	store.ProfileSet(newProfile("p1", "default", map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{
		{
			Name:    "block-everything",
			Match:   []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
			Actions: v1alpha1.SecurityRuleActions{Block: &v1alpha1.BlockAction{StatusCode: 403}},
		},
	}))

	srv, cap := newServerWithAudit(t, store, blockRegistrations(t))

	// attrs with empty pod name + namespace simulates Envoy not populating
	// filter_state['downstream_peer'].
	state := newStreamState()
	responses, err := srv.HandleRequestHeaders(
		context.Background(),
		makeRequestHeaders("api.example.com", "/admin", "GET"),
		makeAttrsWithLabels("", "", ""),
		state,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}
	if _, ok := responses[0].Response.(*extProcPb.ProcessingResponse_RequestHeaders); !ok {
		t.Fatalf("expected pass-through RequestHeaders, got %T", responses[0].Response)
	}
	srv.finishStream(context.Background(), state, nil)

	entry := cap.last(t)
	if entry.Pod.Name != "" || entry.Pod.Namespace != "" {
		t.Errorf("expected empty Pod in audit entry, got %+v", entry.Pod)
	}
}

// TestPassThroughHandlers covers the trivial body / trailer / response stubs
// so they show up in coverage and accidental regressions surface immediately.
func TestPassThroughHandlers(t *testing.T) {
	srv := newServerWithBlockOnly(t, profilestore.MakeFakeStore())
	ctx := context.Background()

	if r, err := srv.HandleRequestBody(ctx, &extProcPb.HttpBody{EndOfStream: true}, nil); err != nil || len(r) != 1 {
		t.Errorf("HandleRequestBody: got len=%d err=%v", len(r), err)
	}
	if r, err := srv.HandleRequestTrailers(ctx, nil); err != nil || len(r) != 1 {
		t.Errorf("HandleRequestTrailers: got len=%d err=%v", len(r), err)
	}
	if r, err := srv.HandleResponseBody(ctx, nil); err != nil || len(r) != 1 {
		t.Errorf("HandleResponseBody: got len=%d err=%v", len(r), err)
	}
	if r, err := srv.HandleResponseTrailers(ctx, nil); err != nil || len(r) != 1 {
		t.Errorf("HandleResponseTrailers: got len=%d err=%v", len(r), err)
	}
}

// TestHandleRequestHeaders_AuditEntry_NilLoggerDoesNotPanic guards against
// regressions in NewServer's nil-default: the handler must still produce a
// passthrough response when ServerDeps.AuditLogger is nil.
func TestHandleRequestHeaders_AuditEntry_NilLoggerDoesNotPanic(t *testing.T) {
	store := profilestore.MakeFakeStore()
	regs := blockRegistrations(t)
	srv := NewServer(ServerDeps{
		Resolve:       securityprofile.NewResolver(store, regs, nil),
		Registrations: regs,
		// AuditLogger intentionally nil.
	})
	if _, err := srv.HandleRequestHeaders(
		context.Background(),
		makeRequestHeaders("api.example.com", "/x", "GET"),
		makeAttrsWithLabels("default", "pod-x", testLabelsB64),
		newStreamState(),
	); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}
