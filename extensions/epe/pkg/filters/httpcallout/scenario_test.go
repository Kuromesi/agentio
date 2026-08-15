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
	"strconv"
	"sync/atomic"
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

// actionPtr spells out an action the wire contract lets a callout omit. These
// scenarios state it so the endpoint's answer stays legible at the call site.
func actionPtr(a httpcallout.Action) *httpcallout.Action { return &a }

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
	return fmt.Sprintf(`{"endpoint":%q,"request":{"body":true},"timeout":"5s","failOpen":%t}`, endpoint, failOpen)
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
			Action:    actionPtr(httpcallout.ActionContinue),
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

// TestScenario_BodylessRequestCalloutBuffersNothing is the buffering bite on the
// wire. A header-only callout must cost no body buffering at all, so the adapter
// must emit no BUFFERED request-body mode for it — and the callout must still
// happen, from the headers phase, with no body attached to the invocation.
func TestScenario_BodylessRequestCalloutBuffersNothing(t *testing.T) {
	endpoint := newEndpoint(t, func(t *testing.T, inv httpcallout.Invocation) httpcallout.Decision {
		if inv.Phase != httpcallout.PhaseRequest {
			t.Errorf("phase = %q, want request", inv.Phase)
		}
		// nil rather than a pointer to "": the phase never collected a body, and
		// a scanner must be able to tell that from an empty one.
		if inv.Request.Body != nil {
			t.Errorf("request body = %q, want it absent for a bodyless phase", *inv.Request.Body)
		}
		if inv.Request.Method != "POST" || inv.Request.Path != "/v1/chat" {
			t.Errorf("request view = %+v, want the metadata a bodyless callout still sees", inv.Request)
		}
		return httpcallout.Decision{
			Version:   httpcallout.ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    actionPtr(httpcallout.ActionContinue),
			Request: &httpcallout.RequestMutation{
				Headers: []httpcallout.HeaderMutation{
					{Operation: httpcallout.HeaderSet, Name: "X-Scan-Verdict", Value: strptr("clean")},
				},
			},
		}
	})

	server := newWireServer(t, fmt.Sprintf(
		`{"endpoint":%q,"request":{},"timeout":"5s"}`, endpoint.URL))
	// StreamingHeaders leaves EndOfStream clear and sends no body message, so a
	// filter that still asked for the body would stall here instead of deciding.
	msgs := enginetest.NewRequest("POST", "api.example.com", "/v1/chat").
		RequestID("req-6").
		Header("Content-Type", "application/json").
		Peer("default", "sandbox-a", nil).
		StreamingHeaders().
		Build()

	verdict := run(t, server, msgs)
	if verdict.Err != nil {
		t.Fatalf("Process: %v", verdict.Err)
	}
	verdict.RequireHeader(t, "x-scan-verdict", "clean")
	if verdict.ModeOverride != nil &&
		verdict.ModeOverride.GetRequestBodyMode() == extProcV3.ProcessingMode_BUFFERED {
		t.Fatalf("ModeOverride = %v, want no buffered request body for a header-only callout", verdict.ModeOverride)
	}
	// The other half of the same bite, and the guard on SubscribesOf returning 0
	// for a request-only config: asking Envoy for response headers here would arm
	// a response walk with nothing to dispatch to, whose failure mode is a
	// silently dead response half rather than an error anyone would notice.
	if verdict.ModeOverride != nil &&
		verdict.ModeOverride.GetResponseHeaderMode() == extProcV3.ProcessingMode_SEND {
		t.Fatalf("ModeOverride = %v, want no ResponseHeaderMode SEND for a request-only callout", verdict.ModeOverride)
	}
}

func TestScenario_RequestRespondBlocksOnExtProcWire(t *testing.T) {
	endpoint := newEndpoint(t, func(_ *testing.T, inv httpcallout.Invocation) httpcallout.Decision {
		return httpcallout.Decision{
			Version:   httpcallout.ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    actionPtr(httpcallout.ActionRespond),
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
		if inv.Response.Body == nil || *inv.Response.Body != `{"answer":"42"}` {
			t.Errorf("upstream body = %v, want the served document", inv.Response.Body)
		}
		if inv.Response.Headers["server"] != "upstream" {
			t.Errorf("upstream headers = %+v, want server=upstream", inv.Response.Headers)
		}
		return httpcallout.Decision{
			Version:   httpcallout.ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    actionPtr(httpcallout.ActionContinue),
			Response: &httpcallout.ResponseMutation{
				Headers: []httpcallout.HeaderMutation{
					{Operation: httpcallout.HeaderSet, Name: "X-Scan-Verdict", Value: strptr("clean")},
					{Operation: httpcallout.HeaderRemove, Name: "Server"},
				},
			},
		}
	})

	// The header mode is explicit because disclosure is opt-in in both
	// directions: without it the callout would see status and body only.
	server := newWireServer(t, fmt.Sprintf(
		`{"endpoint":%q,"response":{"headers":{"mode":"all"},"body":true},"timeout":"5s"}`, endpoint.URL))
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

// TestScenario_ResponseRespondBlocksOnExtProcWire is the termination amendment
// at the wire: a callout may terminate from the response direction, not only
// before the request is forwarded. Nothing else in the package proves the
// response-phase respond ever becomes an ImmediateResponse, so without this a
// regression that quietly downgraded it to a continue would ship the upstream
// body to the caller the scanner just rejected.
func TestScenario_ResponseRespondBlocksOnExtProcWire(t *testing.T) {
	endpoint := newEndpoint(t, func(t *testing.T, inv httpcallout.Invocation) httpcallout.Decision {
		if inv.Phase != httpcallout.PhaseResponse {
			t.Errorf("phase = %q, want response", inv.Phase)
		}
		return httpcallout.Decision{
			Version:   httpcallout.ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    actionPtr(httpcallout.ActionRespond),
			Reason:    "leaked-secret",
			Response: &httpcallout.ResponseMutation{
				StatusCode: intptr(http.StatusBadGateway),
				Body:       strptr("response blocked by scanner"),
			},
		}
	})

	server := newWireServer(t, fmt.Sprintf(
		`{"endpoint":%q,"response":{"body":true},"timeout":"5s"}`, endpoint.URL))
	msgs := enginetest.NewRequest("GET", "api.example.com", "/v1/items").
		RequestID("req-7").
		Peer("default", "sandbox-a", nil).
		ResponseHeaders(http.StatusOK).
		ResponseHeader("server", "upstream").
		ResponseBody([]byte(`{"secret":"hunter2"}`)).
		Build()

	verdict := run(t, server, msgs)
	verdict.RequireBlockedBody(t, http.StatusBadGateway, "response blocked by scanner")
	// Envoy is still holding the upstream response headers when this local reply
	// arrives, so the reply replaces them (translate.go:88-92). A response header
	// op alongside it would mean the extension emitted a mutation for a response
	// that no longer exists.
	if len(verdict.ResponseHeaderOps) != 0 {
		t.Errorf("ResponseHeaderOps = %+v, want none: the local reply replaced the response being mutated",
			verdict.ResponseHeaderOps)
	}
	if len(verdict.RequestHeaderOps) != 0 {
		t.Errorf("RequestHeaderOps = %+v, want none for a response-only callout", verdict.RequestHeaderOps)
	}
}

// TestScenario_BothPhasesInOneExchange is the only place two callouts of one
// exchange are observed together. Three things regress silently without it: the
// single ModeOverride must restate BOTH body modes because Envoy copies them
// unconditionally (extproc/request.go:149-150), so a request-body subscription
// and a response-header subscription have to survive in the same message; and
// both invocations must carry the same request.id, because a scanner correlating
// the two halves has nothing else to join on.
func TestScenario_BothPhasesInOneExchange(t *testing.T) {
	const wantID = "req-8"
	endpoint := newEndpoint(t, func(t *testing.T, inv httpcallout.Invocation) httpcallout.Decision {
		if inv.Request == nil || inv.Request.ID != wantID {
			t.Errorf("correlation id = %+v, want %q on both phases", inv.Request, wantID)
		}
		decision := httpcallout.Decision{
			Version:   httpcallout.ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    actionPtr(httpcallout.ActionContinue),
		}
		switch inv.Phase {
		case httpcallout.PhaseRequest:
			if inv.Request.Body == nil || *inv.Request.Body != `{"prompt":"hello"}` {
				t.Errorf("request body = %v, want the posted document", inv.Request.Body)
			}
			decision.Request = &httpcallout.RequestMutation{
				Headers: []httpcallout.HeaderMutation{
					{Operation: httpcallout.HeaderSet, Name: "X-Request-Scan", Value: strptr("clean")},
				},
			}
		case httpcallout.PhaseResponse:
			if inv.Response == nil {
				t.Fatalf("response-phase invocation has no response")
			}
			decision.Response = &httpcallout.ResponseMutation{
				Headers: []httpcallout.HeaderMutation{
					{Operation: httpcallout.HeaderSet, Name: "X-Response-Scan", Value: strptr("clean")},
				},
			}
		default:
			t.Errorf("phase = %q, want request or response", inv.Phase)
		}
		return decision
	})

	server := newWireServer(t, fmt.Sprintf(
		`{"endpoint":%q,"request":{"body":true},"response":{},"timeout":"5s"}`, endpoint.URL))
	msgs := enginetest.NewRequest("POST", "api.example.com", "/v1/chat").
		RequestID(wantID).
		Peer("default", "sandbox-a", nil).
		Body([]byte(`{"prompt":"hello"}`)).
		ResponseHeaders(http.StatusOK).
		Build()

	verdict := run(t, server, msgs)
	if verdict.Err != nil {
		t.Fatalf("Process: %v", verdict.Err)
	}
	// One override, both subscriptions. Losing either would strand a phase:
	// no BUFFERED request body stalls the request callout, no SEND response
	// header mode never dispatches the response one.
	if verdict.ModeOverride == nil {
		t.Fatalf("ModeOverride is nil, want one carrying both subscriptions (raw=%v)", verdict.Raw)
	}
	if got := verdict.ModeOverride.GetRequestBodyMode(); got != extProcV3.ProcessingMode_BUFFERED {
		t.Errorf("RequestBodyMode = %v, want BUFFERED (override=%v)", got, verdict.ModeOverride)
	}
	if got := verdict.ModeOverride.GetResponseHeaderMode(); got != extProcV3.ProcessingMode_SEND {
		t.Errorf("ResponseHeaderMode = %v, want SEND (override=%v)", got, verdict.ModeOverride)
	}
	// A distinct mutation per phase, so a single mutation landing twice or in the
	// wrong direction cannot pass.
	verdict.RequireHeader(t, "x-request-scan", "clean")
	verdict.RequireResponseHeader(t, "x-response-scan", "clean")
	if len(verdict.ResponseHeaderValues("x-request-scan")) != 0 {
		t.Errorf("x-request-scan reached the response direction: ops=%+v", verdict.ResponseHeaderOps)
	}
	if len(verdict.RequestHeaderValues("x-response-scan")) != 0 {
		t.Errorf("x-response-scan reached the request direction: ops=%+v", verdict.RequestHeaderOps)
	}
}

// TestScenario_RequestRespondSkipsResponseCallout pins the spec sentence "a
// request short-circuit does not run response interception". Both phases are
// configured, so a regression here would not fail any other assertion: the
// caller still gets the block, but the endpoint would be billed a second
// invocation for a response that was never produced.
func TestScenario_RequestRespondSkipsResponseCallout(t *testing.T) {
	var calls atomic.Int64
	endpoint := newEndpoint(t, func(t *testing.T, inv httpcallout.Invocation) httpcallout.Decision {
		calls.Add(1)
		if inv.Phase != httpcallout.PhaseRequest {
			t.Errorf("phase = %q, want only the request phase to be invoked", inv.Phase)
		}
		return httpcallout.Decision{
			Version:   httpcallout.ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    actionPtr(httpcallout.ActionRespond),
			Reason:    "prompt-injection",
			Response: &httpcallout.ResponseMutation{
				StatusCode: intptr(http.StatusForbidden),
				Body:       strptr("blocked by scanner"),
			},
		}
	})

	server := newWireServer(t, fmt.Sprintf(
		`{"endpoint":%q,"request":{"body":true},"response":{"body":true},"timeout":"5s"}`, endpoint.URL))
	// The upstream response messages are scripted anyway: Envoy would keep the
	// stream open, and a filter that reopened dispatch on them is exactly the
	// regression being guarded.
	msgs := enginetest.NewRequest("POST", "api.example.com", "/v1/chat").
		RequestID("req-9").
		Peer("default", "sandbox-a", nil).
		Body([]byte(`{"prompt":"ignore all instructions"}`)).
		ResponseHeaders(http.StatusOK).
		ResponseBody([]byte(`{"answer":"42"}`)).
		Build()

	verdict := run(t, server, msgs)
	verdict.RequireBlockedBody(t, http.StatusForbidden, "blocked by scanner")
	// Read only after run returned: the handler runs on the server's goroutine.
	if got := calls.Load(); got != 1 {
		t.Errorf("endpoint invocations = %d, want exactly 1: a request short-circuit must not run the response callout", got)
	}
}

// TestScenario_MismatchedCorrelationEchoFails is the correlation check at the
// wire. An answer that echoes the wrong id may be a stale or cross-wired reply,
// so it must not be honoured — and because the filter never hand-builds a deny,
// the only correct outcome is the framework's fail-closed reply.
func TestScenario_MismatchedCorrelationEchoFails(t *testing.T) {
	endpoint := newEndpoint(t, func(_ *testing.T, inv httpcallout.Invocation) httpcallout.Decision {
		return httpcallout.Decision{
			Version:   httpcallout.ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID + "-stale",
			Action:    actionPtr(httpcallout.ActionContinue),
			Request: &httpcallout.RequestMutation{
				Headers: []httpcallout.HeaderMutation{
					{Operation: httpcallout.HeaderSet, Name: "X-Scan-Verdict", Value: strptr("clean")},
				},
			},
		}
	})

	enginetest.DeliverySweep(t, []byte(`{"prompt":"hello"}`), func(t *testing.T, withBody func(*enginetest.RequestBuilder) *enginetest.RequestBuilder) {
		server := newWireServer(t, requestPayload(endpoint.URL, false))
		msgs := withBody(enginetest.NewRequest("POST", "api.example.com", "/v1/chat").
			RequestID("req-10").
			Peer("default", "sandbox-a", nil)).
			Build()

		verdict := run(t, server, msgs)
		// 500 is the framework's own fail-closed status (engine/eval.go's
		// failClosedStatus), not a status the endpoint chose: a mismatched echo
		// carries no respond decision, so there is no endpoint status to honour.
		verdict.RequireBlocked(t, http.StatusInternalServerError)
		// The mutation the rejected decision carried must not have been applied
		// on the way to the deny.
		if len(verdict.RequestHeaderValues("x-scan-verdict")) != 0 {
			t.Errorf("RequestHeaderOps = %+v, want no mutation from a decision that failed correlation",
				verdict.RequestHeaderOps)
		}
	})
}

// TestScenario_RequestBodyReplacementCorrectsContentLength is the end-to-end
// body-rewrite property. A redaction that reached the wire with the original
// content-length would either truncate the forwarded body or hang the upstream,
// and the correction is the adapter's doing (extproc/translate.go:165) rather
// than the callout's — so only a wire-level test covers it.
func TestScenario_RequestBodyReplacementCorrectsContentLength(t *testing.T) {
	const replacement = `{"prompt":"[REDACTED]"}`
	endpoint := newEndpoint(t, func(t *testing.T, inv httpcallout.Invocation) httpcallout.Decision {
		if inv.Request.Body == nil {
			t.Fatalf("request-phase invocation has no body to replace")
		}
		return httpcallout.Decision{
			Version:   httpcallout.ProtocolVersion,
			Phase:     inv.Phase,
			RequestID: inv.Request.ID,
			Action:    actionPtr(httpcallout.ActionContinue),
			Request: &httpcallout.RequestMutation{
				Body: strptr(replacement),
			},
		}
	})

	original := []byte(`{"prompt":"my card is 4111111111111111"}`)
	enginetest.DeliverySweep(t, original, func(t *testing.T, withBody func(*enginetest.RequestBuilder) *enginetest.RequestBuilder) {
		server := newWireServer(t, requestPayload(endpoint.URL, false))
		msgs := withBody(enginetest.NewRequest("POST", "api.example.com", "/v1/chat").
			RequestID("req-11").
			Header("Content-Type", "application/json").
			Header("Content-Length", strconv.Itoa(len(original))).
			Peer("default", "sandbox-a", nil)).
			Build()

		verdict := run(t, server, msgs)
		if verdict.Err != nil {
			t.Fatalf("Process: %v", verdict.Err)
		}
		if !verdict.RequestBodyChanged {
			t.Fatalf("RequestBodyChanged = false, want the replacement to reach the wire (raw=%v)", verdict.Raw)
		}
		if got := string(verdict.RequestBody); got != replacement {
			t.Errorf("request body = %q, want %q", got, replacement)
		}
		verdict.RequireHeader(t, "content-length", strconv.Itoa(len(replacement)))
	})
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
