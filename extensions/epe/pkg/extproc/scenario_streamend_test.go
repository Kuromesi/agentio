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

// Stream-end acceptance invariants plus the
// response-side observation path — full-chain scenarios through the real
// Process loop.
package extproc_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/filters/bypass"
	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
)

const blockingRuleYAML = `  - name: deny
    match:
    - domains:
      - "*"
    actions:
      block:
        statusCode: 403
`

func passthroughProfile() *v1alpha1.SecurityProfile {
	return securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{{
		Name:    "match-all",
		Match:   []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
		Actions: v1alpha1.SecurityRuleActions{},
	}})
}

// bodyBypassFilter keeps the public Bypass action's policy projection but
// postpones its decision until the buffered body phase. It exercises the
// delayed-finalization path that a normal header-only bypass cannot reach.
type bodyBypassFilter struct{ filter.PassThrough }

func (bodyBypassFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(), nil
}

func (bodyBypassFilter) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	return filter.Bypass(), nil
}

func bodyBypassRegistration() filter.Registration {
	return filter.Registration{
		Name:    bypass.FilterName,
		Phases:  filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		Body:    filter.BodyComplete,
		OnError: filter.FailClosed,
		Parse:   func(json.RawMessage) (any, error) { return struct{}{}, nil },
		New:     func(filter.ErasedRuleConfig) filter.Filter { return bodyBypassFilter{} },
	}
}

type responseRecordingStreamLogger struct {
	calls       int
	disposition string
	status      int
}

func (l *responseRecordingStreamLogger) Log(_ context.Context, st *filter.Stream, info *filter.StreamInfo) {
	l.calls++
	l.disposition = info.Disposition.String()
	l.status = st.Response.Status
}

// failNthSendStream preserves the package's deterministic Process fixture
// while injecting a failure at one exact response boundary.
type failNthSendStream struct {
	*enginetest.ScriptedStream
	failAt  int
	sendErr error
	sends   int
}

func (s *failNthSendStream) Send(resp *extProcPb.ProcessingResponse) error {
	s.sends++
	if s.sends == s.failAt {
		return s.sendErr
	}
	return s.ScriptedStream.Send(resp)
}

// The stream loggers must fire on abnormal termination — a stream torn
// down by a receive failure still produces exactly one entry, marked as an
// error, or the requests that need auditing most vanish.
func TestScenario_AbnormalTerminationStillLogged(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{})
	h.Fixture.ApplyProfile(passthroughProfile())

	msgs := blockedPeerRequest("GET", "api.example.com", "/x").Build()
	stream := enginetest.NewScriptedStream(t.Context(), msgs...)
	stream.RecvErr = errors.New("connection reset by peer")

	if err := h.RunStream(t, stream); err == nil {
		t.Fatal("want Process to surface the receive failure")
	}
	entries := h.AccessLog.Entries()
	if len(entries) != 1 {
		t.Fatalf("want exactly 1 accesslog entry from the torn-down stream, got %d", len(entries))
	}
	got := entries[0]
	if got.Outcome != "error" {
		t.Errorf("Outcome = %q, want error — a mid-request teardown is not a passthrough", got.Outcome)
	}
	if got.Error == "" {
		t.Error("Error is empty; the teardown reason must be recorded")
	}
}

func TestScenario_CommittedBlockIsNotOverwrittenByRecvFailure(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(blockingRuleYAML))
	stream := enginetest.NewScriptedStream(t.Context(),
		blockedPeerRequest("GET", "api.example.com", "/deny").Build()...)
	stream.StopOnImmediate = false
	stream.RecvErr = errors.New("stream reset after immediate response")
	if err := h.RunStream(t, stream); err == nil {
		t.Fatal("want the receive failure to remain visible to the gRPC caller")
	}
	entries := h.AccessLog.Entries()
	if len(entries) != 1 || entries[0].Outcome != "blocked" {
		t.Fatalf("entries = %+v, want one blocked entry", entries)
	}
}

func TestScenario_UnsentBlockIsAuditedAsError(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(blockingRuleYAML))
	stream := enginetest.NewScriptedStream(t.Context(),
		blockedPeerRequest("GET", "api.example.com", "/deny").Build()...)
	stream.SendErr = errors.New("send failed")
	if err := h.RunStream(t, stream); err == nil {
		t.Fatal("want Process to return the send failure")
	}
	entries := h.AccessLog.Entries()
	if len(entries) != 1 || entries[0].Outcome != "error" {
		t.Fatalf("entries = %+v, want one error entry", entries)
	}
}

// A statically configured response.headerMode=SEND is independent of the
// server's dynamic ObserveResponses mode. With no matched policy, the first
// response headers still need a matching acknowledgement and one final audit.
func TestScenario_StaticResponseHeadersWithoutMatchedPolicyAreAcknowledged(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{})
	msgs := blockedPeerRequest("GET", "api.example.com", "/x").Build()
	msgs = append(msgs, &extProcPb.ProcessingRequest{
		Request: &extProcPb.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: responseHeadersMsg("204"),
		},
	})

	verdict := h.RunMessages(t, msgs)
	if verdict.Err != nil {
		t.Fatalf("Process error = %v, want nil", verdict.Err)
	}
	if verdict.ModeOverride != nil {
		t.Fatalf("ModeOverride = %+v, want static response selection only", verdict.ModeOverride)
	}
	if len(verdict.Raw) != 2 || verdict.Raw[1].GetResponseHeaders() == nil {
		t.Fatalf("responses = %+v, want request- and response-headers acknowledgements", verdict.Raw)
	}
	if len(verdict.AccessLog) != 1 || verdict.AccessLog[0].Outcome != "passthrough" {
		t.Fatalf("accesslog = %+v, want exactly one passthrough entry", verdict.AccessLog)
	}
}

// Headers-phase Bypass commits after its request-headers acknowledgement, but
// a response selected by static configuration remains protocol-valid. It must
// be acknowledged without reopening the already committed audit lifecycle.
func TestScenario_StaticResponseHeadersAfterHeadersBypassAreAcknowledgedOnce(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(`  - name: trust-internal
    match:
    - domains:
      - internal.local
    actions:
      bypass: true
`))
	msgs := blockedPeerRequest("GET", "internal.local", "/anything").Build()
	msgs = append(msgs, &extProcPb.ProcessingRequest{
		Request: &extProcPb.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: responseHeadersMsg("204"),
		},
	})

	verdict := h.RunMessages(t, msgs)
	if verdict.Err != nil {
		t.Fatalf("Process error = %v, want nil", verdict.Err)
	}
	if verdict.ModeOverride != nil {
		t.Fatalf("ModeOverride = %+v, want static response selection only", verdict.ModeOverride)
	}
	if len(verdict.Raw) != 2 || verdict.Raw[1].GetResponseHeaders() == nil {
		t.Fatalf("responses = %+v, want request- and response-headers acknowledgements", verdict.Raw)
	}
	if len(verdict.AccessLog) != 1 || verdict.AccessLog[0].Outcome != "bypassed" {
		t.Fatalf("accesslog = %+v, want exactly one bypassed entry", verdict.AccessLog)
	}
}

func TestScenario_BodyPhaseBlockWithResponseObservationEndsCleanly(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{ObserveResponses: true})
	h.Fixture.ApplyProfile(securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{{
		Name:  "inspect-body",
		Match: []v1alpha1.RuleMatch{{Domains: []string{"mcp-server.example.com"}}},
		Actions: v1alpha1.SecurityRuleActions{
			MCPToolPolicy: mcpToolPolicy("deny", "tools/call", "safe-tool", "allow"),
		},
	}}))

	verdict := h.Run(t, mcpRequest("mcp-server.example.com", []byte(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"forbidden-tool"}}`,
	)))
	verdict.RequireBlocked(t, 403)
	if len(verdict.AccessLog) != 1 || verdict.AccessLog[0].Outcome != "blocked" {
		t.Fatalf("accesslog = %+v, want one blocked entry", verdict.AccessLog)
	}
}

func TestScenario_OutstandingResponseAtEOFIsError(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{ObserveResponses: true})
	h.Fixture.ApplyProfile(passthroughProfile())

	verdict := h.Run(t, blockedPeerRequest("GET", "api.example.com", "/x"))
	if got := status.Code(verdict.Err); got != codes.Unknown {
		t.Fatalf("Process error code = %v, want Unknown for an outstanding response obligation", got)
	}
	entries := h.AccessLog.Entries()
	if len(entries) != 1 || entries[0].Outcome != "error" {
		t.Fatalf("entries = %+v, want one error entry", entries)
	}
}

// A cancel that arrives while the server still awaits an input it asked
// for (here: response headers) truncates the exchange and must be audited
// as an error, even though the gRPC caller sees a clean return.
func TestScenario_CanceledReceiveWithOutstandingObligationAuditsError(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{ObserveResponses: true})
	h.Fixture.ApplyProfile(passthroughProfile())
	stream := enginetest.NewScriptedStream(t.Context(),
		blockedPeerRequest("GET", "api.example.com", "/x").Build()...)
	stream.RecvErr = context.Canceled

	if err := h.RunStream(t, stream); err != nil {
		t.Fatalf("Process error = %v, want nil for a canceled receive", err)
	}
	entries := h.AccessLog.Entries()
	if len(entries) != 1 || entries[0].Outcome != "error" {
		t.Fatalf("entries = %+v, want one error entry", entries)
	}
}

// Envoy routinely resets the ext-proc stream instead of half-closing once
// it needs nothing further. With matched policy units but no outstanding
// obligation, that reset is normal completion, not an error.
func TestScenario_CanceledReceiveWithMatchedPolicyIsPassthrough(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{})
	h.Fixture.ApplyProfile(passthroughProfile())
	stream := enginetest.NewScriptedStream(t.Context(),
		blockedPeerRequest("GET", "api.example.com", "/x").Build()...)
	stream.RecvErr = context.Canceled

	if err := h.RunStream(t, stream); err != nil {
		t.Fatalf("Process error = %v, want nil for a canceled receive", err)
	}
	entries := h.AccessLog.Entries()
	if len(entries) != 1 {
		t.Fatalf("entries = %+v, want one passthrough entry", entries)
	}
	if got := entries[0]; got.Outcome != "passthrough" || got.Error != "" {
		t.Fatalf("entry = %+v, want passthrough without error", got)
	}
}

func TestScenario_CanceledReceiveWithoutPolicyIsPassthrough(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{})
	stream := enginetest.NewScriptedStream(t.Context(),
		blockedPeerRequest("GET", "api.example.com", "/x").Build()...)
	stream.RecvErr = context.Canceled

	if err := h.RunStream(t, stream); err != nil {
		t.Fatalf("Process error = %v, want nil for a canceled receive", err)
	}
	entries := h.AccessLog.Entries()
	if len(entries) != 1 {
		t.Fatalf("entries = %+v, want one passthrough entry", entries)
	}
	if got := entries[0]; got.Outcome != "passthrough" || got.Error != "" {
		t.Fatalf("entry = %+v, want passthrough without error", got)
	}
}

// A body-phase bypass still owes the adapter a response observation. The
// logger can run only after Envoy has accepted the response-headers reply,
// otherwise the audit loses the upstream status (or fires twice).
func TestScenario_BodyBypassWaitsForResponseStatus(t *testing.T) {
	logger := &responseRecordingStreamLogger{}
	h := enginetest.New(t, enginetest.Options{
		Filters:          regsWith(t, nil, bodyBypassRegistration()),
		StreamLoggers:    []filter.StreamLogger{logger},
		ObserveResponses: true,
	})
	h.Fixture.ApplyProfile(securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{{
		Name:    "bypass-after-body",
		Match:   []v1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
		Actions: v1alpha1.SecurityRuleActions{Bypass: true},
	}}))

	msgs := blockedPeerRequest("POST", "api.example.com", "/body").Body([]byte(`{}`)).Build()
	msgs = append(msgs, &extProcPb.ProcessingRequest{
		Request: &extProcPb.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: responseHeadersMsg("204"),
		},
	})
	verdict := h.RunMessages(t, msgs)
	if verdict.Err != nil {
		t.Fatalf("Process error = %v, want nil", verdict.Err)
	}
	if logger.calls != 1 {
		t.Fatalf("logger calls = %d, want exactly 1 after response headers", logger.calls)
	}
	if logger.disposition != "bypassed" {
		t.Errorf("logger disposition = %q, want bypassed", logger.disposition)
	}
	if logger.status != 204 {
		t.Errorf("logger response status = %d, want 204", logger.status)
	}
}

// Response headers are observed before their reply is sent, but that is not
// a committed audit boundary. A failed final Send must finalize the exchange
// as error even though the status is already available in the stream view.
func TestScenario_BodyBypassFinalResponseSendFailureAuditsError(t *testing.T) {
	logger := &responseRecordingStreamLogger{}
	h := enginetest.New(t, enginetest.Options{
		Filters:          regsWith(t, nil, bodyBypassRegistration()),
		StreamLoggers:    []filter.StreamLogger{logger},
		ObserveResponses: true,
	})
	h.Fixture.ApplyProfile(securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{{
		Name:    "bypass-after-body",
		Match:   []v1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
		Actions: v1alpha1.SecurityRuleActions{Bypass: true},
	}}))

	msgs := blockedPeerRequest("POST", "api.example.com", "/body").Body([]byte(`{}`)).Build()
	msgs = append(msgs, &extProcPb.ProcessingRequest{
		Request: &extProcPb.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: responseHeadersMsg("204"),
		},
	})
	sendErr := errors.New("response-headers send failed")
	stream := &failNthSendStream{
		ScriptedStream: enginetest.NewScriptedStream(t.Context(), msgs...),
		failAt:         3, // request headers and buffered body replies succeed first
		sendErr:        sendErr,
	}

	err := h.RunStream(t, stream)
	if got := status.Code(err); got != codes.Unknown {
		t.Fatalf("Process error code = %v, want Unknown", got)
	}
	if !strings.Contains(err.Error(), sendErr.Error()) {
		t.Fatalf("Process error = %v, want final send failure %q", err, sendErr)
	}
	if got := len(stream.Responses()); got != 2 {
		t.Fatalf("successful responses before failure = %d, want request headers and body only", got)
	}
	entries := h.AccessLog.Entries()
	if len(entries) != 1 || entries[0].Outcome != "error" {
		t.Fatalf("accesslog = %+v, want one error entry", entries)
	}
	if logger.calls != 1 || logger.disposition != "error" {
		t.Fatalf("policy logger = calls:%d disposition:%q, want one error entry", logger.calls, logger.disposition)
	}
	if logger.status != 204 {
		t.Errorf("policy logger response status = %d, want observed 204", logger.status)
	}
}

// EOF after a body bypass is a protocol failure when response observation was
// requested: recording bypassed before those headers arrive would silently
// claim a complete exchange that never happened.
func TestScenario_BodyBypassWithoutResponseHeadersIsError(t *testing.T) {
	logger := &responseRecordingStreamLogger{}
	h := enginetest.New(t, enginetest.Options{
		Filters:          regsWith(t, nil, bodyBypassRegistration()),
		StreamLoggers:    []filter.StreamLogger{logger},
		ObserveResponses: true,
	})
	h.Fixture.ApplyProfile(securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{{
		Name:    "bypass-after-body",
		Match:   []v1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
		Actions: v1alpha1.SecurityRuleActions{Bypass: true},
	}}))

	verdict := h.Run(t, blockedPeerRequest("POST", "api.example.com", "/body").Body([]byte(`{}`)))
	if got := status.Code(verdict.Err); got != codes.Unknown {
		t.Fatalf("Process error code = %v, want Unknown for missing response headers", got)
	}
	if logger.calls != 1 {
		t.Fatalf("logger calls = %d, want exactly 1 error entry", logger.calls)
	}
	if logger.disposition != "error" {
		t.Errorf("logger disposition = %q, want error", logger.disposition)
	}
}

// Every headers-phase ModeOverride must restate both body modes and, when
// response observation is on, open the response-headers phase (the merge
// base is the static config, so an unset mode silently becomes NONE).
func TestScenario_ObserveResponsesOverrideContent(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{ObserveResponses: true})
	h.Fixture.ApplyProfile(passthroughProfile())

	verdict := h.Run(t, blockedPeerRequest("GET", "api.example.com", "/x"))
	if verdict.ModeOverride == nil {
		t.Fatal("want a ModeOverride opening the response side")
	}
	if verdict.ModeOverride.ResponseHeaderMode != extProcV3.ProcessingMode_SEND {
		t.Errorf("ResponseHeaderMode = %v, want SEND", verdict.ModeOverride.ResponseHeaderMode)
	}
	if verdict.ModeOverride.RequestBodyMode != extProcV3.ProcessingMode_NONE {
		t.Errorf("RequestBodyMode = %v, want restated NONE", verdict.ModeOverride.RequestBodyMode)
	}
	if verdict.ModeOverride.ResponseBodyMode != extProcV3.ProcessingMode_NONE {
		t.Errorf("ResponseBodyMode = %v, want restated NONE", verdict.ModeOverride.ResponseBodyMode)
	}
}

// The upstream status delivered on the response side must land in the
// stream view the loggers observe (the first response consumer).
func TestScenario_ResponseStatusRecorded(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{ObserveResponses: true})
	h.Fixture.ApplyProfile(passthroughProfile())

	msgs := blockedPeerRequest("GET", "api.example.com", "/x").Build()
	msgs = append(msgs, &extProcPb.ProcessingRequest{
		Request: &extProcPb.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: responseHeadersMsg("200"),
		},
	})
	h.RunMessages(t, msgs)

	st := h.Probe().LastStream()
	if st == nil {
		t.Fatal("no stream captured")
	}
	if st.Response.Status != 200 {
		t.Fatalf("Response.Status = %d, want 200", st.Response.Status)
	}
}

// responseHeadersMsg builds the response-headers message Envoy sends when
// the response side is open.
func responseHeadersMsg(status string) *extProcPb.HttpHeaders {
	return &extProcPb.HttpHeaders{
		Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
			{Key: ":status", RawValue: []byte(status)},
			{Key: "content-type", RawValue: []byte("application/json")},
		}},
	}
}
