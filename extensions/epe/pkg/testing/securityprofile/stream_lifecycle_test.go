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

// Stream-end acceptance invariants exercised through the real Process loop.
package securityprofile

import (
	"context"
	"errors"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
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

// The stream loggers must fire on abnormal termination — a stream torn
// down by a receive failure still produces exactly one entry, marked as an
// error, or the requests that need auditing most vanish.
func TestScenario_AbnormalTerminationStillLogged(t *testing.T) {
	h := New(t, Options{})
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
	h := New(t, Options{})
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
	h := New(t, Options{})
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

// With statically configured response.headerMode=SEND and no matched policy,
// response headers still need a matching acknowledgement and one final audit.
func TestScenario_StaticResponseHeadersWithoutMatchedPolicyAreAcknowledged(t *testing.T) {
	h := New(t, Options{})
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
	h := New(t, Options{})
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

// Envoy routinely resets the ext-proc stream instead of half-closing once
// it needs nothing further. With matched policy units but no outstanding
// obligation, that reset is normal completion, not an error.
func TestScenario_CanceledReceiveWithMatchedPolicyIsPassthrough(t *testing.T) {
	h := New(t, Options{})
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
	h := New(t, Options{})
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
