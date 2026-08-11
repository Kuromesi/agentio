// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package enginetest

import (
	"strings"
	"testing"

	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"istio.io/istio/extensions/epe/pkg/audit/accesslog"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// VerdictKind is the wire-level classification of a response sequence.
// Bypass and passthrough are indistinguishable on the wire; use
// Verdict.Info (captured by the harness probe) to tell them apart.
type VerdictKind string

const (
	VerdictBlocked     VerdictKind = "blocked"
	VerdictMutated     VerdictKind = "mutated"
	VerdictPassthrough VerdictKind = "passthrough"
)

// Verdict reduces the response sequence of one request to assertable facts.
type Verdict struct {
	Kind VerdictKind

	// ImmediateStatus and ImmediateBody are set when Kind is VerdictBlocked.
	ImmediateStatus int
	ImmediateBody   string

	// SetHeaders and RemovedHeaders merge every header mutation across the
	// headers-phase responses and the body-phase merged mutation.
	SetHeaders     map[string]string
	RemovedHeaders []string

	// ModeOverride is the ProcessingMode set on the first headers-phase
	// response; non-nil proves the NeedsBody signalling fired.
	ModeOverride *extProcV3.ProcessingMode

	// Info is the authoritative StreamInfo observed by the harness
	// InfoProbe; nil when the probe was disabled or never invoked.
	Info *filter.StreamInfo

	// AccessLog holds every entry submitted to the harness audit logger.
	AccessLog []accesslog.Entry

	// Raw preserves the full ordered response sequence (read-only: some
	// responses are shared package singletons).
	Raw []*extProcPb.ProcessingResponse

	// Err is the error returned by Process; nil on clean EOF shutdown.
	Err error
}

// ParseVerdict classifies a response sequence.
func ParseVerdict(responses []*extProcPb.ProcessingResponse, procErr error) *Verdict {
	v := &Verdict{
		Kind:       VerdictPassthrough,
		SetHeaders: map[string]string{},
		Raw:        responses,
		Err:        procErr,
	}
	for i, resp := range responses {
		if i == 0 && resp.ModeOverride != nil {
			v.ModeOverride = resp.ModeOverride
		}
		switch r := resp.GetResponse().(type) {
		case *extProcPb.ProcessingResponse_ImmediateResponse:
			v.Kind = VerdictBlocked
			v.ImmediateStatus = int(r.ImmediateResponse.GetStatus().GetCode())
			v.ImmediateBody = string(r.ImmediateResponse.GetBody())
			return v
		case *extProcPb.ProcessingResponse_RequestHeaders:
			v.mergeMutation(r.RequestHeaders.GetResponse().GetHeaderMutation())
		case *extProcPb.ProcessingResponse_RequestBody:
			v.mergeMutation(r.RequestBody.GetResponse().GetHeaderMutation())
		}
	}
	if len(v.SetHeaders) > 0 || len(v.RemovedHeaders) > 0 {
		v.Kind = VerdictMutated
	}
	return v
}

func (v *Verdict) mergeMutation(hm *extProcPb.HeaderMutation) {
	if hm == nil {
		return
	}
	for _, h := range hm.GetSetHeaders() {
		header := h.GetHeader()
		if header == nil {
			continue
		}
		value := string(header.GetRawValue())
		if value == "" {
			value = header.GetValue()
		}
		v.SetHeaders[strings.ToLower(header.GetKey())] = value
	}
	v.RemovedHeaders = append(v.RemovedHeaders, hm.GetRemoveHeaders()...)
}

// RequireBlocked asserts an ImmediateResponse with the given status.
func (v *Verdict) RequireBlocked(t *testing.T, wantStatus int) {
	t.Helper()
	v.requireNoErr(t)
	if v.Kind != VerdictBlocked {
		t.Fatalf("verdict = %s, want blocked (raw=%v)", v.Kind, v.Raw)
	}
	if v.ImmediateStatus != wantStatus {
		t.Fatalf("immediate status = %d, want %d (body=%q)", v.ImmediateStatus, wantStatus, v.ImmediateBody)
	}
}

// RequireBlockedBody additionally asserts the immediate response body.
func (v *Verdict) RequireBlockedBody(t *testing.T, wantStatus int, wantBodyContains string) {
	t.Helper()
	v.RequireBlocked(t, wantStatus)
	if !strings.Contains(v.ImmediateBody, wantBodyContains) {
		t.Fatalf("immediate body = %q, want it to contain %q", v.ImmediateBody, wantBodyContains)
	}
}

// RequirePassthrough asserts the request passed through unmodified and, when
// the probe captured a resolution, that the outcome was "passthrough".
func (v *Verdict) RequirePassthrough(t *testing.T) {
	t.Helper()
	v.requireNoErr(t)
	if v.Kind != VerdictPassthrough {
		t.Fatalf("verdict = %s, want passthrough (raw=%v)", v.Kind, v.Raw)
	}
	if v.Info != nil && v.Info.Disposition.String() != "passthrough" {
		t.Fatalf("disposition = %q, want passthrough", v.Info.Disposition)
	}
}

// RequireBypassed asserts the wire shape is passthrough and the resolved
// outcome is "bypassed" — the only way to distinguish the two.
func (v *Verdict) RequireBypassed(t *testing.T) {
	t.Helper()
	v.requireNoErr(t)
	if v.Kind != VerdictPassthrough {
		t.Fatalf("verdict = %s, want passthrough wire shape for bypass (raw=%v)", v.Kind, v.Raw)
	}
	if v.Info == nil {
		t.Fatal("no resolution captured; bypass cannot be distinguished from passthrough (probe disabled?)")
	}
	if v.Info.Disposition.String() != "bypassed" {
		t.Fatalf("disposition = %q, want bypassed", v.Info.Disposition)
	}
}

// RequireHeader asserts a merged header mutation set key to want.
func (v *Verdict) RequireHeader(t *testing.T, key, want string) {
	t.Helper()
	got, ok := v.SetHeaders[strings.ToLower(key)]
	if !ok {
		t.Fatalf("header %q not set (set=%v)", key, v.SetHeaders)
	}
	if got != want {
		t.Fatalf("header %q = %q, want %q", key, got, want)
	}
}

// RequireOutcome asserts the resolved outcome string.
func (v *Verdict) RequireOutcome(t *testing.T, want string) {
	t.Helper()
	if v.Info == nil {
		t.Fatal("no resolution captured (probe disabled?)")
	}
	if v.Info.Disposition.String() != want {
		t.Fatalf("disposition = %q, want %q", v.Info.Disposition, want)
	}
}

// RequireGRPCCode asserts Process returned an error with the given code.
func (v *Verdict) RequireGRPCCode(t *testing.T, want codes.Code) {
	t.Helper()
	if got := status.Code(v.Err); got != want {
		t.Fatalf("Process error code = %v (err=%v), want %v", got, v.Err, want)
	}
}

func (v *Verdict) requireNoErr(t *testing.T) {
	t.Helper()
	if v.Err != nil {
		t.Fatalf("Process returned error: %v", v.Err)
	}
}
