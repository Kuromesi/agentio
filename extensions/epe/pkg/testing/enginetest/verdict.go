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

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
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

// HeaderOpKind names what a header operation does. It mirrors filter.HeaderOp's
// kinds but is a distinct type because it is derived from the wire proto: a
// verdict assertion therefore cannot be satisfied by an engine result that never
// reached a ProcessingResponse.
type HeaderOpKind string

const (
	// HeaderSet is OVERWRITE_IF_EXISTS_OR_ADD: it replaces every existing line
	// for the name.
	HeaderSet HeaderOpKind = "set"
	// HeaderAppend is APPEND_IF_EXISTS_OR_ADD: it adds one more line, which is
	// the only way to emit several set-cookie headers.
	HeaderAppend HeaderOpKind = "append"
	// HeaderRemove is a remove_headers entry.
	HeaderRemove HeaderOpKind = "remove"
)

// HeaderOp records one normalized header operation decoded from an ext_proc response.
type HeaderOp struct {
	Kind  HeaderOpKind
	Name  string
	Value string
}

// Verdict reduces the response sequence of one request to assertable facts.
type Verdict struct {
	Kind VerdictKind

	// ImmediateStatus and ImmediateBody are set when Kind is VerdictBlocked.
	ImmediateStatus int
	ImmediateBody   string

	// RequestHeaderOps and ResponseHeaderOps record decoded wire operations by
	// direction and in protobuf order. RequestHeaderOps includes mutations from
	// both request-header and request-body responses.
	RequestHeaderOps  []HeaderOp
	ResponseHeaderOps []HeaderOp

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
		Kind: VerdictPassthrough,
		Raw:  responses,
		Err:  procErr,
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
			v.RequestHeaderOps = appendOps(v.RequestHeaderOps, r.RequestHeaders.GetResponse().GetHeaderMutation())
		case *extProcPb.ProcessingResponse_RequestBody:
			v.RequestHeaderOps = appendOps(v.RequestHeaderOps, r.RequestBody.GetResponse().GetHeaderMutation())
		case *extProcPb.ProcessingResponse_ResponseHeaders:
			v.ResponseHeaderOps = appendOps(v.ResponseHeaderOps, r.ResponseHeaders.GetResponse().GetHeaderMutation())
		}
	}
	// Kind describes the *request* verdict, so a response-only mutation leaves
	// it at passthrough: nothing about the forwarded request changed.
	if len(v.RequestHeaderOps) > 0 {
		v.Kind = VerdictMutated
	}
	return v
}

// appendOps appends one HeaderMutation in protobuf field order.
func appendOps(ops []HeaderOp, hm *extProcPb.HeaderMutation) []HeaderOp {
	if hm == nil {
		return ops
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
		kind := HeaderSet
		if h.GetAppendAction() == corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD {
			kind = HeaderAppend
		}
		ops = append(ops, HeaderOp{Kind: kind, Name: strings.ToLower(header.GetKey()), Value: value})
	}
	for _, name := range hm.GetRemoveHeaders() {
		ops = append(ops, HeaderOp{Kind: HeaderRemove, Name: strings.ToLower(name)})
	}
	return ops
}

// headerValues returns every value ops set or appended for name, in wire order.
func headerValues(ops []HeaderOp, name string) []string {
	want := strings.ToLower(name)
	var out []string
	for _, op := range ops {
		if op.Name == want && op.Kind != HeaderRemove {
			out = append(out, op.Value)
		}
	}
	return out
}

// requireHeader asserts a single value and includes dir in failures.
func requireHeader(t *testing.T, ops []HeaderOp, dir, name, want string) {
	t.Helper()
	got := headerValues(ops, name)
	if len(got) != 1 {
		t.Fatalf("%s header %q values = %v, want exactly [%q] (ops=%+v)", dir, name, got, want, ops)
	}
	if got[0] != want {
		t.Fatalf("%s header %q = %q, want %q", dir, name, got[0], want)
	}
}

// headerRemoved reports whether ops removed name.
func headerRemoved(ops []HeaderOp, name string) bool {
	want := strings.ToLower(name)
	for _, op := range ops {
		if op.Kind == HeaderRemove && op.Name == want {
			return true
		}
	}
	return false
}

func requireHeaderRemoved(t *testing.T, ops []HeaderOp, dir, name string) {
	t.Helper()
	if !headerRemoved(ops, name) {
		t.Fatalf("%s header %q not removed (ops=%+v)", dir, name, ops)
	}
}

// RequestHeaderValues returns every value the request direction set or appended
// for name, in wire order. Several values mean several header lines.
func (v *Verdict) RequestHeaderValues(name string) []string {
	return headerValues(v.RequestHeaderOps, name)
}

// ResponseHeaderValues returns every value the response phase set or appended
// for name, in wire order. Several values mean several header lines, which is
// how multi-valued set-cookie is expressed.
func (v *Verdict) ResponseHeaderValues(name string) []string {
	return headerValues(v.ResponseHeaderOps, name)
}

// RequireHeader asserts the request direction produced exactly one value for
// name, equal to want.
func (v *Verdict) RequireHeader(t *testing.T, name, want string) {
	t.Helper()
	requireHeader(t, v.RequestHeaderOps, "request", name, want)
}

// RequireResponseHeader asserts the response phase produced exactly one value
// for name, equal to want.
func (v *Verdict) RequireResponseHeader(t *testing.T, name, want string) {
	t.Helper()
	requireHeader(t, v.ResponseHeaderOps, "response", name, want)
}

// RequireHeaderRemoved asserts the request direction removed name.
func (v *Verdict) RequireHeaderRemoved(t *testing.T, name string) {
	t.Helper()
	requireHeaderRemoved(t, v.RequestHeaderOps, "request", name)
}

// RequireResponseHeaderRemoved asserts the response phase removed name.
func (v *Verdict) RequireResponseHeaderRemoved(t *testing.T, name string) {
	t.Helper()
	requireHeaderRemoved(t, v.ResponseHeaderOps, "response", name)
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
