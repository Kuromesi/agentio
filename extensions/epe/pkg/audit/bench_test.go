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
package audit

import (
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/eval"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// benchSink defeats dead-code elimination.
var benchSink any

// BenchmarkAuditActivation charges the audit projection's two halves separately:
// the memoised base, which every evaluation after the first gets for a map
// lookup, and the full audit.Scope.Activation, which additionally builds the
// hierarchical child holding `result`.
//
// The child is the interesting number, because it is rebuilt on every call even
// though Result is fixed once buildScope has run
// (policy/securityprofile/auditlog.go:105). That caller builds one scope per unit
// and then loops over N audit entries, calling EvalWhen on each, so the child's
// cost is paid N times per matched unit for a value that never changes — i.e.
// this is a memoisation candidate. Measuring it is the point here; nothing is
// optimised.
//
// It lives in package audit because eval cannot import audit (audit imports
// eval), so eval's BenchmarkActivation can only reach the base, and
// BenchmarkEvalBool hoists its layering out of the timed loop by contract.
func BenchmarkAuditActivation(b *testing.B) {
	s := benchAuditScope()
	// Guard the fixture: both arms must project what the names claim, or the
	// numbers would describe a trivial bag. The base must carry the request and
	// must NOT resolve the audit-only variables; the full activation must
	// resolve both those and the base.
	guardBase(b, &s.Scope)
	guardFull(b, s)

	b.Run("base-memoised", func(b *testing.B) {
		base := &s.Scope
		_ = base.Activation() // pay the first-call projection outside the loop
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchSink = base.Activation()
		}
	})
	b.Run("full-with-audit-child", func(b *testing.B) {
		_ = s.Activation() // memoise the base so the loop charges only the child
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchSink = s.Activation()
		}
	})
}

func benchAuditScope() *Scope {
	return &Scope{
		Scope: *inputs.NewScope(
			inputs.RequestFrom(httpreq.HTTPRequest{
				Host: "api.example.com", Port: 443, Path: "/v1/chat/completions",
				Scheme: "https", Method: "POST",
				Headers: map[string]string{"x-request-id": "abc", "x-tenant": "a"},
			}),
			inputs.Pod{Name: "sandbox-pod", Namespace: "test-ns", IP: "10.0.0.1", Labels: map[string]string{"app": "sleep"}},
			inputs.Profile{Name: "profile", Namespace: "test-ns"},
			inputs.Rule{Name: "rule"},
			nil,
		),
		Result: "blocked",
	}
}

// guardBase fails the benchmark unless the base really projects the request and
// really lacks the audit-only variables — the property that makes the two arms
// measure different things.
func guardBase(b *testing.B, base *inputs.Scope) {
	b.Helper()
	prog, err := eval.CompileBool(`request.host == "api.example.com" && pod.labels["app"] == "sleep"`)
	if err != nil {
		b.Fatalf("guard: compile: %v", err)
	}
	if ok, err := eval.EvalBool(prog, base.Activation()); err != nil || !ok {
		b.Fatalf("guard: base does not project the fixture request: (%v, %v)", ok, err)
	}
	auditOnly, err := eval.CompileBool(`result == "blocked"`)
	if err != nil {
		b.Fatalf("guard: compile: %v", err)
	}
	if _, err := eval.EvalBool(auditOnly, base.Activation()); err == nil {
		b.Fatal("guard: the base must not resolve the audit-only `result`")
	}
}

// guardFull fails the benchmark unless the full activation resolves both the
// audit-only child variables and the base ones.
func guardFull(b *testing.B, s *Scope) {
	b.Helper()
	prog, err := eval.CompileBool(`result == "blocked" && request.host == "api.example.com"`)
	if err != nil {
		b.Fatalf("guard: compile: %v", err)
	}
	if ok, err := eval.EvalBool(prog, s.Activation()); err != nil || !ok {
		b.Fatalf("guard: full activation does not carry the layered fixture: (%v, %v)", ok, err)
	}
}
