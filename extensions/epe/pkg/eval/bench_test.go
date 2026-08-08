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
package eval

import (
	"testing"

	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

// benchSink defeats dead-code elimination.
var benchSink any

func benchRequest() inputs.Request {
	return inputs.RequestFrom(httpreq.HTTPRequest{
		Host:   "api.example.com",
		Port:   443,
		Path:   "/v1/chat/completions",
		Scheme: "https",
		Method: "POST",
	})
}

func benchActivation(extra map[string]any) map[string]any {
	return inputs.NewActivationWithInputs(
		benchRequest(),
		inputs.Pod{Namespace: "test-ns", Name: "sandbox-pod", Labels: map[string]string{"app": "sleep"}},
		inputs.Profile{Name: "profile"},
		inputs.Rule{Name: "rule"},
		extra,
		"blocked",
	)
}

// BenchmarkEvalBool measures one audit `when` evaluation against an already
// compiled program and an already built activation — the per-request cost a
// profile with audit conditions adds. Compilation happens once per profile
// (BenchmarkCompileBool) and activation construction is charged separately
// (BenchmarkActivation).
func BenchmarkEvalBool(b *testing.B) {
	cases := []struct {
		name string
		expr string
	}{
		// Empty expression: the "always fire" nil-program path.
		{"empty", ""},
		{"result-compare", `result == "blocked"`},
		{"labels-and-result", `pod.labels["app"] == "sleep" && result == "blocked"`},
		{"string-functions", `request.path.startsWith("/v1/") && request.host.endsWith(".example.com")`},
	}
	for _, tc := range cases {
		prog, err := CompileBool(tc.expr)
		if err != nil {
			b.Fatalf("%s: compile: %v", tc.name, err)
		}
		act := benchActivation(nil)
		defer inputs.ReleaseActivation(act)
		// Guard the fixture: every arm must actually evaluate to true, or
		// the numbers would describe an error path instead.
		if ok, err := EvalBool(prog, act); err != nil || !ok {
			b.Fatalf("%s: fixture does not evaluate to true: (%v, %v)", tc.name, ok, err)
		}
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ok, err := EvalBool(prog, act)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = ok
			}
		})
	}
}

// BenchmarkEvalValue measures one credentialProvider parameter evaluation:
// the CEL expression yields an arbitrary value that is then converted to its
// native Go representation.
func BenchmarkEvalValue(b *testing.B) {
	routing := map[string]any{
		"routing": map[string]any{"api.example.com": "tenant-a"},
	}
	cases := []struct {
		name   string
		expr   string
		inputs map[string]any
	}{
		{"string-field", `pod.namespace`, nil},
		{"inputs-lookup", `inputs["routing"][request.host]`, routing},
		{"list-literal", `[request.host, request.path]`, nil},
	}
	for _, tc := range cases {
		prog, err := CompileValue(tc.expr)
		if err != nil {
			b.Fatalf("%s: compile: %v", tc.name, err)
		}
		act := benchActivation(tc.inputs)
		defer inputs.ReleaseActivation(act)
		if v, err := EvalValue(prog, act); err != nil || v == nil {
			b.Fatalf("%s: fixture yields (%v, %v), want a value", tc.name, v, err)
		}
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				v, err := EvalValue(prog, act)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = v
			}
		})
	}
}

// BenchmarkActivation measures building and releasing one pooled activation —
// the fixed overhead every CEL evaluation pays on top of Eval itself.
func BenchmarkActivation(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		act := benchActivation(nil)
		inputs.ReleaseActivation(act)
	}
}

// BenchmarkCompileBool measures one full compile (parse, type-check,
// optimize). This runs per profile compilation, not per request; it exists to
// document why compiled programs are cached on the profile.
func BenchmarkCompileBool(b *testing.B) {
	const expr = `pod.labels["app"] == "sleep" && result == "blocked"`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		prog, err := CompileBool(expr)
		if err != nil {
			b.Fatal(err)
		}
		benchSink = prog
	}
}
