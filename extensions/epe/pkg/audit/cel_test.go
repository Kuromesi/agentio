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

	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

func TestEvalWhen_NilProgReturnsTrue(t *testing.T) {
	got, err := EvalWhen(nil, &Scope{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("nil program should return true")
	}
}

func TestEvalWhen_TrueExpression(t *testing.T) {
	prog, err := eval.CompileBool(`result == "blocked"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	s := &Scope{Result: "blocked"}
	got, err := EvalWhen(prog, s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected true for matching result")
	}
}

func TestEvalWhen_FalseExpression(t *testing.T) {
	prog, err := eval.CompileBool(`result == "blocked"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	s := &Scope{Result: "passthrough"}
	got, err := EvalWhen(prog, s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("expected false for non-matching result")
	}
}

func TestEvalWhen_RequestFieldAccess(t *testing.T) {
	tests := []struct {
		name  string
		expr  string
		scope Scope
		want  bool
	}{
		{
			name:  "request method matches",
			expr:  `request.method == "POST"`,
			scope: Scope{Scope: inputs.Scope{Request: inputs.RequestFrom(httpreq.HTTPRequest{Method: "POST"})}},
			want:  true,
		},
		{
			name:  "request host matches",
			expr:  `request.host == "example.com"`,
			scope: Scope{Scope: inputs.Scope{Request: inputs.RequestFrom(httpreq.HTTPRequest{Host: "example.com"})}},
			want:  true,
		},
		{
			name:  "request port matches",
			expr:  `request.port == 443`,
			scope: Scope{Scope: inputs.Scope{Request: inputs.RequestFrom(httpreq.HTTPRequest{Port: 443})}},
			want:  true,
		},
		{
			name:  "pod namespace matches",
			expr:  `pod.namespace == "production"`,
			scope: Scope{Scope: inputs.Scope{Pod: inputs.Pod{Namespace: "production"}}},
			want:  true,
		},
		{
			name:  "profile name matches",
			expr:  `profile.name == "strict"`,
			scope: Scope{Scope: inputs.Scope{Profile: inputs.Profile{Name: "strict"}}},
			want:  true,
		},
		{
			name:  "rule name matches",
			expr:  `rule.name == "deny-admin"`,
			scope: Scope{Scope: inputs.Scope{Rule: inputs.Rule{Name: "deny-admin"}}},
			want:  true,
		},
		{
			name: "complex expression with headers",
			expr: `result == "blocked" && request.headers["x-priority"] == "high"`,
			scope: Scope{
				Scope:  inputs.Scope{Request: inputs.RequestFrom(httpreq.HTTPRequest{Headers: map[string]string{"x-priority": "high"}})},
				Result: "blocked",
			},
			want: true,
		},
		{
			name:  "complex expression with labels",
			expr:  `pod.labels["team"] == "fraud"`,
			scope: Scope{Scope: inputs.Scope{Pod: inputs.Pod{Labels: map[string]string{"team": "fraud"}}}},
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog, err := eval.CompileBool(tt.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := EvalWhen(prog, &tt.scope)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if got != tt.want {
				t.Errorf("want %v, got %v", tt.want, got)
			}
		})
	}
}

func TestEvalWhen_QueryParams(t *testing.T) {
	prog, err := eval.CompileBool(`request.queryParams["tag"] == "urgent"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	s := &Scope{
		Scope: inputs.Scope{Request: inputs.RequestFrom(httpreq.HTTPRequest{Query: map[string][]string{"tag": {"urgent", "extra"}}})},
	}
	got, err := EvalWhen(prog, s)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !got {
		t.Error("expected true when query param matches")
	}
}

func TestEvalWhen_ProfileInputs(t *testing.T) {
	prog, err := eval.CompileBool(`inputs["routing"]["tenant-a"] == "provider-a"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	s := &Scope{Scope: inputs.Scope{Inputs: map[string]any{
		"routing": map[string]string{"tenant-a": "provider-a"},
	}}}
	got, err := EvalWhen(prog, s)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !got {
		t.Fatal("expected profile input to be visible to audit CEL")
	}
}
