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
	"strings"
	"testing"

	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

func TestCompileBool(t *testing.T) {
	tests := []struct {
		name        string
		expr        string
		wantNil     bool
		expectError string
	}{
		{"empty", "", true, ""},
		{"valid bool", `pod.namespace == "ns"`, false, ""},
		{"non-bool", `pod.namespace`, false, "must return bool"},
		{"syntax error", `pod.`, false, "compile when"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog, err := CompileBool(tt.expr)
			if tt.expectError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.expectError) {
					t.Fatalf("expected error containing %q, got %v", tt.expectError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil != (prog == nil) {
				t.Errorf("prog nil = %v, want %v", prog == nil, tt.wantNil)
			}
		})
	}
}

func TestEvalBool(t *testing.T) {
	if ok, err := EvalBool(nil, nil); err != nil || !ok {
		t.Fatalf("nil program should return true, got (%v, %v)", ok, err)
	}
	prog, err := CompileBool(`pod.labels["app"] == "sleep" && result == "blocked"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	act := inputs.NewActivation(
		inputs.RequestFrom(httpreq.HTTPRequest{Host: "h", Port: 80, Path: "/", Scheme: "http", Method: "GET"}),
		inputs.Pod{Namespace: "ns", Labels: map[string]string{"app": "sleep"}},
		inputs.Profile{Name: "p"}, inputs.Rule{Name: "r"}, "blocked")
	defer inputs.ReleaseActivation(act)
	ok, err := EvalBool(prog, act)
	if err != nil || !ok {
		t.Fatalf("expected true, got (%v, %v)", ok, err)
	}
}
