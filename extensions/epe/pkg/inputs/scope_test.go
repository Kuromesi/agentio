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
package inputs_test

import (
	"bytes"
	"reflect"
	"testing"

	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

func TestScopeActivationParity(t *testing.T) {
	scope := &inputs.Scope{
		Request: inputs.RequestFrom(httpreq.HTTPRequest{Host: "api.example.com", Port: 443, Path: "/v1", Scheme: "https", Method: "GET", Query: map[string][]string{"q": {"1"}}, Headers: map[string]string{"x-id": "abc"}}),
		Pod:     inputs.Pod{Name: "p", Namespace: "ns", IP: "10.0.0.1", Labels: map[string]string{"app": "a"}},
		Profile: inputs.Profile{Name: "sp", Namespace: "ns"},
		Rule:    inputs.Rule{Name: "r"},
	}
	act, release := scope.Activation()
	defer release()

	tests := []struct {
		name    string
		celPath func() any
		tmpl    string
		want    string
	}{
		{
			name:    "host",
			celPath: func() any { return act["request"].(map[string]any)["host"] },
			tmpl:    "{{ .Request.Host }}",
			want:    "api.example.com",
		},
		{
			name:    "header lowercase lookup",
			celPath: func() any { return act["request"].(map[string]any)["headers"].(map[string]string)["x-id"] },
			tmpl:    `{{ .Request.Header "X-Id" }}`,
			want:    "abc",
		},
		{
			name:    "query param first value",
			celPath: func() any { return act["request"].(map[string]any)["queryParams"].(map[string]string)["q"] },
			tmpl:    `{{ .Request.QueryParam "q" }}`,
			want:    "1",
		},
		{
			name:    "pod label",
			celPath: func() any { return act["pod"].(map[string]any)["labels"].(map[string]string)["app"] },
			tmpl:    `{{ .Pod.Label "app" }}`,
			want:    "a",
		},
		{
			name:    "profile name",
			celPath: func() any { return act["profile"].(map[string]string)["name"] },
			tmpl:    "{{ .Profile.Name }}",
			want:    "sp",
		},
		{
			name:    "rule name",
			celPath: func() any { return act["rule"].(map[string]string)["name"] },
			tmpl:    "{{ .Rule.Name }}",
			want:    "r",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.celPath(); got != any(tt.want) {
				t.Errorf("CEL activation value: want %q, got %v", tt.want, got)
			}
			tp, err := eval.CompileTemplate("p", tt.tmpl)
			if err != nil {
				t.Fatalf("CompileTemplate(%q): %v", tt.tmpl, err)
			}
			var buf bytes.Buffer
			if err := tp.Execute(&buf, scope); err != nil {
				t.Fatalf("template Execute: %v", err)
			}
			if buf.String() != tt.want {
				t.Errorf("template output: want %q, got %q", tt.want, buf.String())
			}
		})
	}
}

func TestScopeActivationScalarKeys(t *testing.T) {
	scope := &inputs.Scope{
		Request: inputs.RequestFrom(httpreq.HTTPRequest{Host: "h", Port: 8080, Path: "/p", Scheme: "http", Method: "POST"}),
		Pod:     inputs.Pod{Name: "pn", Namespace: "pns", IP: "1.2.3.4"},
	}
	act, release := scope.Activation()
	defer release()

	reqMap := act["request"].(map[string]any)
	podMap := act["pod"].(map[string]any)

	tests := []struct {
		name string
		got  any
		want any
	}{
		{name: "request port is int64", got: reqMap["port"], want: int64(8080)},
		{name: "request path", got: reqMap["path"], want: "/p"},
		{name: "request method", got: reqMap["method"], want: "POST"},
		{name: "request scheme", got: reqMap["scheme"], want: "http"},
		{name: "pod name", got: podMap["name"], want: "pn"},
		{name: "pod namespace", got: podMap["namespace"], want: "pns"},
		{name: "pod ip", got: podMap["ip"], want: "1.2.3.4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("want %v (%T), got %v (%T)", tt.want, tt.want, tt.got, tt.got)
			}
		})
	}
}

func TestScopeActivationOmitsResultKey(t *testing.T) {
	tests := []struct {
		name  string
		scope *inputs.Scope
	}{
		{name: "empty scope", scope: &inputs.Scope{}},
		{
			name: "populated scope",
			scope: &inputs.Scope{
				Request: inputs.RequestFrom(httpreq.HTTPRequest{Host: "h", Port: 80, Path: "/", Scheme: "http", Method: "GET"}),
				Rule:    inputs.Rule{Name: "r"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			act, release := tt.scope.Activation()
			defer release()
			if _, ok := act["result"]; ok {
				t.Errorf("Scope.Activation must not expose the audit-only result variable")
			}
		})
	}
}

func TestScopeNeverExposesSecrets(t *testing.T) {
	// Structural guarantee: Scope has no SandboxToken / RequestBody field.
	st := reflect.TypeOf(inputs.Scope{})
	for i := 0; i < st.NumField(); i++ {
		name := st.Field(i).Name
		if name == "SandboxToken" || name == "RequestBody" {
			t.Errorf("Scope must not carry secret field %q", name)
		}
	}
	act, release := (&inputs.Scope{}).Activation()
	defer release()
	for _, banned := range []string{"sandboxToken", "requestBody", "token"} {
		if _, ok := act[banned]; ok {
			t.Errorf("activation must not expose %q", banned)
		}
	}
}

func TestActivationPoolReuse(t *testing.T) {
	tests := []struct {
		name  string
		first *inputs.Scope
		next  *inputs.Scope
	}{
		{
			name: "stale entries cleared across reuse",
			first: &inputs.Scope{
				Request: inputs.RequestFrom(httpreq.HTTPRequest{Host: "h1", Port: 80, Path: "/", Scheme: "http", Method: "GET", Query: map[string][]string{"stale": {"v"}}, Headers: map[string]string{"x-stale": "v"}}),
				Pod:     inputs.Pod{Labels: map[string]string{"stale": "v"}},
			},
			next: &inputs.Scope{
				Request: inputs.RequestFrom(httpreq.HTTPRequest{Host: "h2", Port: 80, Path: "/", Scheme: "http", Method: "GET"}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			act1, release1 := tt.first.Activation()
			_ = act1
			release1()

			act2, release2 := tt.next.Activation()
			defer release2()
			reqMap := act2["request"].(map[string]any)
			if headers := reqMap["headers"].(map[string]string); len(headers) != 0 {
				t.Errorf("stale headers survived pool reuse: %v", headers)
			}
			if qp := reqMap["queryParams"].(map[string]string); len(qp) != 0 {
				t.Errorf("stale queryParams survived pool reuse: %v", qp)
			}
			if labels := act2["pod"].(map[string]any)["labels"].(map[string]string); len(labels) != 0 {
				t.Errorf("stale pod labels survived pool reuse: %v", labels)
			}
			if reqMap["host"] != "h2" {
				t.Errorf("request.host: want h2, got %v", reqMap["host"])
			}
		})
	}
}
