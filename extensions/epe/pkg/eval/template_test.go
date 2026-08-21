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

	"istio.io/istio/extensions/epe/pkg/inputs"
)

func TestCompileTemplateAndRender(t *testing.T) {
	tokenValueTemplate := `{{- $json := fromJson .Token -}}Bearer {{ if kindIs "map" $json }}{{ first (values $json) }}{{ else }}{{ .Token }}{{ end }}`
	tests := []struct {
		name        string
		raw         string
		data        any
		want        string
		expectError string // compile error substring
	}{
		{"literal", "sk-abc123", nil, "sk-abc123", ""},
		{"pod field", "{{ .Pod.Namespace }}", struct{ Pod inputs.Pod }{inputs.Pod{Namespace: "ns"}}, "ns", ""},
		{"label helper", "{{ .Pod.Label \"app\" }}", struct{ Pod inputs.Pod }{inputs.Pod{Labels: map[string]string{"app": "x"}}}, "x", ""},
		{"missingkey zero", "{{ .Pod.Labels.absent }}", struct{ Pod inputs.Pod }{inputs.Pod{Labels: map[string]string{}}}, "", ""},
		{"default helper", "{{ default \"fb\" .V }}", struct{ V string }{""}, "fb", ""},
		{"json helper", "{{ json .V }}", struct{ V []string }{[]string{"a"}}, `["a"]`, ""},
		{"fromJson map helper", "{{ range fromJson .V }}{{ . }}{{ end }}", struct{ V string }{`{"key":"value"}`}, "value", ""},
		{"kindIs helper", `{{ kindIs "map" (fromJson .V) }}`, struct{ V string }{`{"key":"value"}`}, "true", ""},
		{"trim helper", `{{ trim .V }}`, struct{ V string }{"  value\n"}, "value", ""},
		{"hasPrefix helper", `{{ hasPrefix "Bearer " .V }}`, struct{ V string }{"Bearer value"}, "true", ""},
		{"values and first helpers", `{{ first (values (fromJson .V)) }}`, struct{ V string }{`{"only":"value"}`}, "value", ""},
		{"token template with raw value", tokenValueTemplate, struct{ Token string }{"raw-token"}, "Bearer raw-token", ""},
		{"token template with JSON value", tokenValueTemplate, struct{ Token string }{`{"arbitrary-key":"json-token"}`}, "Bearer json-token", ""},
		{"syntax error", "{{ .Token", nil, "", "unclosed action"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl, err := CompileTemplate("t", tt.raw)
			if tt.expectError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.expectError) {
					t.Fatalf("expected error containing %q, got %v", tt.expectError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected compile error: %v", err)
			}
			got, err := RenderToString(tmpl, tt.data)
			if err != nil {
				t.Fatalf("unexpected render error: %v", err)
			}
			if got != tt.want {
				t.Errorf("render = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTemplateFailHelperReturnsRenderError(t *testing.T) {
	tmpl, err := CompileTemplate("t", `{{ fail "stop rendering" }}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = RenderToString(tmpl, nil)
	if err == nil || !strings.Contains(err.Error(), "stop rendering") {
		t.Fatalf("RenderToString() error = %v, want stop rendering", err)
	}
}
