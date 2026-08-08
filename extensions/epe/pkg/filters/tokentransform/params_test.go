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
package tokentransform

import (
	"net/url"
	"reflect"
	"strings"
	"testing"

	"k8s.io/utils/ptr"

	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

func TestRenderParamsValueAndTemplate(t *testing.T) {
	tmpl, err := eval.CompileTemplate("test", "pod-{{ .Pod.Name }}")
	if err != nil {
		t.Fatal(err)
	}
	params := map[string]ParamSource{
		"static":   {Value: ptr.To("v1")},
		"rendered": {Template: tmpl},
	}
	scope := &inputs.Scope{Pod: inputs.Pod{Name: "pod-a"}}
	got, err := renderParams(params, scope)
	if err != nil {
		t.Fatal(err)
	}
	if got["static"] != "v1" || got["rendered"] != "pod-pod-a" {
		t.Fatalf("renderParams = %v", got)
	}
}

// TestRenderParamsCel covers the CEL branch and the JSON normalization that
// turns a CEL list into a plain []any.
func TestRenderParamsCel(t *testing.T) {
	prog, err := eval.CompileValue(`[inputs["routing"][request.host], request.headers["x-scope"]]`)
	if err != nil {
		t.Fatal(err)
	}
	scope := &inputs.Scope{
		Request: inputs.RequestFrom(httpreq.HTTPRequest{Host: "example.com", Port: 443, Path: "/v1/resources", Scheme: "https", Method: "GET", Query: url.Values{}, Headers: map[string]string{"x-scope": "readonly"}}),
		Inputs:  map[string]any{"routing": map[string]string{"example.com": "kms-name"}},
	}
	got, err := renderParams(map[string]ParamSource{"computed": {Cel: prog}}, scope)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got["computed"], []any{"kms-name", "readonly"}) {
		t.Fatalf("renderParams = %#v, want normalized []any", got["computed"])
	}
}

// TestRenderParamsNullResult keeps the all-or-nothing guard: a parameter that
// evaluates to null aborts the whole provider call.
func TestRenderParamsNullResult(t *testing.T) {
	prog, err := eval.CompileValue(`null`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = renderParams(map[string]ParamSource{"nothing": {Cel: prog}}, &inputs.Scope{})
	if err == nil || !strings.Contains(err.Error(), "result is null") {
		t.Fatalf("err = %v, want result-is-null error", err)
	}
}

func TestRenderParamsUnsetSource(t *testing.T) {
	_, err := renderParams(map[string]ParamSource{"empty": {}}, &inputs.Scope{})
	if err == nil || !strings.Contains(err.Error(), "exactly one of value, cel or template") {
		t.Fatalf("err = %v, want exactly-one-source error", err)
	}
}

func TestRenderParamsNilScope(t *testing.T) {
	if _, err := renderParams(map[string]ParamSource{"a": {Value: ptr.To("x")}}, nil); err == nil {
		t.Fatal("nil scope with parameters must error")
	}
	if got, err := renderParams(nil, nil); err != nil || got != nil {
		t.Fatalf("empty params = %v, %v; want nil, nil", got, err)
	}
}
