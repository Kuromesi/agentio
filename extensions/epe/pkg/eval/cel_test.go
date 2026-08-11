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
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

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

// valueActivation builds a pooled activation whose every slot carries tag, so
// a value that still points at pooled storage is visible as soon as another
// tag is projected into the same activation.
func valueActivation(tag string, in map[string]any) map[string]any {
	return inputs.NewActivationWithInputs(
		inputs.RequestFrom(httpreq.HTTPRequest{
			Host: "api.example.com", Port: 443, Path: "/v1", Scheme: "https", Method: "POST",
			Headers: map[string]string{"x-tenant": tag},
			Query:   map[string][]string{"q": {tag}},
		}),
		inputs.Pod{Name: "pod-" + tag, Namespace: "ns", IP: "10.0.0.1", Labels: map[string]string{"tenant": tag}},
		inputs.Profile{Name: tag, Namespace: "ns"},
		inputs.Rule{Name: "rule-" + tag},
		in,
		"allowed",
	)
}

func mustCompileValue(t *testing.T, expr string) cel.Program {
	t.Helper()
	prog, err := CompileValue(expr)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	return prog
}

// TestEvalValueResultIsJSONNative pins the contract the only caller depends
// on: renderParams marshals the result, so every container EvalValue returns
// must be a JSON-native shape. cel-go's ConvertToNative(any) yields
// map[any]any for a map result, which json.Marshal rejects outright.
func TestEvalValueResultIsJSONNative(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want any
	}{
		{"string", `pod.namespace`, "ns"},
		{"int", `request.port`, int64(443)},
		{"bool", `request.path.startsWith("/v1")`, true},
		{"double", `1.5`, 1.5},
		{"list", `[request.host, request.path]`, []any{"api.example.com", "/v1"}},
		{"string-keyed map slot", `request.headers`, map[string]any{"x-tenant": "a"}},
		{"pod labels", `pod.labels`, map[string]any{"tenant": "a"}},
		{"whole string map slot", `profile`, map[string]any{"name": "a", "namespace": "ns"}},
		{"map literal", `{"tenant": pod.labels["tenant"]}`, map[string]any{"tenant": "a"}},
		{"map nested in list", `[request.headers]`, []any{map[string]any{"x-tenant": "a"}}},
		{"map nested in map", `pod`, map[string]any{
			"name": "pod-a", "namespace": "ns", "ip": "10.0.0.1",
			"labels": map[string]any{"tenant": "a"},
		}},
		{"non-string map key", `{1: "one"}`, map[string]any{"1": "one"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			act := valueActivation("a", nil)
			defer inputs.ReleaseActivation(act)
			got, err := EvalValue(mustCompileValue(t, tt.expr), act)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EvalValue = %#v, want %#v", got, tt.want)
			}
			if _, err := json.Marshal(got); err != nil {
				t.Errorf("result is not JSON-marshalable: %v", err)
			}
		})
	}
}

// TestEvalValueResultIsOwned covers the lifecycle renderParamSource creates:
// the activation is released by defer while the caller still reads the value.
// A result that shares storage with the activation is overwritten by whichever
// request takes that activation next.
func TestEvalValueResultIsOwned(t *testing.T) {
	// A []any reachable through `inputs` is handed back by reference by
	// cel-go's assignability shortcut, so this aliases regardless of how
	// maps happen to convert in the current cel-go release.
	t.Run("value reached through inputs", func(t *testing.T) {
		src := []any{"one", map[string]any{"k": "v"}}
		act := valueActivation("a", map[string]any{"list": src})
		defer inputs.ReleaseActivation(act)
		got, err := EvalValue(mustCompileValue(t, `inputs["list"]`), act)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		before := fmt.Sprint(got)
		src[0] = "mutated"
		src[1].(map[string]any)["k"] = "mutated"
		if after := fmt.Sprint(got); after != before {
			t.Errorf("result tracks the source container: before=%s after=%s", before, after)
		}
	})

	for _, expr := range []string{
		`request.headers`, `request.queryParams`, `pod.labels`,
		`request`, `pod`, `profile`, `rule`, `[pod.labels]`,
	} {
		t.Run("pooled slot "+expr, func(t *testing.T) {
			act := valueActivation("a", nil)
			got, err := EvalValue(mustCompileValue(t, expr), act)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			// fmt renders maps in key order, so this is stable without
			// requiring the value to be JSON-marshalable yet.
			before := fmt.Sprint(got)
			inputs.ReleaseActivation(act)
			next := valueActivation("b", nil)
			defer inputs.ReleaseActivation(next)
			if after := fmt.Sprint(got); after != before {
				t.Errorf("result was overwritten by the next activation: before=%s after=%s", before, after)
			}
		})
	}
}

// TestOwnedNativeCoversPooledShapes is shape-driven rather than
// expression-driven: it walks every slot a pooled activation hands out and
// fails if ownedNative lets any of that storage escape into its result. Adding
// a pooled slot with a container type ownedNative does not copy fails here
// instead of silently reintroducing the aliasing.
func TestOwnedNativeCoversPooledShapes(t *testing.T) {
	act := valueActivation("a", nil)
	defer inputs.ReleaseActivation(act)
	for name, slot := range act {
		if name == "inputs" {
			// Caller-owned, not pooled; covered by TestEvalValueResultIsOwned.
			continue
		}
		t.Run(name, func(t *testing.T) {
			got, err := ownedNative(types.DefaultTypeAdapter.NativeToValue(slot))
			if err != nil {
				t.Fatalf("ownedNative(%T): %v", slot, err)
			}
			pooled := containerAddrs(slot)
			for addr := range containerAddrs(got) {
				if pooled[addr] {
					t.Fatalf("result shares a container with pooled slot %q (%T)", name, slot)
				}
			}
		})
	}
}

// containerAddrs records the identity of every map and slice reachable from v.
func containerAddrs(v any) map[uintptr]bool {
	out := map[uintptr]bool{}
	var walk func(any)
	walk = func(v any) {
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Map:
			if p := rv.Pointer(); p != 0 {
				out[p] = true
			}
			for _, k := range rv.MapKeys() {
				walk(rv.MapIndex(k).Interface())
			}
		case reflect.Slice:
			if p := rv.Pointer(); p != 0 {
				out[p] = true
			}
			for i := 0; i < rv.Len(); i++ {
				walk(rv.Index(i).Interface())
			}
		}
	}
	walk(v)
	return out
}
