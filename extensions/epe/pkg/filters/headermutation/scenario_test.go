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
package headermutation_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"istio.io/istio/extensions/epe/pkg/engine"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/filters/headermutation"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

// This scenario exercises the policy-neutral boundary a future SecurityProfile
// field will use: payload projection, filter construction, engine invocation,
// and folding all run without importing a policy API.
func TestProjectedPayloadRunsThroughEngine(t *testing.T) {
	regs, err := filter.Build(headermutation.Definition())
	if err != nil {
		t.Fatalf("build registration: %v", err)
	}
	cfgs, errs := filter.Project(regs, map[string]json.RawMessage{
		headermutation.FilterName: json.RawMessage(`{
			"set":[{"name":"X-Policy","value":"{{ .Profile.Name }}"}],
			"add":[{"name":"X-Tag","value":"{{ index .Inputs \"tag\" }}"}],
			"remove":["X-Legacy"]
		}`),
	})
	if errs[0] != nil {
		t.Fatalf("project payload: %v", errs[0])
	}
	scope := inputs.NewScope(
		inputs.Request{}, inputs.Pod{}, inputs.Profile{Name: "outbound"}, inputs.Rule{Name: "mutate"},
		map[string]any{"tag": "trusted"},
	)
	res, err := engine.NewEngine(regs, 0).EvalRequestHeaders(
		context.Background(),
		&filter.Stream{Info: filter.NewStreamInfo()},
		[]engine.Unit{{ID: filter.UnitID{Scope: "default/profile", Name: "mutate"}, Scope: scope, Cfgs: cfgs}},
	)
	if err != nil {
		t.Fatalf("evaluate request headers: %v", err)
	}
	want := []filter.HeaderOp{
		{Kind: filter.HeaderSet, Name: "x-policy", Value: "outbound"},
		{Kind: filter.HeaderAppend, Name: "x-tag", Value: "trusted"},
		{Kind: filter.HeaderRemove, Name: "x-legacy"},
	}
	if !reflect.DeepEqual(res.HeaderOps, want) {
		t.Errorf("HeaderOps = %+v, want %+v", res.HeaderOps, want)
	}
	if res.Disposition != engine.DispositionMutated {
		t.Errorf("Disposition = %v, want mutated", res.Disposition)
	}
}
