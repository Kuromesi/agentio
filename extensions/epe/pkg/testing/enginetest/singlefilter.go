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

package enginetest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// SingleFilter configures a one-filter, one-rule wire harness: the given
// payload — in the filter's own schema, never a policy CRD's — is projected
// once, and every request resolves to exactly one unit carrying it. It is the
// standard shape of a filter-local engine scenario (see doc.go): everything
// between the scripted Envoy stream and the filter is real, and no policy API
// is involved.
type SingleFilter struct {
	// Definition is the filter under test, with whatever deps the scenario
	// injects (fake clientsets, in-process endpoints).
	Definition filter.Definition
	// Payload is the filter's own configuration document.
	Payload string

	// Profile and Rule name the unit's attribution and evaluation scope.
	// Zero values default to profile "profile" in namespace "default" and
	// rule "rule"; scenarios asserting on rendered identity set their own.
	Profile inputs.Profile
	Rule    inputs.Rule
	// Inputs is the profile-scoped inputs snapshot visible to CEL/templates.
	Inputs map[string]any
	// InputsError marks the inputs as unavailable, mirroring a profile whose
	// ConfigMap-backed inputs did not resolve; evaluations that read inputs
	// fail with it.
	InputsError string
}

// NewSingleFilter builds a Harness around cfg. The payload is projected once,
// up front — exactly as the collection boundary does in production — so a
// payload that does not parse fails the test here rather than as a puzzling
// wire error.
func NewSingleFilter(t testing.TB, cfg SingleFilter) *Harness {
	t.Helper()
	regs, err := filter.Build(cfg.Definition)
	if err != nil {
		t.Fatalf("enginetest: build registration: %v", err)
	}
	cfgs, errs := filter.Project(regs, map[string]json.RawMessage{
		regs[0].Name: json.RawMessage(cfg.Payload),
	})
	if errs[0] != nil {
		t.Fatalf("enginetest: project %s payload: %v", regs[0].Name, errs[0])
	}

	profile := cfg.Profile
	if profile == (inputs.Profile{}) {
		profile = inputs.Profile{Name: "profile", Namespace: "default"}
	}
	rule := cfg.Rule
	if rule == (inputs.Rule{}) {
		rule = inputs.Rule{Name: "rule"}
	}
	var scopeOpts []inputs.ScopeOption
	if cfg.InputsError != "" {
		scopeOpts = append(scopeOpts, inputs.WithInputsError(cfg.InputsError))
	}

	resolve := func(_ context.Context, pod inputs.Pod, req *httpreq.HTTPRequest) (engine.Resolution, error) {
		scope := inputs.NewScope(inputs.RequestFrom(*req), pod, profile, rule, cfg.Inputs, scopeOpts...)
		return engine.Resolution{Units: []engine.Unit{{
			ID:    filter.UnitID{Scope: profile.Namespace + "/" + profile.Name, Name: rule.Name},
			Scope: scope,
			Cfgs:  cfgs,
		}}}, nil
	}
	return New(t, Options{Resolve: resolve, Registrations: regs})
}
