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

// conformance_test.go is the filter contract conformance suite: it iterates
// the PRODUCTION chain BuildFilters assembles and asserts, for every
// registered filter, the parts of the filter.Definition contract the
// framework relies on but cannot enforce at compile time. Registering a new
// filter automatically subjects it to the suite — the minimalPayloads table
// fails the build until the new filter declares its entry, which is the
// mechanism that keeps coverage complete without anyone remembering to add
// tests.
package wiring

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// minimalPayloads maps every registered filter to a minimal valid payload in
// the filter's own schema. An entry is the filter author's conscious
// statement of "this is the smallest thing my Parse accepts"; a missing
// entry fails the suite by name.
var minimalPayloads = map[string]string{
	"bypass":         `{}`,
	"block":          `{}`,
	"mcpacl":         `{"defaultAction":"deny"}`,
	"headermutation": `{"request":{"set":[{"name":"X-A","value":"v"}]}}`,
	"tokentransform": `{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"valueTemplate":"Bearer {{ .Token }}"}}`,
}

func TestFilterContractConformance(t *testing.T) {
	regs, err := BuildFilters(Deps{})
	if err != nil {
		t.Fatalf("BuildFilters: %v", err)
	}
	registered := make(map[string]struct{}, len(regs))

	for _, reg := range regs {
		registered[reg.Name] = struct{}{}
		t.Run(reg.Name, func(t *testing.T) {
			payload, ok := minimalPayloads[reg.Name]
			if !ok {
				t.Fatalf("filter %q has no entry in minimalPayloads; every registered filter "+
					"must declare its minimal valid payload so the conformance suite covers it", reg.Name)
			}

			// Malformed JSON must be rejected, never panic and never be
			// interpreted: a corrupted policy document is a malformed policy,
			// not an absent or permissive one.
			if _, err := reg.Parse(json.RawMessage(`{"broken`)); err == nil {
				t.Error("Parse accepted malformed JSON; a corrupted payload must fail closed")
			}

			// Parse must not mutate its input. Projections share the raw
			// payload bytes across rules; an in-place normalization would
			// corrupt a later parse of the same document.
			raw := []byte(payload)
			pristine := bytes.Clone(raw)
			cfg, err := reg.Parse(raw)
			if err != nil {
				t.Fatalf("Parse(minimal payload) = %v; fix the payload or the parser", err)
			}
			if !bytes.Equal(raw, pristine) {
				t.Error("Parse mutated its input payload bytes")
			}

			// Parse must be repeatable for the same document — the
			// chainFingerprint guard identifies a chain by filter names alone,
			// which is sound only while Parse is a pure function of its
			// payload (see chainFingerprint).
			if _, err := reg.Parse(json.RawMessage(payload)); err != nil {
				t.Errorf("second Parse of the same payload failed: %v", err)
			}

			// A nil config resolves fail-closed, whatever the filter's own
			// policy mapping does with real configs.
			if got := reg.OnError(nil); got != filter.FailClosed {
				t.Errorf("OnError(nil) = %v, want FailClosed", got)
			}

			// The construction path must work with a real parsed config and
			// a plain scope: New runs on the request hot path and may not
			// panic or return a nil filter.
			scope := inputs.NewScope(inputs.Request{}, inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil)
			f := reg.New(filter.ErasedRuleConfig{
				ID:    filter.UnitID{Scope: "default/conformance", Name: "rule"},
				Cfg:   cfg,
				Scope: scope,
			})
			if f == nil {
				t.Error("New returned a nil Filter")
			}

			// Declared phases are the dispatch contract.
			if reg.Phases == 0 {
				t.Error("registration declares no phases")
			}
			if sub := reg.Subscribes(cfg); sub&^reg.Phases != 0 {
				t.Errorf("Subscribes(cfg) = %08b requests phases outside the declared %08b", sub, reg.Phases)
			}
		})
	}

	// The reverse direction: a stale table entry means a filter was renamed
	// or removed without revisiting its conformance declaration.
	for name := range minimalPayloads {
		if _, ok := registered[name]; !ok {
			t.Errorf("minimalPayloads has entry %q but no such filter is registered", name)
		}
	}
}
