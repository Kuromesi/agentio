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
package wiring

import (
	"testing"

	"github.com/openkruise/agentio/pkg/kube"
)

// The action order inside one rule is a load-bearing, machine-checked
// contract. Rules themselves are evaluated in policy order by the engine.
func TestBuildFiltersOrderIsExplicit(t *testing.T) {
	regs, err := BuildFilters(Deps{Kube: kube.NewFakeClient(), Stop: t.Context().Done()})
	if err != nil {
		t.Fatalf("BuildFilters: %v", err)
	}
	want := []string{"bypass", "block", "mcpacl", "headermutation", "tokentransform"}
	if len(regs) != len(want) {
		t.Fatalf("got %d registrations, want %d", len(regs), len(want))
	}
	for i, reg := range regs {
		if reg.Name != want[i] {
			t.Errorf("position %d = %q, want %q", i, reg.Name, want[i])
		}
	}
}
