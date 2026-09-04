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
package filter

import "testing"

func TestDispositionStrings(t *testing.T) {
	want := map[Disposition]string{
		DispositionPassthrough: "passthrough",
		DispositionMutated:     "mutated",
		DispositionBlocked:     "blocked",
		DispositionBypassed:    "bypassed",
		DispositionError:       "error",
	}
	for d, s := range want {
		if d.String() != s {
			t.Errorf("%d.String() = %q, want %q", d, d.String(), s)
		}
	}
}

func TestRecordUnitActionGroupsByUnit(t *testing.T) {
	info := NewStreamInfo()
	id := UnitID{Scope: "ns/p", Name: "r"}
	info.RecordUnitAction(id, "block", ActionBlock)
	// A kind outside the vocabulary, explicitly converted: grouping is the
	// subject here, and the recorder is not the vocabulary's gatekeeper.
	info.RecordUnitAction(id, "audit", UnitActionKind("observed"))
	other := UnitID{Scope: "ns/p", Name: "r2", Ordinal: 1}
	info.RecordUnitAction(other, "tt", ActionMutate)

	if len(info.Matched) != 2 {
		t.Fatalf("Matched = %d records, want 2", len(info.Matched))
	}
	want := UnitAction{Filter: "block", Kind: ActionBlock}
	if len(info.Matched[0].FilterActions) != 2 || info.Matched[0].FilterActions[0] != want {
		t.Errorf("first unit actions = %v", info.Matched[0].FilterActions)
	}
}
