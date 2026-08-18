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
package accesslog

import (
	"context"
	"testing"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

type captureLogger struct{ fn func(Entry) }

func (c *captureLogger) Submit(e Entry) { c.fn(e) }

// Actions must name what the filter did, not merely that it acted. Under the
// derived outcome an explicit bypass is no longer visible in Outcome — a
// bypass after a mutation reports "mutated", and a matched-but-inert stream
// reports "bypassed" without any bypass having fired — so the kind here is the
// only place an exemption is recorded.
func TestStreamLog_ActionsCarryTheKind(t *testing.T) {
	var got Entry
	l := &captureLogger{fn: func(e Entry) { got = e }}
	s := NewStreamLog(l)

	// UnitID is {Scope, Name, Ordinal} where Scope is "<ns>/<profile>"
	// (engine/filter/rule.go:25-32); String() renders "<scope>/<name>#<ordinal>".
	unit := filter.UnitID{Scope: "ns/p", Name: "r", Ordinal: 0}
	info := filter.NewStreamInfo()
	info.RecordUnitAction(unit, "block", filter.ActionBlock)
	info.RecordUnitAction(unit, "authz", filter.ActionBypass)
	info.RecordUnitAction(unit, "tokentransform", filter.ActionMutate)

	s.Log(context.Background(), &filter.Stream{}, info)

	want := []string{
		"block:block:" + unit.String(),
		"authz:bypass:" + unit.String(),
		"tokentransform:mutate:" + unit.String(),
	}
	if len(got.Actions) != len(want) {
		t.Fatalf("Actions = %v, want %v", got.Actions, want)
	}
	for i := range want {
		if got.Actions[i] != want[i] {
			t.Errorf("Actions[%d] = %q, want %q", i, got.Actions[i], want[i])
		}
	}
}
