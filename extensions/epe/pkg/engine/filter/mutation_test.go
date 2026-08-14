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

// :path rewrites silently miss routing unless the route cache is cleared;
// the helper must force it so no filter can forget.
func TestSetPathSetsClearRouteCache(t *testing.T) {
	m := SetPath("/new")
	if !m.ClearRouteCache {
		t.Error("SetPath must set ClearRouteCache")
	}
	if len(m.HeaderOps) != 1 || m.HeaderOps[0].Kind != HeaderSet || m.HeaderOps[0].Name != ":path" || m.HeaderOps[0].Value != "/new" {
		t.Errorf("SetPath ops = %+v", m.HeaderOps)
	}
}

func TestHeaderHelpers(t *testing.T) {
	if op := SetHeader("a", "1").HeaderOps[0]; op != (HeaderOp{Kind: HeaderSet, Name: "a", Value: "1"}) {
		t.Errorf("SetHeader op = %+v", op)
	}
	if op := AddHeader("a", "2").HeaderOps[0]; op != (HeaderOp{Kind: HeaderAdd, Name: "a", Value: "2"}) {
		t.Errorf("AddHeader op = %+v", op)
	}
	if op := RemoveHeader("a").HeaderOps[0]; op != (HeaderOp{Kind: HeaderRemove, Name: "a"}) {
		t.Errorf("RemoveHeader op = %+v", op)
	}
	if SetHeader("a", "1").ClearRouteCache {
		t.Error("plain SetHeader must not clear the route cache")
	}
}

func TestMutationEqualComparesStatusValueAndPresence(t *testing.T) {
	statusOK := 200
	statusOKAgain := 200
	statusAccepted := 202

	if !((Mutation{StatusCode: &statusOK}).equal(Mutation{StatusCode: &statusOKAgain})) {
		t.Fatal("equal status values at different addresses must compare equal")
	}
	if (Mutation{StatusCode: &statusOK}).equal(Mutation{StatusCode: &statusAccepted}) {
		t.Fatal("different status values must not compare equal")
	}
	if (Mutation{StatusCode: &statusOK}).equal(Mutation{}) {
		t.Fatal("present and absent status values must not compare equal")
	}
}

func TestUnitIDString(t *testing.T) {
	id := UnitID{Scope: "ns/prof", Name: "rule", Ordinal: 2}
	if got := id.String(); got != "ns/prof/rule#2" {
		t.Errorf("UnitID.String() = %q, want %q", got, "ns/prof/rule#2")
	}
}
