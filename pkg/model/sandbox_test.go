// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import "testing"

func TestSandboxContainsUIDAndNamespace(t *testing.T) {
	sandbox := Sandbox{UID: "sandbox-a", Namespace: "demo"}
	if got := sandbox.ResourceName(); got != "sandbox-a" {
		t.Fatalf("resource name = %q", got)
	}
	if !sandbox.Equals(Sandbox{UID: "sandbox-a", Namespace: "demo"}) {
		t.Fatal("equal identity and namespace must compare equal")
	}
	changed := sandbox
	changed.Namespace = "other"
	if sandbox.Equals(changed) {
		t.Fatal("namespace change must change Sandbox equality")
	}
}

func TestSandboxAttesterValidation(t *testing.T) {
	for _, sandbox := range []Sandbox{{}, {UID: " "}, {UID: "a", Attester: &Attester{}}} {
		if sandbox.Validate() == nil {
			t.Fatalf("invalid Sandbox accepted: %+v", sandbox)
		}
	}
	if err := (Sandbox{UID: "a"}).Validate(); err != nil {
		t.Fatal(err)
	}
}
