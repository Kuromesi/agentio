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

func TestSandboxContainsUIDLabelsAndPolicyReferences(t *testing.T) {
	sandbox := Sandbox{
		UID:       "sandbox-a",
		Namespace: "demo",
		Labels:    map[string]string{"app": "client"},
		PolicyRefs: []PolicyRef{{
			Kind: PolicyKindSNIPolicy,
			Name: "demo/security",
		}},
	}
	if got := sandbox.ResourceName(); got != "sandbox-a" {
		t.Fatalf("resource name = %q, want sandbox-a", got)
	}
	if !sandbox.Equals(Sandbox{
		UID:       "sandbox-a",
		Namespace: "demo",
		Labels:    map[string]string{"app": "client"},
		PolicyRefs: []PolicyRef{{
			Kind: PolicyKindSNIPolicy,
			Name: "demo/security",
		}},
	}) {
		t.Fatal("equal identity, namespace, labels, and policy references must compare equal")
	}
	changed := sandbox
	changed.Namespace = "other"
	if sandbox.Equals(changed) {
		t.Fatal("namespace change must change Sandbox equality")
	}
	changed = sandbox
	changed.Labels = map[string]string{"app": "other"}
	if sandbox.Equals(changed) {
		t.Fatal("label change must change Sandbox equality")
	}
	changed = sandbox
	changed.PolicyRefs = []PolicyRef{{
		Kind: PolicyKindSNIPolicy,
		Name: "demo/other",
	}}
	if sandbox.Equals(changed) {
		t.Fatal("policy reference change must change Sandbox equality")
	}
}

func TestSandboxValidationRejectsInvalidPolicyReferences(t *testing.T) {
	valid := Sandbox{
		UID: "sandbox-a",
		PolicyRefs: []PolicyRef{{
			Kind: PolicyKindSNIPolicy,
			Name: "demo/security",
		}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid Sandbox rejected: %v", err)
	}

	for _, sandbox := range []Sandbox{
		{},
		{
			UID: "sandbox-a",
			PolicyRefs: []PolicyRef{{
				Name: "demo/security",
			}},
		},
		{
			UID: "sandbox-a",
			PolicyRefs: []PolicyRef{{
				Kind: PolicyKindSNIPolicy,
			}},
		},
		{
			UID: "sandbox-a",
			PolicyRefs: []PolicyRef{
				{
					Kind: PolicyKindSNIPolicy,
					Name: "demo/security",
				},
				{
					Kind: PolicyKindSNIPolicy,
					Name: "demo/security",
				},
			},
		},
	} {
		if err := sandbox.Validate(); err == nil {
			t.Fatalf("invalid Sandbox accepted: %+v", sandbox)
		}
	}
}
