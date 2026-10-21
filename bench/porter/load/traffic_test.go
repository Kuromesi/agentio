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

package main

import (
	"slices"
	"testing"

	security "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestTrafficInventory(t *testing.T) {
	oldPolicies, oldRules, oldSharing := trafficPolicies, trafficRules, policySharing
	t.Cleanup(func() { trafficPolicies, trafficRules, policySharing = oldPolicies, oldRules, oldSharing })
	trafficPolicies, trafficRules, policySharing = 2, 3, 2
	if !slices.Equal(trafficReferences(0), trafficReferences(1)) ||
		slices.Equal(trafficReferences(1), trafficReferences(2)) {
		t.Fatal("policy sets must be shared only within a group")
	}
	inventory := resources(3)
	policies := map[string]*security.TrafficPolicy{}
	for _, r := range inventory {
		if r.Key.TypeURL != model.TrafficPolicyType {
			continue
		}
		p := &security.TrafficPolicy{}
		if err := r.Value.UnmarshalTo(p); err != nil {
			t.Fatal(err)
		}
		policies[r.Key.Name] = p
	}
	if len(policies) != 4 {
		t.Fatalf("policies=%d, want 4", len(policies))
	}
	for i := range 3 {
		for j, name := range trafficReferences(i) {
			p := policies[name]
			if p == nil || len(p.Egress.Rules) != 3 {
				t.Fatalf("missing or malformed policy %s", name)
			}
			for k, rule := range p.Egress.Rules {
				if got, want := rule.Match.Ports[0].GetPort() == 443, j == 1 && k == 2; got != want {
					t.Fatal("only the last rule of the final policy may match the CONNECT target")
				}
			}
		}
	}
}
