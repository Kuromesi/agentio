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

package compiler

import (
	"reflect"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestSandboxManifestScopesBaselinesAndOrdersEgress(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "actor", Namespace: "tenant"})
	worker := testWorkload("workers", "worker", "10.1.0.1")
	sandbox := *fixture.sandboxes.GetKey("actor")
	sandbox.Attester = &model.Attester{WorkloadUID: worker.UID}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	fixture.workloads.ConditionalUpdateObject(worker)
	for _, namespace := range []string{"tenant", "workers"} {
		fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{Name: "baseline", Namespace: namespace,
			Spec: agentsv1alpha1.TrafficPolicySpec{Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}}}},
			}},
		})
	}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "egress", Value: &configv1.AgentioConfig{
		EgressPolicies: []*extensionsv1.EgressPolicy{
			{Namespaces: []string{"tenant"}, MatchCidrs: []string{"203.0.113.1/32"}, Policy: extensionsv1.EgressPolicyAction_PASSTHROUGH},
			{Namespaces: []string{"workers"}, MatchCidrs: []string{"203.0.113.2/32"}, Policy: extensionsv1.EgressPolicyAction_PASSTHROUGH},
			{Namespaces: []string{"tenant"}, MatchCidrs: []string{"203.0.113.3/32"}, Policy: extensionsv1.EgressPolicyAction_PASSTHROUGH},
		},
	}})
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		m := manifestAt(t, fixture.compiler, "actor")
		return m != nil && len(m.TrafficPolicies) == 1 && len(m.GetEgressRouting().GetRoutes()) == 2
	}, "Sandbox-scoped baseline and egress manifest")
	manifest := manifestAt(t, fixture.compiler, "actor")
	var names []string
	snapshot := currentSnapshot(t, fixture.compiler)
	for _, policy := range manifest.TrafficPolicies {
		names = append(names, policy.Name)
	}
	want := []string{"trafficpolicy/tenant/baseline"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("policies %v, want %v", names, want)
	}
	if len(snapshot.List(model.WorkloadAuthorizationType)) != 2 || len(snapshot.List(model.SniTrafficPolicyType)) != 0 {
		t.Fatal("Workload baselines must coexist with embedded Sandbox policies")
	}
	var cidrs []string
	for _, rule := range manifest.EgressRouting.Routes {
		cidrs = append(cidrs, rule.MatchCidrs...)
	}
	if !reflect.DeepEqual(cidrs, []string{"203.0.113.1/32", "203.0.113.3/32"}) {
		t.Fatalf("embedded egress order/scope: %v", cidrs)
	}
	if len(snapshot.List("type.googleapis.com/kruise.networking.extensions.v1.EgressPolicy")) != 0 {
		t.Fatal("standalone EgressPolicy resources must not be published")
	}
}

func TestSandboxExplicitEgressOrderStaysInManifest(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "actor", Namespace: "tenant", PolicyRefs: []model.PolicyRef{
		{Kind: model.PolicyKindEgressPolicy, Name: "agentio-config/egress/000001"},
		{Kind: model.PolicyKindEgressPolicy, Name: "agentio-config/egress/000000"},
	}})
	worker := testWorkload("workers", "worker", "10.1.0.1")
	sandbox := *fixture.sandboxes.GetKey("actor")
	sandbox.Attester = &model.Attester{WorkloadUID: worker.UID}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	fixture.workloads.ConditionalUpdateObject(worker)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "ordered", Value: &configv1.AgentioConfig{
		EgressPolicies: []*extensionsv1.EgressPolicy{
			{MatchCidrs: []string{"203.0.113.1/32"}, Policy: extensionsv1.EgressPolicyAction_PASSTHROUGH},
			{MatchCidrs: []string{"203.0.113.2/32"}, Policy: extensionsv1.EgressPolicyAction_PASSTHROUGH},
		},
	}})
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		m := manifestAt(t, fixture.compiler, "actor")
		return m != nil && len(m.TrafficPolicies) == 0 && len(m.GetEgressRouting().GetRoutes()) == 2
	}, "ordered egress references")
	eventually(t, func() bool {
		r, ok := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
		if !ok || r.Facts.Workload == nil {
			return false
		}
		address := new(workloadv1.Address)
		if err := r.Value.UnmarshalTo(address); err != nil {
			t.Fatal(err)
		}
		for _, extension := range address.GetWorkload().Extensions {
			if extension.Name != "egress-policies" {
				continue
			}
			payload := new(extensionsv1.EgressPolicies)
			if err := extension.Config.UnmarshalTo(payload); err != nil {
				t.Fatal(err)
			}
			return len(payload.EgressPolicies) == 2
		}
		return false
	}, "worker egress policies ready")
	manifest := manifestAt(t, fixture.compiler, "actor")
	if manifest.EgressRouting.Routes[0].MatchCidrs[0] != "203.0.113.2/32" {
		t.Fatal("embedded egress policies were reordered")
	}
	r, _ := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
	address := new(workloadv1.Address)
	if err := r.Value.UnmarshalTo(address); err != nil {
		t.Fatal(err)
	}
	if len(address.GetWorkload().AuthorizationPolicies) != 0 {
		t.Fatal("Workload must not carry authorization references")
	}
	found := false
	for _, extension := range address.GetWorkload().Extensions {
		if extension.Name == "egress-policies" {
			found = true
			payload := new(extensionsv1.EgressPolicies)
			if err := extension.Config.UnmarshalTo(payload); err != nil {
				t.Fatal(err)
			}
			if len(payload.EgressPolicies) != 2 || payload.EgressPolicies[0].MatchCidrs[0] != "203.0.113.1/32" || payload.EgressPolicies[1].MatchCidrs[0] != "203.0.113.2/32" {
				t.Fatalf("Workload must retain its own egress order: %v", payload)
			}
		}
	}
	if !found {
		t.Fatal("Workload egress policies missing")
	}
}
