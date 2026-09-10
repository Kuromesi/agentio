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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

func TestCompilerModeOutputs(t *testing.T) {
	for _, sandboxMode := range []bool{false, true} {
		name := "workload"
		if sandboxMode {
			name = "sandbox"
		}
		t.Run(name, func(t *testing.T) {
			stop := make(chan struct{})
			t.Cleanup(func() { close(stop) })
			opts := []krt.CollectionOption{krt.WithStop(stop)}
			inputs := validCompilerInputs(stop)
			inputs.SandboxMode = sandboxMode
			worker := testWorkload("demo", "client", "10.0.0.1")
			inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{worker}, opts...)
			inputs.Sandboxes = krt.NewStaticCollection(nil, []model.Sandbox{{UID: "actor", Namespace: "demo", Labels: worker.Labels, State: model.SandboxStateRunning, Attester: &model.Attester{WorkloadUID: worker.UID}}}, opts...)
			selector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}
			inputs.TrafficPolicies = krt.NewStaticCollection(nil, []model.TrafficPolicy{{Name: "allow", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
				Selector: selector, Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "203.0.113.0/24"}}}}},
			}}}, opts...)
			inputs.SecurityProfiles = krt.NewStaticCollection(nil, []model.SecurityProfile{
				{Name: "shared", Namespace: "demo", Spec: agentsv1alpha1.SecurityProfileSpec{Selector: selector, Rules: []agentsv1alpha1.SecurityRule{{Name: "api", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}}}}}},
				{Name: "actor-only", Namespace: "demo", SandboxUID: "actor", Spec: agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{Name: "secret", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"actor.example.com"}}}}}}},
			}, opts...)
			config := krt.NewStaticCollection(nil, []model.AgentioConfiguration{{Value: &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{{Policy: extensionsv1.EgressPolicyAction_PASSTHROUGH}}}}}, opts...)
			inputs.AgentioConfig = config
			compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
			if err != nil {
				t.Fatal(err)
			}
			snapshot := compileSynced(t, compiler)
			resource, ok := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
			if !ok {
				t.Fatal("Workload missing")
			}
			address := new(workloadv1.Address)
			if err := resource.Value.UnmarshalTo(address); err != nil {
				t.Fatal(err)
			}
			wire := address.GetWorkload()
			if !reflect.DeepEqual(wire.AuthorizationPolicies, []string{"demo/allow-egress"}) || len(snapshot.List(model.WorkloadAuthorizationType)) != 1 {
				t.Fatalf("legacy Authorization output = %v", wire.AuthorizationPolicies)
			}
			if !reflect.DeepEqual(extensionNames(wire.Extensions), []string{"workload-metadata", "egress-policies", "sni-traffic-policy"}) {
				t.Fatalf("ordinary extensions = %v", extensionNames(wire.Extensions))
			}
			sni := new(extensionsv1.SniTrafficPolicy)
			if err := wire.Extensions[2].Config.UnmarshalTo(sni); err != nil {
				t.Fatal(err)
			}
			if len(sni.Rules) != 1 || !reflect.DeepEqual(sni.Rules[0].Match.Sni, []string{"api.example.com"}) {
				t.Fatalf("ordinary SNI = %v", sni)
			}
			binding := compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetWorkload, worker.UID))
			if binding == nil || !reflect.DeepEqual(binding.PolicyNames(policy.PolicyKindAuthorization), []string{"demo/allow-egress"}) {
				t.Fatalf("Workload authorization binding = %+v", binding)
			}
			if sandboxMode {
				manifest := manifestAt(t, compiler, "actor")
				if manifest == nil || manifest.State != sandboxv1.SandboxState_SANDBOX_STATE_RUNNING || manifest.GetAttester().GetWorkloadUid() != worker.UID || len(manifest.TrafficPolicies) != 1 || len(manifest.Extensions) != 2 || len(manifest.GetEgressRouting().GetRoutes()) != 1 {
					t.Fatalf("Sandbox output = %v", manifest)
				}
				binding := compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetSandbox, "actor"))
				if binding == nil || !reflect.DeepEqual(binding.PolicyNames(policy.PolicyKindAuthorization), []string{"trafficpolicy/demo/allow"}) {
					t.Fatalf("Sandbox authorization binding = %+v", binding)
				}
			} else {
				if len(snapshot.List(model.SandboxType)) != 0 {
					t.Fatal("ordinary mode published Sandbox state")
				}
				config.UpdateObject(model.AgentioConfiguration{ResourceVersion: "deny", Value: &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{{Policy: extensionsv1.EgressPolicyAction_DENY}}}})
				eventually(t, func() bool {
					r, ok := currentSnapshot(t, compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
					if !ok {
						return false
					}
					a := new(workloadv1.Address)
					if r.Value.UnmarshalTo(a) != nil {
						return false
					}
					for _, ext := range a.GetWorkload().Extensions {
						if ext.Name == "egress-policies" {
							egress := new(extensionsv1.EgressPolicies)
							return ext.Config.UnmarshalTo(egress) == nil && len(egress.EgressPolicies) == 1 && egress.EgressPolicies[0].Policy == extensionsv1.EgressPolicyAction_DENY
						}
					}
					return false
				}, "ordinary egress updates preserve legacy DENY")
			}
		})
	}
}

func TestSandboxAttesterMovePreservesWorkloads(t *testing.T) {
	fixture := newIncrementalFixture(t)
	a, b := testWorkload("demo", "a", "10.0.0.1"), testWorkload("demo", "b", "10.0.0.2")
	fixture.workloads.UpdateObject(a)
	fixture.workloads.UpdateObject(b)
	sandbox := model.Sandbox{UID: "actor", State: model.SandboxStateRunning, Attester: &model.Attester{WorkloadUID: a.UID}}
	fixture.sandboxes.UpdateObject(sandbox)
	eventually(t, func() bool {
		snapshot := currentSnapshot(t, fixture.compiler)
		_, hasA := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: a.UID})
		_, hasB := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: b.UID})
		return hasA && hasB && manifestAt(t, fixture.compiler, sandbox.UID) != nil
	}, "initial Workloads and Sandbox ready")
	baseline := currentSnapshot(t, fixture.compiler)
	check := func(uid string, wantState model.SandboxState) {
		t.Helper()
		eventually(t, func() bool {
			snapshot := currentSnapshot(t, fixture.compiler)
			for _, worker := range []model.Workload{a, b} {
				r, ok := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
				if !ok {
					return false
				}
				old, found := baseline.Get(r.Key)
				if !found || old.Hash != r.Hash {
					return false
				}
			}
			manifest := manifestAt(t, fixture.compiler, "actor")
			return manifest != nil && int32(manifest.State) == int32(wantState) && manifest.GetAttester().GetWorkloadUid() == uid
		}, "attester and lifecycle propagate independently of policies")
	}
	check(a.UID, model.SandboxStateRunning)
	sandbox.Attester = &model.Attester{WorkloadUID: b.UID}
	fixture.sandboxes.UpdateObject(sandbox)
	check(b.UID, model.SandboxStateRunning)
	sandbox.Attester = nil
	sandbox.State = model.SandboxStatePaused
	fixture.sandboxes.UpdateObject(sandbox)
	check("", model.SandboxStatePaused)
}

func TestCompilerSandboxManagedHostSkipsWorkloadPolicies(t *testing.T) {
	fixture := newIncrementalFixture(t)
	host := testWorkload("demo", "host", "10.0.0.1")
	host.SandboxManaged = true
	host.Labels = map[string]string{"app": "shared"}
	ordinary := testWorkload("demo", "ordinary", "10.0.0.2")
	ordinary.Labels = host.Labels
	fixture.workloads.UpdateObject(host)
	fixture.workloads.UpdateObject(ordinary)
	selector := metav1.LabelSelector{MatchLabels: host.Labels}
	fixture.trafficPolicies.UpdateObject(model.TrafficPolicy{Name: "allow", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
		Selector: selector, Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "203.0.113.0/24"}}}}},
	}})
	fixture.securityProfiles.UpdateObject(model.SecurityProfile{Name: "sni", Namespace: "demo", Spec: agentsv1alpha1.SecurityProfileSpec{
		Selector: selector, Rules: []agentsv1alpha1.SecurityRule{{Name: "api", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}}}}},
	})
	fixture.agentioConfig.UpdateObject(model.AgentioConfiguration{Value: &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{{Policy: extensionsv1.EgressPolicyAction_PASSTHROUGH}}}})
	checkWorkloads := func() {
		t.Helper()
		eventually(t, func() bool {
			snapshot := currentSnapshot(t, fixture.compiler)
			for _, workload := range []model.Workload{host, ordinary} {
				r, ok := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: workload.UID})
				if !ok || r.Facts.Workload.SandboxManaged != workload.SandboxManaged {
					return false
				}
				wire := new(workloadv1.Address)
				if r.Value.UnmarshalTo(wire) != nil {
					return false
				}
				binding := fixture.compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetWorkload, workload.UID))
				if workload.SandboxManaged {
					if binding != nil || len(wire.GetWorkload().AuthorizationPolicies) != 0 || !reflect.DeepEqual(extensionNames(wire.GetWorkload().Extensions), []string{"workload-metadata"}) {
						return false
					}
				} else if binding == nil || len(wire.GetWorkload().AuthorizationPolicies) != 1 || !reflect.DeepEqual(extensionNames(wire.GetWorkload().Extensions), []string{"workload-metadata", "egress-policies", "sni-traffic-policy"}) {
					return false
				}
			}
			return true
		}, "host and ordinary Workload policy ownership")
	}
	checkWorkloads() // Classification already applies before Sandbox discovery.
	fixture.sandboxes.UpdateObject(model.Sandbox{UID: "actor", Namespace: "demo", Labels: host.Labels, Attester: &model.Attester{WorkloadUID: host.UID}})
	eventually(t, func() bool {
		manifest := manifestAt(t, fixture.compiler, "actor")
		return manifest != nil && len(manifest.TrafficPolicies) == 1 && len(manifest.Extensions) == 1 && len(manifest.GetEgressRouting().GetRoutes()) == 1
	}, "Sandbox owns the complete policy set")
	checkWorkloads()
	fixture.sandboxes.DeleteObject("actor")
	eventually(t, func() bool { return manifestAt(t, fixture.compiler, "actor") == nil }, "Sandbox removed")
	checkWorkloads() // Deletion must not re-enable Workload policy fallback.
}
