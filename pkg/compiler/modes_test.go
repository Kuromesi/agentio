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
	"fmt"
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

func TestCompilerOptionalSandboxInputs(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, withSandbox := range []bool{false, true} {
			t.Run(fmt.Sprintf("native=%v/bound=%v", native, withSandbox), func(t *testing.T) {
				stop := make(chan struct{})
				t.Cleanup(func() { close(stop) })
				opts := []krt.CollectionOption{krt.WithStop(stop)}
				inputs := validCompilerInputs(stop)
				inputs.NativeSandboxPolicies = native
				worker := testWorkload("demo", "client", "10.0.0.1")
				inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{worker}, opts...)
				if withSandbox {
					inputs.Sandboxes = krt.NewStaticCollection(nil, []model.Sandbox{{UID: "actor", Namespace: "demo", Labels: worker.Labels, State: model.SandboxStateRunning, Attester: &model.Attester{WorkloadUID: worker.UID}}}, opts...)
				}
				selector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}
				inputs.TrafficPolicies = krt.NewStaticCollection(nil, []model.TrafficPolicy{{
					Name:      "allow",
					Namespace: "demo",
					Spec: agentsv1alpha1.TrafficPolicySpec{
						Selector: selector,
						Egress:   &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "203.0.113.0/24"}}}}},
					},
				}}, opts...)
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
				if len(snapshot.List(model.TrafficPolicyType)) != 1 {
					t.Fatal("shared TrafficPolicy resource missing")
				}
				wantExtensions := []string{"workload-metadata"}
				if withSandbox && !native {
					wantExtensions = append(wantExtensions, "egress-policies", "sni-traffic-policy")
					if len(wire.AuthorizationPolicies) != 2 || len(snapshot.List(model.WorkloadAuthorizationType)) != 2 {
						t.Fatalf("Sandbox compatibility Authorization output = %v", wire.AuthorizationPolicies)
					}
					sni := new(extensionsv1.SniTrafficPolicy)
					if !compatibilityExtension(t, wire, "sni-traffic-policy", sni) || len(sni.Rules) != 2 {
						t.Fatalf("Sandbox compatibility SNI output = %v", sni)
					}
				} else if len(wire.AuthorizationPolicies) != 0 || len(snapshot.List(model.WorkloadAuthorizationType)) != 0 {
					t.Fatalf("Workload without compatibility emitted policies: %v", wire.AuthorizationPolicies)
				}
				if !reflect.DeepEqual(extensionNames(wire.Extensions), wantExtensions) {
					t.Fatalf("Workload extensions = %v, want %v", extensionNames(wire.Extensions), wantExtensions)
				}
				if compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetWorkload, worker.UID)) != nil {
					t.Fatal("Workload independently matched policy attachments")
				}
				if withSandbox {
					manifest := manifestAt(t, compiler, "actor")
					if manifest == nil || manifest.State != sandboxv1.SandboxState_SANDBOX_STATE_RUNNING || manifest.GetAttester().GetWorkloadUid() != worker.UID || len(trafficPolicyRefs(manifest)) != 1 || len(manifest.Extensions) != 2 || len(manifest.GetEgressRouting().GetRoutes()) != 1 {
						t.Fatalf("Sandbox output = %v", manifest)
					}
					binding := compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetSandbox, "actor"))
					if binding == nil || !reflect.DeepEqual(binding.PolicyNames(policy.PolicyKindTrafficPolicy), []string{"namespaces/demo/trafficPolicies/allow"}) {
						t.Fatalf("Sandbox authorization binding = %+v", binding)
					}
				} else {
					if len(snapshot.List(model.SandboxType)) != 0 {
						t.Fatal("ordinary mode published Sandbox state")
					}
				}
			})
		}
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

func TestNativeWorkloadsNeverSelectPolicies(t *testing.T) {
	fixture := newIncrementalFixture(t)
	host := testWorkload("demo", "host", "10.0.0.1")
	host.Labels = map[string]string{"app": "shared"}
	ordinary := testWorkload("demo", "ordinary", "10.0.0.2")
	ordinary.Labels = host.Labels
	fixture.workloads.UpdateObject(host)
	fixture.workloads.UpdateObject(ordinary)
	selector := metav1.LabelSelector{MatchLabels: host.Labels}
	fixture.trafficPolicies.UpdateObject(model.TrafficPolicy{
		Name:      "allow",
		Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: selector,
			Egress:   &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "203.0.113.0/24"}}}}},
		},
	})
	fixture.securityProfiles.UpdateObject(model.SecurityProfile{
		Name:      "sni",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: selector,
			Rules:    []agentsv1alpha1.SecurityRule{{Name: "api", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}}}},
		},
	})
	fixture.agentioConfig.UpdateObject(model.AgentioConfiguration{Value: &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{{Policy: extensionsv1.EgressPolicyAction_PASSTHROUGH}}}})
	checkWorkloads := func() {
		t.Helper()
		eventually(t, func() bool {
			snapshot := currentSnapshot(t, fixture.compiler)
			for _, workload := range []model.Workload{host, ordinary} {
				r, ok := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: workload.UID})
				if !ok {
					return false
				}
				wire := new(workloadv1.Address)
				if r.Value.UnmarshalTo(wire) != nil {
					return false
				}
				binding := fixture.compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetWorkload, workload.UID))
				if binding != nil || len(wire.GetWorkload().AuthorizationPolicies) != 0 || !reflect.DeepEqual(extensionNames(wire.GetWorkload().Extensions), []string{"workload-metadata"}) {
					return false
				}
			}
			return true
		}, "host and ordinary Workload policy ownership")
	}
	checkWorkloads() // Endpoints do not select policies before Sandbox discovery.
	fixture.sandboxes.UpdateObject(model.Sandbox{UID: "actor", Namespace: "demo", Labels: host.Labels, Attester: &model.Attester{WorkloadUID: host.UID}})
	eventually(t, func() bool {
		manifest := manifestAt(t, fixture.compiler, "actor")
		return manifest != nil && len(trafficPolicyRefs(manifest)) == 1 && len(manifest.Extensions) == 1 && len(manifest.GetEgressRouting().GetRoutes()) == 1
	}, "Sandbox owns the complete policy set")
	checkWorkloads()
	fixture.sandboxes.DeleteObject("actor")
	eventually(t, func() bool { return manifestAt(t, fixture.compiler, "actor") == nil }, "Sandbox removed")
	checkWorkloads() // Deletion must not re-enable Workload policy fallback.
}

func TestSandboxOwnsOrderedTrafficPolicyReferences(t *testing.T) {
	fixture := newIncrementalFixture(t)
	worker := testWorkload("demo", "client", "10.0.0.1")
	fixture.workloads.UpdateObject(worker)
	fixture.sandboxes.UpdateObject(model.Sandbox{UID: "actor", Namespace: "demo", Labels: worker.Labels})
	for _, source := range []model.TrafficPolicy{
		{Name: "namespace", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 40}},
		{Name: "selector", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 20, Selector: metav1.LabelSelector{MatchLabels: worker.Labels}}},
		{Name: "global", Global: true, Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 10}},
		{Name: "root", Namespace: "agentio-system", Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 30}},
	} {
		source.Spec.Egress = &agentsv1alpha1.TrafficPolicyDirection{}
		fixture.trafficPolicies.UpdateObject(source)
	}
	want := []string{"trafficPolicies/global", "namespaces/demo/trafficPolicies/selector", "namespaces/agentio-system/trafficPolicies/root", "namespaces/demo/trafficPolicies/namespace"}
	eventually(t, func() bool {
		binding := fixture.compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetWorkload, worker.UID))
		manifest := manifestAt(t, fixture.compiler, "actor")
		return binding == nil && manifest != nil && reflect.DeepEqual(trafficPolicyRefs(manifest), want)
	}, "Sandbox owns ordered global, namespace and selector policies")
}
