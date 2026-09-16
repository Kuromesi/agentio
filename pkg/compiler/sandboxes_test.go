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
	"net/netip"
	"reflect"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

func manifestAt(t *testing.T, compiler *Compiler, uid string) *sandboxv1.Sandbox {
	t.Helper()
	r, ok := currentSnapshot(t, compiler).Get(model.ResourceKey{TypeURL: model.SandboxType, Name: uid})
	if !ok {
		return nil
	}
	value := new(sandboxv1.Sandbox)
	if err := r.Value.UnmarshalTo(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func trafficPolicyRefs(sandbox *sandboxv1.Sandbox) []string {
	return sandbox.GetPolicyRefs()[model.TrafficPolicyType].GetResourceNames()
}

func trafficPolicyAt(t *testing.T, compiler *Compiler, name string) *securityv1.TrafficPolicy {
	t.Helper()
	resource, ok := currentSnapshot(t, compiler).Get(model.ResourceKey{TypeURL: model.TrafficPolicyType, Name: name})
	if !ok {
		return nil
	}
	value := new(securityv1.TrafficPolicy)
	if err := resource.Value.UnmarshalTo(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSandboxSharedPoliciesWithoutWorkerAndBodyUpdate(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "a", Namespace: "tenant", Labels: map[string]string{"app": "a"}})
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "b", Namespace: "tenant", Labels: map[string]string{"app": "b"}})
	policy := model.TrafficPolicy{
		Name:      "allow",
		Namespace: "tenant",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
			Egress:   &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}}}}},
		},
	}
	fixture.trafficPolicies.ConditionalUpdateObject(policy)
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		a, b := manifestAt(t, fixture.compiler, "a"), manifestAt(t, fixture.compiler, "b")
		return a != nil && reflect.DeepEqual(trafficPolicyRefs(a), []string{"namespaces/tenant/trafficPolicies/allow"}) && a.TrafficPolicy == nil && b != nil && len(trafficPolicyRefs(b)) == 0 && trafficPolicyAt(t, fixture.compiler, "namespaces/tenant/trafficPolicies/allow") != nil
	}, "paused Sandbox manifests compiled independently")
	first := trafficPolicyAt(t, fixture.compiler, "namespaces/tenant/trafficPolicies/allow")
	// Sandbox and Authorization resources are published by separate collections.
	eventually(t, func() bool {
		return len(currentSnapshot(t, fixture.compiler).List(model.WorkloadAuthorizationType)) == 1
	}, "Workload Authorization published independently")
	worker := testWorkload("workers", "worker", "10.1.0.1")
	for _, uid := range []string{"a", "b"} {
		sandbox := *fixture.sandboxes.GetKey(uid)
		sandbox.Attester = &model.Attester{WorkloadUID: worker.UID}
		fixture.sandboxes.ConditionalUpdateObject(sandbox)
	}
	fixture.workloads.ConditionalUpdateObject(worker)
	eventually(t, func() bool {
		_, ok := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
		return ok
	}, "multi Sandbox workload")
	settle()
	before := currentSnapshot(t, fixture.compiler)
	policy.Spec.Egress = policy.Spec.Egress.DeepCopy()
	policy.Spec.Egress.Rules[0].To[0].CIDR = "10.2.0.0/24"
	fixture.trafficPolicies.ConditionalUpdateObject(policy)
	eventually(t, func() bool {
		current := trafficPolicyAt(t, fixture.compiler, "namespaces/tenant/trafficPolicies/allow")
		return current != nil && !proto.Equal(current, first)
	}, "independent policy tracks changed payload")
	settle()
	after := currentSnapshot(t, fixture.compiler)
	var names []string
	for _, change := range before.Diff(after) {
		names = append(names, change.Key.TypeURL+"|"+change.Key.Name)
	}
	want := []string{model.TrafficPolicyType + "|namespaces/tenant/trafficPolicies/allow", model.WorkloadAuthorizationType + "|tenant/allow-egress"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("changed resources %v, want %v", names, want)
	}
}

func TestMultiSandboxFailureDeletionAndShrinkRetainNetworking(t *testing.T) {
	fixture := newIncrementalFixture(t)
	a := model.Sandbox{UID: "actor-a", Namespace: "tenant"}
	b := model.Sandbox{UID: "actor-b", Namespace: "tenant", PolicyRefs: []model.PolicyRef{{Kind: model.PolicyKindSNIPolicy, Name: "missing"}}}
	fixture.sandboxes.ConditionalUpdateObject(a)
	fixture.sandboxes.ConditionalUpdateObject(b)
	worker := testWorkload("workers", "worker", "10.1.0.1")
	a.Attester = &model.Attester{WorkloadUID: worker.UID}
	b.Attester = &model.Attester{WorkloadUID: worker.UID}
	fixture.sandboxes.ConditionalUpdateObject(a)
	fixture.sandboxes.ConditionalUpdateObject(b)
	fixture.workloads.ConditionalUpdateObject(worker)
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		ma, mb := manifestAt(t, fixture.compiler, a.UID), manifestAt(t, fixture.compiler, b.UID)
		return ma != nil && mb == nil
	}, "isolate invalid actor")
	a.Attester = nil
	fixture.sandboxes.ConditionalUpdateObject(a)
	fixture.workloads.ConditionalUpdateObject(worker)
	eventually(t, func() bool {
		r, ok := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
		return ok && r.Facts.Workload != nil && manifestAt(t, fixture.compiler, b.UID) == nil
	}, "last invalid actor does not remove networking")
	fixture.sandboxes.DeleteObject(b.UID)
	eventually(t, func() bool { return manifestAt(t, fixture.compiler, b.UID) == nil }, "deleted actor must not become an implicit Pod Sandbox")
	settle()
	if manifestAt(t, fixture.compiler, b.UID) != nil {
		t.Fatal("deleted Sandbox reappeared")
	}
	if ma := manifestAt(t, fixture.compiler, a.UID); ma == nil {
		t.Fatal("unbound valid Sandbox must remain available for prefetch")
	}
}

func TestMalformedSandboxUIDDoesNotStopCompiler(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: " ", Namespace: "tenant"})
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "valid", Namespace: "tenant"})
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Sandbox/ "]
		valid := manifestAt(t, fixture.compiler, "valid")
		return failed && valid != nil
	}, "invalid UID is isolated from valid Sandboxes")
	fixture.sandboxes.DeleteObject(" ")
	eventually(t, func() bool { _, failed := fixture.compiler.Failures()["Sandbox/ "]; return !failed }, "removed malformed UID clears diagnostic")
}

func TestSandboxReferencePrioritySNIOrderAndUnavailableView(t *testing.T) {
	sniAt := func(manifest *sandboxv1.Sandbox, index int) *extensionsv1.SniTrafficPolicy {
		t.Helper()
		value := new(extensionsv1.SniTrafficPolicy)
		if err := manifest.Extensions[index].UnmarshalTo(value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{
		UID:       "a",
		Namespace: "tenant",
		PolicyRefs: []model.PolicyRef{
			{Kind: model.PolicyKindSNIPolicy, Name: "tenant/second"},
			{Kind: model.PolicyKindSNIPolicy, Name: "tenant/first"},
		},
	})
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "b", Namespace: "other"})
	global := model.TrafficPolicy{Name: "baseline", Global: true, Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 10, Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionReject, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}}}}}}}
	local := model.TrafficPolicy{Name: "local", Namespace: "tenant", Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 100, Ingress: &agentsv1alpha1.TrafficPolicyDirection{}, Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}}}}}}}
	fixture.trafficPolicies.ConditionalUpdateObject(global)
	fixture.trafficPolicies.ConditionalUpdateObject(local)
	profile := func(name, domain string) model.SecurityProfile {
		return model.SecurityProfile{
			Name:      name,
			Namespace: "tenant",
			Spec: agentsv1alpha1.SecurityProfileSpec{
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{"not": "selected"}},
				Rules:    []agentsv1alpha1.SecurityRule{{Name: "rule", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{domain}}}}},
			},
		}
	}
	first, second := profile("first", "first.example"), profile("second", "second.example")
	fixture.securityProfiles.ConditionalUpdateObject(first)
	fixture.securityProfiles.ConditionalUpdateObject(second)
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		a, b := manifestAt(t, fixture.compiler, "a"), manifestAt(t, fixture.compiler, "b")
		return a != nil && len(trafficPolicyRefs(a)) == 2 && len(a.Extensions) == 2 && b != nil && len(trafficPolicyRefs(b)) == 1
	}, "inline global/local policies and explicit SNI order")
	a := manifestAt(t, fixture.compiler, "a")
	if a.TrafficPolicy != nil || !reflect.DeepEqual(trafficPolicyRefs(a), []string{"trafficPolicies/baseline", "namespaces/tenant/trafficPolicies/local"}) {
		t.Fatalf("traffic reference order: %v", a)
	}
	eventually(t, func() bool {
		local := trafficPolicyAt(t, fixture.compiler, "namespaces/tenant/trafficPolicies/local")
		global := trafficPolicyAt(t, fixture.compiler, "trafficPolicies/baseline")
		return local != nil && local.Ingress == nil && global != nil && global.Ingress == nil
	}, "shared bodies omit unconfigured and empty source directions")
	if sniAt(a, 0).Rules[0].Match.Sni[0] != "second.example" || sniAt(a, 1).Rules[0].Match.Sni[0] != "first.example" {
		t.Fatal("SNI explicit order was not preserved")
	}
	local.Spec.Priority = 0
	fixture.trafficPolicies.ConditionalUpdateObject(local)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && len(trafficPolicyRefs(a)) == 2 &&
			reflect.DeepEqual(trafficPolicyRefs(a), []string{"namespaces/tenant/trafficPolicies/local", "trafficPolicies/baseline"})
	}, "lower numeric priority moves the local policy ahead of the global policy")
	local.Spec.Priority = global.Spec.Priority
	fixture.trafficPolicies.ConditionalUpdateObject(local)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && len(trafficPolicyRefs(a)) == 2 &&
			reflect.DeepEqual(trafficPolicyRefs(a), []string{"trafficPolicies/baseline", "namespaces/tenant/trafficPolicies/local"})
	}, "equal priorities and creation times use namespace/name ordering")
	second.Spec = *second.Spec.DeepCopy()
	second.Spec.Rules[0].Match[0].Domains = []string{"updated.example"}
	fixture.securityProfiles.ConditionalUpdateObject(second)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && len(a.Extensions) == 2 && sniAt(a, 0).Rules[0].Match.Sni[0] == "updated.example"
	}, "inline SNI body follows source change")
	fixture.securityProfiles.DeleteObject(second.ResourceName())
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a == nil
	}, "missing explicit policy withdraws the manifest")
	if b := manifestAt(t, fixture.compiler, "b"); b == nil {
		t.Fatal("unrelated Sandbox was invalidated")
	}
	fixture.securityProfiles.ConditionalUpdateObject(second)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && len(trafficPolicyRefs(a)) == 2 && len(a.Extensions) == 2
	}, "complete inline view recovers")
}

func TestCompilerUsesOnlyProvidedSandboxes(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workload := testWorkload("demo", "client", "10.1.0.2")
	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{workload}, options...)
	sandboxes := krt.NewStaticCollection[model.Sandbox](nil, nil, options...)
	inputs.Sandboxes = sandboxes
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	waitSynced(t, compiler)
	if manifestAt(t, compiler, workload.UID) != nil {
		t.Fatal("Workload synthesized a Sandbox inside the compiler")
	}
	sandboxes.UpdateObject(model.Sandbox{UID: workload.UID, Namespace: "sandbox-namespace", Labels: map[string]string{"source": "sandbox"}})
	eventually(t, func() bool { return manifestAt(t, compiler, workload.UID) != nil }, "provider Sandbox appears")
	sandboxes.DeleteObject(workload.UID)
	eventually(t, func() bool {
		return manifestAt(t, compiler, workload.UID) == nil && compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetSandbox, workload.UID)) == nil
	}, "Sandbox deletion removes resource and bindings despite surviving Workload")
	settle()
	if manifestAt(t, compiler, workload.UID) != nil {
		t.Fatal("surviving Workload resurrected a deleted Sandbox")
	}
}

func TestSandboxSelectorMetadataUpdateRecomputesBindings(t *testing.T) {
	fixture := newIncrementalFixture(t)
	workload := testWorkload("workload-namespace", "client", "10.1.0.1")
	sandbox := model.Sandbox{
		UID:       workload.UID,
		Namespace: "sandbox-namespace",
		Labels:    map[string]string{"app": "sandbox"},
	}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	fixture.workloads.ConditionalUpdateObject(workload)
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name:      "allow",
		Namespace: sandbox.Namespace,
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "sandbox"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	})
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		binding := fixture.compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetSandbox, sandbox.UID))
		return binding != nil && reflect.DeepEqual(
			binding.PolicyNames(policy.PolicyKindTrafficPolicy),
			[]string{"namespaces/sandbox-namespace/trafficPolicies/allow"},
		)
	}, "explicit Sandbox namespace and labels select policy")

	sandbox.Labels = map[string]string{"app": "other"}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	eventually(t, func() bool {
		binding := fixture.compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetSandbox, sandbox.UID))
		return binding != nil && binding.Valid() && len(binding.PolicyNames(policy.PolicyKindTrafficPolicy)) == 0
	}, "Sandbox label update removes selector-derived binding")
}

func TestSandboxTrafficPolicyCompilesDirectly(t *testing.T) {
	fixture := newIncrementalFixture(t)
	sandbox := model.Sandbox{
		UID: "a", Namespace: "tenant",
		TrafficPolicy: &model.TrafficPolicyRules{
			Ingress: &agentsv1alpha1.TrafficPolicyDirection{},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "192.0.2.0/24"}},
			}}},
		},
	}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "b", Namespace: "tenant"})
	shared := model.TrafficPolicy{Name: "global", Global: true, Spec: agentsv1alpha1.TrafficPolicySpec{
		Priority: 0, Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionReject, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}}}}},
	}}
	fixture.trafficPolicies.ConditionalUpdateObject(shared)
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		a, b := manifestAt(t, fixture.compiler, "a"), manifestAt(t, fixture.compiler, "b")
		return a != nil && len(a.GetTrafficPolicy().GetEgress().GetRules()) == 1 && b != nil && b.TrafficPolicy == nil &&
			reflect.DeepEqual(trafficPolicyRefs(a), []string{"trafficPolicies/global"}) && reflect.DeepEqual(trafficPolicyRefs(b), []string{"trafficPolicies/global"})
	}, "direct Sandbox rules coexist with shared references")
	a := manifestAt(t, fixture.compiler, "a")
	if a.TrafficPolicy.Ingress != nil ||
		a.TrafficPolicy.Egress.Rules[0].Action != securityv1.TrafficPolicy_ALLOW {
		t.Fatalf("inline directions or action lost: %v", a.TrafficPolicy)
	}
	if got := fixture.compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetSandbox, "a")).PolicyNames(model.PolicyKindTrafficPolicy); !reflect.DeepEqual(got, []string{"trafficPolicies/global"}) {
		t.Fatalf("inline policy entered the shared binding graph: %v", got)
	}
	if got := currentSnapshot(t, fixture.compiler).List(model.TrafficPolicyType); len(got) != 1 {
		t.Fatalf("inline policy produced an independent xDS resource: %v", got)
	}
	other := manifestAt(t, fixture.compiler, "b")

	sandbox.TrafficPolicy = &model.TrafficPolicyRules{Egress: sandbox.TrafficPolicy.Egress.DeepCopy()}
	sandbox.TrafficPolicy.Egress.Rules[0].Action = agentsv1alpha1.RuleActionReject
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return len(a.GetTrafficPolicy().GetEgress().GetRules()) == 1 && a.TrafficPolicy.Egress.Rules[0].Action == securityv1.TrafficPolicy_DENY && a.TrafficPolicy.Ingress == nil
	}, "Sandbox body update recompiles directly")

	invalid := sandbox
	invalid.TrafficPolicy = &model.TrafficPolicyRules{Egress: sandbox.TrafficPolicy.Egress.DeepCopy()}
	invalid.TrafficPolicy.Egress.Rules[0].Action = "invalid"
	fixture.sandboxes.ConditionalUpdateObject(invalid)
	eventually(t, func() bool {
		return manifestAt(t, fixture.compiler, "a") == nil && fixture.compiler.Failures()["SandboxResource/a"] != ""
	}, "invalid inline rules are not published as an empty policy")

	sandbox.TrafficPolicy = &model.TrafficPolicyRules{Egress: &agentsv1alpha1.TrafficPolicyDirection{}}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && a.TrafficPolicy != nil && a.TrafficPolicy.Egress == nil && fixture.compiler.Failures()["SandboxResource/a"] == ""
	}, "empty source direction stops enforcement after recovery")

	sandbox.TrafficPolicy = nil
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && a.TrafficPolicy == nil && reflect.DeepEqual(trafficPolicyRefs(a), []string{"trafficPolicies/global"})
	}, "inline removal preserves shared references")
	if !proto.Equal(other, manifestAt(t, fixture.compiler, "b")) {
		t.Fatal("inline changes affected an unrelated Sandbox")
	}
}

func TestSandboxTrafficPolicyTracksPeerUpdates(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.setResolved("api.example.com", netip.MustParseAddr("192.0.2.1"))
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{
		UID: "a", Namespace: "tenant",
		TrafficPolicy: &model.TrafficPolicyRules{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "api.example.com"}},
			}}},
		},
	})
	waitSynced(t, fixture.compiler)
	awaitAddress := func(last byte) {
		t.Helper()
		eventually(t, func() bool {
			rules := manifestAt(t, fixture.compiler, "a").GetTrafficPolicy().GetEgress().GetRules()
			return len(rules) == 1 && len(rules[0].Match.DestinationIps) == 1 &&
				reflect.DeepEqual(rules[0].Match.DestinationIps[0].Address, []byte{192, 0, 2, last})
		}, "inline policy follows the peer resolver dependency")
	}
	awaitAddress(1)
	fixture.setResolved("api.example.com", netip.MustParseAddr("192.0.2.2"))
	awaitAddress(2)
}
