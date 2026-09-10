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
	"slices"
	"sync/atomic"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
	policypkg "github.com/openkruise/agentio/pkg/policy"
)

func TestEgressPolicyIncrementalAttachmentAndLastKnownGood(t *testing.T) {
	fixture := newIncrementalFixture(t)
	client := testWorkload("demo", "client", "10.0.0.2")
	other := testWorkload("other", "client", "10.0.1.2")
	fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(client))
	fixture.workloads.ConditionalUpdateObject(client)
	fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(other))
	fixture.workloads.ConditionalUpdateObject(other)
	valid := func(resourceVersion, cidr, service string) model.AgentioConfiguration {
		return model.AgentioConfiguration{
			ResourceVersion: resourceVersion,
			Value: &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{
				{
					Namespaces: []string{"demo"}, MatchCidrs: []string{cidr}, Policy: extensionsv1.EgressPolicyAction_GATEWAY,
					Gateway: &extensionsv1.GatewayAddress{Service: service, Port: 15008},
				},
			}},
		}
	}
	fixture.agentioConfig.ConditionalUpdateObject(valid("valid", "203.0.113.1/32", "egress-a.agentio-system.svc.cluster.local"))
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, addressResourceName("demo", "client"), addressResourceName("other", "client"))
	baseline, _ := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: client.UID})
	otherBaseline, _ := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: other.UID})
	if !resourceReferencesGateway(baseline, "agentio-system/egress-a") {
		t.Fatalf("valid facts = %+v", baseline.Facts)
	}

	var bindingEvents atomic.Int64
	fixture.compiler.graph.policies.policyBindings.RegisterBatch(func(events []krt.Event[policy.Bindings]) {
		bindingEvents.Add(int64(len(events)))
	}, false)
	fixture.agentioConfig.ConditionalUpdateObject(valid("rules", "203.0.113.2/32", "egress-a.agentio-system.svc.cluster.local"))
	eventually(t, func() bool {
		resource, found := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: client.UID})
		return found && resource.Hash != baseline.Hash
	}, "rules-only egress update changes matching workload")
	settle()
	if got := bindingEvents.Load(); got != 0 {
		t.Fatalf("rules-only egress update emitted %d workload binding events, want 0", got)
	}
	if current, _ := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: other.UID}); current.Hash != otherBaseline.Hash {
		t.Fatal("rules-only demo egress update changed unrelated namespace")
	}

	fixture.agentioConfig.ConditionalUpdateObject(valid("gateway", "203.0.113.2/32", "egress-b.agentio-system.svc.cluster.local"))
	eventually(t, func() bool {
		resource, found := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: client.UID})
		return found && resourceReferencesGateway(resource, "agentio-system/egress-b")
	}, "gateway reference changes")
	lastGood, _ := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: client.UID})
	if resourceReferencesGateway(lastGood, "agentio-system/egress-a") {
		t.Fatalf("old gateway reference remains: %+v", lastGood.Facts)
	}

	fixture.agentioConfig.ConditionalUpdateObject(valid("invalid", "203.0.113.3/32", "egress..svc.cluster.local"))
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["AgentioConfig/configuration"]
		return found
	}, "malformed gateway records configuration failure")
	settle()
	retained, _ := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: client.UID})
	if retained.Hash != lastGood.Hash {
		t.Fatalf("malformed gateway replaced last-known-good workload: %s != %s", retained.Hash, lastGood.Hash)
	}
}

// A namespaced policy edit must invalidate only the workloads of that namespace.
func TestPolicyEditInvalidatesOnlyItsNamespace(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(testWorkload("alpha", "client", "10.1.0.1")))
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(testWorkload("beta", "client", "10.2.0.1")))
	fixture.workloads.ConditionalUpdateObject(testWorkload("beta", "client", "10.2.0.1"))
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "allow", Namespace: "alpha",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	})
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		addressResourceName("alpha", "client"),
		addressResourceName("beta", "client"),
		model.SandboxType+"|cluster//Pod/alpha/client")

	recorder := newRecorder(fixture.compiler.Resources())

	// Widen the alpha policy. Only alpha's workload and the alpha Authorization
	// depend on it.
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "allow", Namespace: "alpha",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/8"}},
			}}},
		},
	})

	eventually(t, func() bool {
		return recorder.has(model.SandboxType + "|cluster//Pod/alpha/client")
	}, "alpha authorization recompiled")
	settle()

	if recorder.has(addressResourceName("beta", "client")) {
		t.Fatalf("editing an alpha policy invalidated a beta workload; changed=%v", recorder.names())
	}
}

func TestExactSandboxPolicyLifecycleAffectsOnlyTarget(t *testing.T) {
	fixture := newIncrementalFixture(t)
	first := testWorkload("demo", "first", "10.1.0.1")
	second := testWorkload("demo", "second", "10.1.0.2")
	firstUID := "sandbox-first"
	secondUID := "sandbox-second"
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{
		UID: firstUID, Attester: &model.Attester{WorkloadUID: first.UID}, Namespace: "demo",
		Labels: map[string]string{agentsv1alpha1.LabelSandboxID: firstUID},
	})
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{
		UID: secondUID, Attester: &model.Attester{WorkloadUID: second.UID}, Namespace: "demo",
		Labels: map[string]string{agentsv1alpha1.LabelSandboxID: secondUID},
	})
	fixture.workloads.ConditionalUpdateObject(first)
	fixture.workloads.ConditionalUpdateObject(second)
	waitSynced(t, fixture.compiler)
	firstAddress := addressResourceName("demo", "first")
	secondAddress := addressResourceName("demo", "second")
	awaitSteadyState(t, fixture.compiler, firstAddress, secondAddress)

	policyInput := model.TrafficPolicy{
		Name: "exact", Namespace: "demo", SandboxUID: firstUID,
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				agentsv1alpha1.LabelSandboxID: firstUID,
			}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	}
	sandboxKey := model.SandboxType + "|" + firstUID
	recorder := newRecorder(fixture.compiler.Resources())
	fixture.trafficPolicies.ConditionalUpdateObject(policyInput)
	eventually(t, func() bool {
		return recorder.has(sandboxKey)
	}, "exact policy attached to its Sandbox")
	settle()
	if got, want := recorder.names(), []string{sandboxKey}; !reflect.DeepEqual(got, want) {
		t.Fatalf("exact policy add changed %v, want %v", got, want)
	}
	if recorder.has(secondAddress) {
		t.Fatalf("exact policy add invalidated unrelated Sandbox; changed=%v", recorder.names())
	}

	recorder.reset()
	fixture.trafficPolicies.DeleteObject(policyInput.ResourceName())
	eventually(t, func() bool {
		return recorder.has(sandboxKey)
	}, "exact policy detached from its Sandbox")
	settle()
	if got, want := recorder.names(), []string{sandboxKey}; !reflect.DeepEqual(got, want) {
		t.Fatalf("exact policy delete changed %v, want %v", got, want)
	}
	if recorder.has(secondAddress) {
		t.Fatalf("exact policy delete invalidated unrelated Sandbox; changed=%v", recorder.names())
	}
}

// A global policy legitimately attaches everywhere, so it must invalidate
// Sandbox views in every namespace.
func TestGlobalPolicyInvalidatesEveryNamespace(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(testWorkload("alpha", "client", "10.1.0.1")))
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(testWorkload("beta", "client", "10.2.0.1")))
	fixture.workloads.ConditionalUpdateObject(testWorkload("beta", "client", "10.2.0.1"))
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		addressResourceName("alpha", "client"),
		addressResourceName("beta", "client"))

	recorder := newRecorder(fixture.compiler.Resources())

	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "deny-all", Global: true,
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	})

	for _, namespace := range []string{"alpha", "beta"} {
		expected := model.SandboxType + "|cluster//Pod/" + namespace + "/client"
		eventually(t, func() bool { return recorder.has(expected) },
			"global policy invalidated Sandbox in "+namespace)
	}
}

// One malformed object must not stop the rest of the configuration from publishing.
func TestMalformedPolicyIsOmittedWhileRestPublishes(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(testWorkload("alpha", "client", "10.1.0.1")))
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "broken", Namespace: "alpha", SandboxUID: "sandbox-a",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				"app": "client", agentsv1alpha1.LabelSandboxID: "sandbox-b",
			}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	})
	waitSynced(t, fixture.compiler)

	eventually(t, func() bool {
		_, found := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{
			TypeURL: model.AddressType, Name: "cluster//Pod/alpha/client"})
		return found
	}, "workload published despite the broken policy")

	if compiled := fixture.compiler.graph.policies.trafficPolicies.GetKey("trafficpolicy/alpha/broken"); compiled != nil {
		t.Fatal("a policy with conflicting Sandbox UIDs produced a native TrafficPolicy")
	}
	eventually(t, func() bool {
		failures := fixture.compiler.Failures()
		return failures["TrafficPolicy/namespaced/alpha/broken"] != "" && failures["NativeTrafficPolicy/namespaced/alpha/broken"] != ""
	}, "both policy compilation stages report the invalid source")

	failures := fixture.compiler.Failures()
	if _, found := failures["TrafficPolicy/namespaced/alpha/broken"]; !found {
		t.Fatalf("failure not attributed to the policy: %v", failures)
	}

	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "broken", Namespace: "alpha",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	})
	eventually(t, func() bool {
		manifest := manifestAt(t, fixture.compiler, "cluster//Pod/alpha/client")
		return manifest != nil && len(manifest.TrafficPolicies) == 1 && len(fixture.compiler.Failures()) == 0
	}, "fixed policy publishes and clears the failure")
}

func TestDeletingMalformedTrafficPolicyClearsFailure(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name:       "broken",
		Namespace:  "alpha",
		SandboxUID: "sandbox-a",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				agentsv1alpha1.LabelSandboxID: "sandbox-b",
			}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: []agentsv1alpha1.TrafficPolicyRule{
					{
						Action: agentsv1alpha1.RuleActionAllow,
						To: []agentsv1alpha1.TrafficPolicyPeer{
							{
								CIDR: "10.0.0.0/24",
							},
						},
					},
				},
			},
		},
	})
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["TrafficPolicy/namespaced/alpha/broken"]
		return found
	}, "malformed policy failure")

	fixture.trafficPolicies.DeleteObject("namespaced/alpha/broken")
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["TrafficPolicy/namespaced/alpha/broken"]
		return !found
	}, "deleted malformed policy clears failure")
}

func TestDeletingMalformedSecurityProfileClearsFailure(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.securityProfiles.ConditionalUpdateObject(model.SecurityProfile{
		Name:      "broken",
		Namespace: "alpha",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{},
			Rules: []agentsv1alpha1.SecurityRule{
				{
					Name: "api",
					Match: []agentsv1alpha1.RuleMatch{
						{
							Domains: []string{"*foo.example.com"},
						},
					},
				},
			},
		},
	})
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["SecurityProfile/namespaced/alpha/broken"]
		return found
	}, "malformed profile failure")

	fixture.securityProfiles.DeleteObject("namespaced/alpha/broken")
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["SecurityProfile/namespaced/alpha/broken"]
		return !found
	}, "deleted malformed profile clears failure")
}

func TestMalformedTrafficPolicyUpdatePreservesLastKnownGood(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(testWorkload("alpha", "client", "10.1.0.1")))
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	valid := model.TrafficPolicy{
		Name:      "allow",
		Namespace: "alpha",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "client",
				},
			},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: []agentsv1alpha1.TrafficPolicyRule{
					{
						Action: agentsv1alpha1.RuleActionAllow,
						To: []agentsv1alpha1.TrafficPolicyPeer{
							{
								CIDR: "10.0.0.0/24",
							},
						},
					},
				},
			},
		},
	}
	fixture.trafficPolicies.ConditionalUpdateObject(valid)
	waitSynced(t, fixture.compiler)

	key := model.ResourceKey{
		TypeURL: model.SandboxType,
		Name:    "cluster//Pod/alpha/client",
	}
	eventually(t, func() bool {
		_, found := currentSnapshot(t, fixture.compiler).Get(key)
		return found
	}, "initial authorization resource")
	baseline, _ := currentSnapshot(t, fixture.compiler).Get(key)

	invalid := valid
	invalid.SandboxUID = "sandbox-a"
	invalid.Spec = *valid.Spec.DeepCopy()
	invalid.Spec.Selector.MatchLabels[agentsv1alpha1.LabelSandboxID] = "sandbox-b"
	fixture.trafficPolicies.ConditionalUpdateObject(invalid)
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["TrafficPolicy/namespaced/alpha/allow"]
		return found
	}, "invalid update failure")
	settle()

	retained, found := currentSnapshot(t, fixture.compiler).Get(key)
	if !found {
		t.Fatal("invalid update removed the last-known-good Authorization")
	}
	if retained.Hash != baseline.Hash {
		t.Fatalf("invalid update replaced the last-known-good Authorization: %s != %s", retained.Hash, baseline.Hash)
	}
}

func TestMalformedSecurityProfileUpdatePreservesLastKnownGood(t *testing.T) {
	fixture := newIncrementalFixture(t)
	valid := model.SecurityProfile{
		Name:      "terminate",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "client",
				},
			},
			Rules: []agentsv1alpha1.SecurityRule{
				{
					Name: "api",
					Match: []agentsv1alpha1.RuleMatch{
						{
							Domains: []string{"api.example.com"},
						},
					},
				},
			},
		},
	}
	fixture.securityProfiles.ConditionalUpdateObject(valid)
	waitSynced(t, fixture.compiler)

	key := "demo/terminate"
	eventually(t, func() bool {
		return fixture.compiler.graph.policies.sniPolicies.GetKey(key) != nil
	}, "initial SNI policy")
	baseline := fixture.compiler.graph.policies.sniPolicies.GetKey(key)

	invalid := valid
	invalid.Spec.Rules = append([]agentsv1alpha1.SecurityRule(nil), valid.Spec.Rules...)
	invalid.Spec.Rules[0].Match = append([]agentsv1alpha1.RuleMatch(nil), valid.Spec.Rules[0].Match...)
	invalid.Spec.Rules[0].Match[0].Domains = []string{"*foo.example.com"}
	fixture.securityProfiles.ConditionalUpdateObject(invalid)
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["SecurityProfile/namespaced/demo/terminate"]
		return found
	}, "invalid update failure")
	settle()

	retained := fixture.compiler.graph.policies.sniPolicies.GetKey(key)
	if retained == nil || !retained.Equals(*baseline) {
		t.Fatal("invalid update replaced the last-known-good SNI policy")
	}
}

func TestWorkloadPeerResolutionUsesPodMetadata(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}

	bound := testWorkload("demo", "bound", "10.1.0.3")
	bound.Labels = map[string]string{"role": "not-peer"}

	agentioConfig := krt.NewStaticCollection[model.AgentioConfiguration](nil, nil, options...)
	inputs := validCompilerInputs(stop)
	inputs.Sandboxes = krt.NewStaticCollection(nil, []model.Sandbox{{
		UID: "sandbox-bound", Attester: &model.Attester{WorkloadUID: bound.UID},
		Namespace: "sandbox-namespace",
		Labels:    map[string]string{"role": "not-peer"},
	}}, options...)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{bound}, options...)
	inputs.Pods = krt.NewStaticCollection(nil, []*corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "bound", Labels: map[string]string{"role": "peer"}},
		Status: corev1.PodStatus{
			PodIP:      "10.1.0.3",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}}, options...)
	inputs.Gateways = testGatewaySource(agentioConfig, options...)
	inputs.TrafficPolicies = krt.NewStaticCollection(nil, []model.TrafficPolicy{{
		Name: "allow-peers", Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To: []agentsv1alpha1.TrafficPolicyPeer{{Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{
					Namespace: "demo",
					Selector:  map[string]string{"role": "peer"},
				}}},
			}}},
		},
	}}, options...)
	inputs.AgentioConfig = agentioConfig
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}

	compileSynced(t, compiler)
	compiled := compiler.graph.policies.trafficPolicies.GetKey("trafficpolicy/demo/allow-peers")
	if compiled == nil {
		t.Fatal("compiled native TrafficPolicy missing")
	}
	addresses := map[string]struct{}{}
	for _, rule := range compiled.Policy.Egress.Rules {
		for _, address := range rule.Match.DestinationIps {
			parsed, ok := netip.AddrFromSlice(address.Address)
			if ok {
				addresses[netip.PrefixFrom(parsed, int(address.Length)).String()] = struct{}{}
			}
		}
	}
	for _, want := range []string{"10.1.0.3/32"} {
		if _, found := addresses[want]; !found {
			t.Fatalf("Workload peer addresses = %v, missing %s", addresses, want)
		}
	}
}

func TestCompilerPublishesWorkloadsWithoutAttestablePrincipalAndResolvesTrafficPolicyPeers(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}

	withoutServiceAccount := testWorkload("demo", "static-control-plane", "10.1.0.9")
	withoutServiceAccount.Labels = map[string]string{"role": "control-plane"}
	withoutServiceAccount.Principal.ServiceAccount.ServiceAccount = ""
	withoutPrincipal := testWorkload("demo", "opaque-endpoint", "10.1.0.10")
	withoutPrincipal.Labels = map[string]string{"role": "control-plane"}
	withoutPrincipal.Principal = model.Principal{}
	workloads := []model.Workload{withoutServiceAccount, withoutPrincipal}

	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, workloads, options...)
	inputs.Pods = krt.NewStaticCollection(nil, []*corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "static-control-plane", Labels: map[string]string{"role": "control-plane"}},
			Status: corev1.PodStatus{PodIP: "10.1.0.9", Conditions: []corev1.PodCondition{{
				Type: corev1.PodReady, Status: corev1.ConditionTrue,
			}}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "opaque-endpoint", Labels: map[string]string{"role": "control-plane"}},
			Status: corev1.PodStatus{PodIP: "10.1.0.10", Conditions: []corev1.PodCondition{{
				Type: corev1.PodReady, Status: corev1.ConditionTrue,
			}}},
		},
	}, options...)
	inputs.TrafficPolicies = krt.NewStaticCollection(nil, []model.TrafficPolicy{{
		Name: "allow-control-plane", Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To: []agentsv1alpha1.TrafficPolicyPeer{{Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{
					Namespace: "demo",
					Selector:  map[string]string{"role": "control-plane"},
				}}},
			}}},
		},
	}}, options...)

	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	snapshot := compileSynced(t, compiler)

	for _, workload := range workloads {
		workloadResource, found := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: workload.UID})
		if !found {
			t.Fatalf("WDS Address for unattestable workload %q is missing", workload.UID)
		}
		address := &workloadv1.Address{}
		if err := workloadResource.Value.UnmarshalTo(address); err != nil {
			t.Fatalf("unmarshal WDS Address %q: %v", workload.UID, err)
		}
		if got := address.GetWorkload().GetServiceAccount(); got != "" {
			t.Fatalf("WDS ServiceAccount for %q = %q, want omitted", workload.UID, got)
		}
	}

	compiled := compiler.graph.policies.trafficPolicies.GetKey("trafficpolicy/demo/allow-control-plane")
	if compiled == nil {
		t.Fatal("compiled native TrafficPolicy missing")
	}
	got := map[netip.Prefix]struct{}{}
	for _, rule := range compiled.Policy.Egress.Rules {
		for _, candidate := range rule.Match.DestinationIps {
			address, ok := netip.AddrFromSlice(candidate.Address)
			if ok {
				got[netip.PrefixFrom(address, int(candidate.Length))] = struct{}{}
			}
		}
	}
	for _, want := range []netip.Prefix{
		netip.MustParsePrefix("10.1.0.9/32"),
		netip.MustParsePrefix("10.1.0.10/32"),
	} {
		if _, found := got[want]; !found {
			t.Fatalf("TrafficPolicy Workload peers = %v, missing %s", got, want)
		}
	}
}

func TestCompilerInlinesTrafficPolicyInSandbox(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workloads := krt.NewStaticCollection[model.Workload](nil, nil, options...)
	services := krt.NewStaticCollection[model.Service](nil, nil, options...)
	endpoints := krt.NewStaticCollection[model.Endpoint](nil, nil, options...)
	trafficPolicies := krt.NewStaticCollection[model.TrafficPolicy](nil, nil, options...)
	securityProfiles := krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...)
	agentioConfig := krt.NewStaticCollection[model.AgentioConfiguration](nil, nil, options...)
	workloads.ConditionalUpdateObject(testWorkload("demo", "client", "10.1.0.2"))
	trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{Name: "allow", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
		Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
			Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "203.0.113.0/24"}},
		}}},
	}})

	inputs := validCompilerInputs(stop)
	inputs.Sandboxes = krt.NewStaticCollection(nil, []model.Sandbox{{UID: "cluster//Pod/demo/client", Namespace: "demo", Labels: map[string]string{"app": "client"}}}, options...)
	inputs.Workloads = workloads
	inputs.Services = services
	inputs.Endpoints = endpoints
	inputs.Gateways = testGatewaySource(agentioConfig, options...)
	inputs.TrafficPolicies = trafficPolicies
	inputs.SecurityProfiles = securityProfiles
	inputs.AgentioConfig = agentioConfig
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	snapshot := compileSynced(t, compiler)
	if len(snapshot.List(model.WorkloadAuthorizationType)) != 1 {
		t.Fatal("Workload Authorization must be published independently")
	}
	workloadResource, found := snapshot.Get(model.ResourceKey{
		TypeURL: model.AddressType,
		Name:    "cluster//Pod/demo/client",
	})
	if !found {
		t.Fatal("compiled Workload resource not found")
	}
	address := &workloadv1.Address{}
	if err := workloadResource.Value.UnmarshalTo(address); err != nil {
		t.Fatalf("unmarshal Workload: %v", err)
	}
	got := address.GetWorkload().GetAuthorizationPolicies()
	if !reflect.DeepEqual(got, []string{"demo/allow-egress"}) {
		t.Fatalf("workload authorization policies = %v", got)
	}
	manifest := manifestAt(t, compiler, "cluster//Pod/demo/client")
	if manifest == nil || !slices.ContainsFunc(manifest.TrafficPolicies, func(policy *securityv1.TrafficPolicy) bool {
		return policy.Name == "trafficpolicy/demo/allow"
	}) {
		t.Fatalf("Sandbox is missing inline TrafficPolicy: %+v", manifest)
	}
}

func TestAuthorizationResourceCarriesScopeFacts(t *testing.T) {
	tests := []struct {
		name          string
		source        model.TrafficPolicy
		authorization *securityv1.Authorization
		want          model.AuthorizationResourceFacts
	}{
		{
			name:   "global",
			source: model.TrafficPolicy{Name: "global", Namespace: "agentio-system", Global: true},
			authorization: &securityv1.Authorization{
				Name: "global-egress", Namespace: "agentio-system", Scope: securityv1.Scope_GLOBAL,
			},
			want: model.AuthorizationResourceFacts{Scope: model.AuthorizationScopeGlobal},
		},
		{
			name:   "namespace",
			source: model.TrafficPolicy{Name: "namespace", Namespace: "demo"},
			authorization: &securityv1.Authorization{
				Name: "namespace-egress", Namespace: "demo", Scope: securityv1.Scope_NAMESPACE,
			},
			want: model.AuthorizationResourceFacts{Scope: model.AuthorizationScopeNamespace, Namespace: "demo"},
		},
		{
			name:   "selector",
			source: model.TrafficPolicy{Name: "selector", Namespace: "demo"},
			authorization: &securityv1.Authorization{
				Name: "selector-egress", Namespace: "demo", Scope: securityv1.Scope_WORKLOAD_SELECTOR,
			},
			want: model.AuthorizationResourceFacts{Scope: model.AuthorizationScopeWorkload},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource, err := authorizationResource(policypkg.CompiledAuthorization{
				Name: test.authorization.GetNamespace() + "/" + test.authorization.GetName(), Policy: test.authorization,
			})
			if err != nil {
				t.Fatal(err)
			}
			if resource.Facts.Authorization == nil || *resource.Facts.Authorization != test.want {
				t.Fatalf("Authorization facts = %+v, want %+v", resource.Facts.Authorization, test.want)
			}
		})
	}
}

func TestCompilerKeepsSandboxSNIOutOfWorkload(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workloads := krt.NewStaticCollection[model.Workload](nil, nil, options...)
	services := krt.NewStaticCollection[model.Service](nil, nil, options...)
	endpoints := krt.NewStaticCollection[model.Endpoint](nil, nil, options...)
	trafficPolicies := krt.NewStaticCollection[model.TrafficPolicy](nil, nil, options...)
	securityProfiles := krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...)
	agentioConfig := krt.NewStaticCollection[model.AgentioConfiguration](nil, nil, options...)
	workload := testWorkload("demo", "client", "10.1.0.2")
	workloads.ConditionalUpdateObject(workload)
	securityProfiles.ConditionalUpdateObject(model.SecurityProfile{Name: "terminate", Namespace: "demo", Spec: agentsv1alpha1.SecurityProfileSpec{
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "does-not-match"}},
		Rules:    []agentsv1alpha1.SecurityRule{{Name: "api", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}}}},
	}})
	securityProfiles.ConditionalUpdateObject(model.SecurityProfile{Name: "pod-policy", Namespace: "demo", Spec: agentsv1alpha1.SecurityProfileSpec{
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
		Rules:    []agentsv1alpha1.SecurityRule{{Name: "pod", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"pod.example.com"}}}}},
	}})
	agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{Value: &configv1.AgentioConfig{
		EgressPolicies: []*extensionsv1.EgressPolicy{{Policy: extensionsv1.EgressPolicyAction_PASSTHROUGH}},
	}})
	inputs := validCompilerInputs(stop)
	inputs.Sandboxes = krt.NewStaticCollection(nil, []model.Sandbox{{
		UID: workload.UID, Attester: &model.Attester{WorkloadUID: workload.UID},
		PolicyRefs: []model.PolicyRef{{
			Kind: model.PolicyKindSNIPolicy,
			Name: "demo/terminate",
		}},
	}}, options...)
	inputs.Workloads = workloads
	inputs.Services = services
	inputs.Endpoints = endpoints
	inputs.Gateways = testGatewaySource(agentioConfig, options...)
	inputs.TrafficPolicies = trafficPolicies
	inputs.SecurityProfiles = securityProfiles
	inputs.AgentioConfig = agentioConfig
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	snapshot := compileSynced(t, compiler)
	if _, found := snapshot.Get(model.ResourceKey{
		TypeURL: model.SniTrafficPolicyType,
		Name:    "demo/terminate",
	}); found {
		t.Fatal("independent SNI resource must not be published")
	}
	workloadResource, _ := snapshot.Get(model.ResourceKey{
		TypeURL: model.AddressType,
		Name:    "cluster//Pod/demo/client",
	})
	address := &workloadv1.Address{}
	if err := workloadResource.Value.UnmarshalTo(address); err != nil {
		t.Fatalf("unmarshal Workload: %v", err)
	}
	if got := extensionNames(address.GetWorkload().GetExtensions()); !reflect.DeepEqual(got, []string{"workload-metadata", "egress-policies", "sni-traffic-policy"}) {
		t.Fatalf("Address workload extensions = %v, want independently matched Workload policies", got)
	}
	workloadSNI := new(extensionsv1.SniTrafficPolicy)
	if err := address.GetWorkload().Extensions[2].Config.UnmarshalTo(workloadSNI); err != nil {
		t.Fatal(err)
	}
	if len(workloadSNI.Rules) != 1 || !reflect.DeepEqual(workloadSNI.Rules[0].Match.Sni, []string{"pod.example.com"}) {
		t.Fatalf("Workload SNI must use its own selector: %v", workloadSNI)
	}
	if _, found := snapshot.Get(model.ResourceKey{TypeURL: model.WorkloadType, Name: "cluster//Pod/demo/client"}); found {
		t.Fatal("compiler retained a direct Workload resource")
	}
	manifest := manifestAt(t, compiler, workload.UID)
	if manifest == nil || len(manifest.Extensions) != 1 {
		t.Fatalf("Sandbox extensions = %v", manifest)
	}
	payload := &extensionsv1.SniTrafficPolicy{}
	if err := manifest.Extensions[0].UnmarshalTo(payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Rules) != 1 {
		t.Fatalf("Sandbox SNI payload = %v", payload)
	}
	binding := compiler.Bindings().GetKey(policypkg.BindingsKey(policypkg.PolicyTargetSandbox, workload.UID))
	if binding == nil || !reflect.DeepEqual(binding.PolicyNames(policypkg.PolicyKindSNIPolicy), []string{"demo/terminate"}) {
		t.Fatalf("Sandbox policy binding = %+v", binding)
	}
}

func TestCompilerRetainsNetworkingWithUnresolvedSandboxPolicyReference(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workload := testWorkload("demo", "client", "10.1.0.2")
	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{workload}, options...)
	inputs.Sandboxes = krt.NewStaticCollection(nil, []model.Sandbox{{
		UID: workload.UID,
		PolicyRefs: []model.PolicyRef{{
			Kind: model.PolicyKindSNIPolicy, Name: "demo/missing",
		}},
	}}, options...)

	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	waitSynced(t, compiler)
	snapshot, err := compiler.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if r, found := snapshot.Get(model.ResourceKey{
		TypeURL: model.AddressType, Name: workload.UID,
	}); !found || r.Facts.Workload == nil {
		t.Fatal("networking must remain available when Sandbox policies are unavailable")
	}
	failures := compiler.Failures()
	if _, found := failures["Bindings/"+policypkg.BindingsKey(policypkg.PolicyTargetSandbox, workload.UID)]; !found {
		t.Fatalf("Sandbox failure is missing: %v", failures)
	}
	if manifest := manifestAt(t, compiler, workload.UID); manifest != nil {
		t.Fatal("invalid Sandbox policy binding must withdraw the manifest")
	}
}

func TestCompilerPublishesWorkloadEgressPolicies(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workloads := krt.NewStaticCollection(nil, []model.Workload{
		testWorkload("demo-a", "client", "10.1.0.2"),
		testWorkload("demo-b", "client", "10.2.0.2"),
		testWorkload("other", "client", "10.3.0.2"),
	}, options...)
	config := krt.NewStaticCollection[model.AgentioConfiguration](nil, []model.AgentioConfiguration{{
		Value: &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{
			{Namespaces: []string{"demo-a"}, MatchCidrs: []string{"203.0.113.1/32"}, Policy: extensionsv1.EgressPolicyAction_GATEWAY,
				Gateway: &extensionsv1.GatewayAddress{Service: "egress-a.agentio-system.svc.cluster.local", Port: 15008}},
			{Namespaces: []string{"demo-a"}, MatchCidrs: []string{"203.0.113.2/32"}, Policy: extensionsv1.EgressPolicyAction_GATEWAY,
				Gateway: &extensionsv1.GatewayAddress{Service: "egress-a.agentio-system.svc.cluster.local", Port: 15008}},
			{Namespaces: []string{"demo-b"}, MatchCidrs: []string{"198.51.100.1/32"}, Policy: extensionsv1.EgressPolicyAction_GATEWAY,
				Gateway: &extensionsv1.GatewayAddress{Service: "egress-b.agentio-system.svc.cluster.local", Port: 15008}},
			{Namespaces: []string{"demo-b"}, MatchCidrs: []string{"198.51.100.2/32"}, Policy: extensionsv1.EgressPolicyAction_PASSTHROUGH},
		}},
	}}, options...)
	emptyServices := krt.NewStaticCollection[model.Service](nil, nil, options...)
	emptyEndpoints := krt.NewStaticCollection[model.Endpoint](nil, nil, options...)
	emptyTrafficPolicies := krt.NewStaticCollection[model.TrafficPolicy](nil, nil, options...)
	emptySecurity := krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...)
	inputs := validCompilerInputs(stop)
	inputs.Sandboxes = krt.NewStaticCollection(nil, []model.Sandbox{
		{UID: "cluster//Pod/demo-a/client", Namespace: "demo-a", Attester: &model.Attester{WorkloadUID: "cluster//Pod/demo-a/client"}},
		{UID: "cluster//Pod/demo-b/client", Namespace: "demo-b", Attester: &model.Attester{WorkloadUID: "cluster//Pod/demo-b/client"}},
		{UID: "cluster//Pod/other/client", Namespace: "other", Attester: &model.Attester{WorkloadUID: "cluster//Pod/other/client"}},
	}, options...)
	inputs.Workloads = workloads
	inputs.Services = emptyServices
	inputs.Endpoints = emptyEndpoints
	inputs.Gateways = testGatewaySource(config, options...)
	inputs.TrafficPolicies = emptyTrafficPolicies
	inputs.SecurityProfiles = emptySecurity
	inputs.AgentioConfig = config
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := compileSynced(t, compiler)

	tests := []struct {
		uid          string
		wantPolicies int
		wantGateway  string
	}{
		{
			uid:          "cluster//Pod/demo-a/client",
			wantPolicies: 2,
			wantGateway:  "agentio-system/egress-a",
		},
		{
			uid:          "cluster//Pod/demo-b/client",
			wantPolicies: 2,
			wantGateway:  "agentio-system/egress-b",
		},
		{
			uid: "cluster//Pod/other/client",
		},
	}
	for _, test := range tests {
		resource, found := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: test.uid})
		if !found {
			t.Fatalf("Address %s is missing", test.uid)
		}
		address := &workloadv1.Address{}
		if err := resource.Value.UnmarshalTo(address); err != nil {
			t.Fatal(err)
		}
		manifest := manifestAt(t, compiler, test.uid)
		if manifest == nil {
			t.Fatalf("Sandbox %s is missing", test.uid)
		}
		effective := manifest.EgressRouting
		if test.wantPolicies == 0 {
			if effective != nil {
				t.Fatalf("%s received unrelated egress policies: %+v", test.uid, effective)
			}
			continue
		}
		if got := len(effective.GetRoutes()); got != test.wantPolicies {
			t.Fatalf("%s policy count = %d, want %d", test.uid, got, test.wantPolicies)
		}
		sandboxResource, _ := snapshot.Get(model.ResourceKey{TypeURL: model.SandboxType, Name: test.uid})
		if sandboxResource.Facts.Sandbox == nil ||
			!slices.Contains(sandboxResource.Facts.Sandbox.GatewayReferences, test.wantGateway) {
			t.Fatalf("%s facts = %+v, missing Gateway reference %s", test.uid, sandboxResource.Facts, test.wantGateway)
		}
		count := 0
		for _, current := range sandboxResource.Facts.Sandbox.GatewayReferences {
			if current == test.wantGateway {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s Gateway reference count = %d, want 1", test.uid, count)
		}
	}
}

// Rule payload changes update the owning Sandbox without
// invalidating canonical Workload Addresses.
func TestTrafficRulesOnlyUpdateDoesNotInvalidateWorkloads(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(testWorkload("demo", "client", "10.1.0.1")))
	fixture.workloads.ConditionalUpdateObject(testWorkload("demo", "client", "10.1.0.1"))
	policyInput := model.TrafficPolicy{
		Name: "allow", Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	}
	fixture.trafficPolicies.ConditionalUpdateObject(policyInput)
	waitSynced(t, fixture.compiler)
	sandboxKey := model.ResourceKey{TypeURL: model.SandboxType, Name: "cluster//Pod/demo/client"}
	eventually(t, func() bool {
		_, found := currentSnapshot(t, fixture.compiler).Get(sandboxKey)
		return found
	}, "initial Sandbox resource")
	settle()
	recorder := newRecorder(fixture.compiler.Resources())
	oldSandbox, _ := currentSnapshot(t, fixture.compiler).Get(sandboxKey)

	updated := policyInput
	updated.Spec.Egress = policyInput.Spec.Egress.DeepCopy()
	updated.Spec.Egress.Rules[0].To[0].CIDR = "10.0.0.0/8"
	fixture.trafficPolicies.ConditionalUpdateObject(updated)
	eventually(t, func() bool {
		current, found := currentSnapshot(t, fixture.compiler).Get(sandboxKey)
		return found && current.Hash != oldSandbox.Hash
	}, "authorization rules update")
	settle()

	if recorder.has(addressResourceName("demo", "client")) {
		t.Fatalf("rules-only TrafficPolicy update invalidated workload; changed=%v", recorder.names())
	}
}
