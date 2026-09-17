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
	"sync"
	"sync/atomic"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
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

func TestSandboxInlineSecurityRulesLifecycle(t *testing.T) {
	fixture := newIncrementalFixture(t)
	shared := model.SecurityProfile{Name: "shared",
		Namespace: "tenant",
		Spec: agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{
			Name:  "shared",
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"shared.example"}}},
		}}},
	}
	fixture.securityProfiles.ConditionalUpdateObject(shared)
	sandbox := model.Sandbox{UID: "inline", Namespace: "tenant"}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "other", Namespace: "tenant"})
	waitSynced(t, fixture.compiler)
	awaitHosts := func(uid string, hosts ...[]string) {
		t.Helper()
		eventually(t, func() bool {
			manifest := manifestAt(t, fixture.compiler, uid)
			if manifest == nil || len(manifest.Extensions) != len(hosts) {
				return false
			}
			for i, want := range hosts {
				payload := new(extensionsv1.SniTrafficPolicy)
				if err := manifest.Extensions[i].UnmarshalTo(payload); err != nil {
					t.Fatal(err)
				}
				if len(payload.Rules) != 1 ||
					payload.Rules[0].Action != extensionsv1.SniAction_SNI_ACTION_TLS_TERMINATION ||
					!reflect.DeepEqual(payload.Rules[0].GetMatch().GetSni(), want) {
					return false
				}
			}
			return true
		}, "Sandbox SNI extensions reflect inline and shared rules")
	}
	awaitHosts("inline", []string{"shared.example"})
	awaitHosts("other", []string{"shared.example"})
	other := manifestAt(t, fixture.compiler, "other")
	inline := model.SecurityProfile{Dedicated: true, SandboxUID: sandbox.UID, Namespace: sandbox.Namespace}
	inline.Spec.Rules = []agentsv1alpha1.SecurityRule{{
		Name: "inline",
		Match: []agentsv1alpha1.RuleMatch{
			{Domains: []string{"API.Example.", "*.Example", "api.example"}},
			{Domains: []string{"https.example"}, Schemes: []string{"HTTPS"}},
			{Domains: []string{"http.example"}, Schemes: []string{"http"}},
		},
	}}
	fixture.securityProfiles.ConditionalUpdateObject(inline)
	awaitHosts("inline", []string{"api.example", "*.example", "https.example"}, []string{"shared.example"})

	inline.Spec.Rules = []agentsv1alpha1.SecurityRule{
		{Name: "updated", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"updated.example"}}}},
	}
	fixture.securityProfiles.ConditionalUpdateObject(inline)
	awaitHosts("inline", []string{"updated.example"}, []string{"shared.example"})

	// Reject the whole inline policy, including valid rules preceding the bad one.
	inline.Spec.Rules = []agentsv1alpha1.SecurityRule{
		{Name: "valid", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"updated.example"}}}},
		{Name: "invalid", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*bad.example"}}}},
	}
	fixture.securityProfiles.ConditionalUpdateObject(inline)
	eventually(t, func() bool {
		return fixture.compiler.Failures()["SecurityProfile/"+inline.ResourceName()] != ""
	}, "invalid SNI records a compilation failure")
	awaitHosts("inline", []string{"shared.example"})

	inline.Spec.Rules = []agentsv1alpha1.SecurityRule{
		{
			Name:  "http-only",
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"http.example"}, Schemes: []string{"http"}}},
		},
	}
	fixture.securityProfiles.ConditionalUpdateObject(inline)
	awaitHosts("inline", []string{"shared.example"})
	eventually(
		t,
		func() bool { return fixture.compiler.Failures()["SecurityProfile/"+inline.ResourceName()] == "" },
		"valid rules clear the failure",
	)

	fixture.securityProfiles.DeleteObject(shared.ResourceName())
	awaitHosts("inline")
	inline.Spec.Rules = []agentsv1alpha1.SecurityRule{
		{Name: "inline", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*"}}}},
	}
	fixture.securityProfiles.ConditionalUpdateObject(inline)
	awaitHosts("inline", []string{"*"})
	fixture.securityProfiles.DeleteObject(inline.ResourceName())
	awaitHosts("inline")

	// Reinstall the shared policy to check the other Sandbox was not changed by inline rules.
	fixture.securityProfiles.ConditionalUpdateObject(shared)
	awaitHosts("other", []string{"shared.example"})
	if !proto.Equal(other, manifestAt(t, fixture.compiler, "other")) {
		t.Fatal("inline security rules changed another Sandbox")
	}
	fixture.sandboxes.DeleteObject("inline")
	fixture.securityProfiles.DeleteObject(inline.ResourceName())
	eventually(
		t,
		func() bool { return manifestAt(t, fixture.compiler, "inline") == nil },
		"Sandbox deletion removes its SNI rules",
	)
}

// Invalid inline policies disappear without withdrawing the Sandbox or other policies.
func TestSandboxPolicyFailuresAreIsolated(t *testing.T) {
	const noTrafficPolicy securityv1.TrafficPolicy_Action = -1
	fixture := newIncrementalFixture(t)
	traffic := func(action agentsv1alpha1.RuleAction) agentsv1alpha1.TrafficPolicySpec {
		return agentsv1alpha1.TrafficPolicySpec{Egress: &agentsv1alpha1.TrafficPolicyDirection{
			Rules: []agentsv1alpha1.TrafficPolicyRule{
				{Action: action, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}}},
			},
		}}
	}
	security := func(domain string) []agentsv1alpha1.SecurityRule {
		return []agentsv1alpha1.SecurityRule{
			{Name: "rule", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{domain}}}},
		}
	}
	sharedTraffic := model.TrafficPolicy{Name: "baseline",
		Global: true,
		Spec:   agentsv1alpha1.TrafficPolicySpec{Egress: traffic(agentsv1alpha1.RuleActionReject).Egress}}
	sharedSNI := model.SecurityProfile{Name: "shared",
		Namespace: "tenant",
		Spec:      agentsv1alpha1.SecurityProfileSpec{Rules: security("shared.example")}}
	fixture.trafficPolicies.ConditionalUpdateObject(sharedTraffic)
	fixture.securityProfiles.ConditionalUpdateObject(sharedSNI)
	config := model.AgentioConfiguration{Value: &configv1.AgentioConfig{
		EgressPolicies: []*extensionsv1.EgressPolicy{{
			Namespaces: []string{"tenant"},
			Policy:     extensionsv1.EgressPolicyAction_GATEWAY,
			Gateway:    &extensionsv1.GatewayAddress{Service: "egress.agentio-system.svc.cluster.local", Port: 15008},
		}},
	}}
	fixture.agentioConfig.ConditionalUpdateObject(config)
	sandbox := model.Sandbox{UID: "isolated",
		Namespace: "tenant",
		State:     model.SandboxStateRunning,
		Attester:  &model.Attester{WorkloadUID: "worker-a"}}
	inlineTraffic := model.TrafficPolicy{Dedicated: true,
		SandboxUID: sandbox.UID,
		Namespace:  sandbox.Namespace,
		Spec:       traffic(agentsv1alpha1.RuleActionAllow)}
	inlineSecurity := model.SecurityProfile{Dedicated: true,
		SandboxUID: sandbox.UID,
		Namespace:  sandbox.Namespace,
		Spec:       agentsv1alpha1.SecurityProfileSpec{Rules: security("first.example")}}
	update := func() {
		if inlineTraffic.Spec.Ingress == nil && inlineTraffic.Spec.Egress == nil {
			fixture.trafficPolicies.DeleteObject(inlineTraffic.ResourceName())
		} else {
			fixture.trafficPolicies.ConditionalUpdateObject(inlineTraffic)
		}
		if inlineSecurity.Spec.Rules == nil {
			fixture.securityProfiles.DeleteObject(inlineSecurity.ResourceName())
		} else {
			fixture.securityProfiles.ConditionalUpdateObject(inlineSecurity)
		}
		fixture.sandboxes.ConditionalUpdateObject(sandbox)
	}
	update()
	waitSynced(t, fixture.compiler)

	await := func(action securityv1.TrafficPolicy_Action, domain string, routing bool) {
		t.Helper()
		eventually(t, func() bool {
			current := manifestAt(t, fixture.compiler, sandbox.UID)
			if current == nil || current.GetAttester().GetWorkloadUid() != sandboxAttesterUID(sandbox) ||
				current.State != sandboxv1.SandboxState(sandbox.State) ||
				!reflect.DeepEqual(
					trafficPolicyRefs(current),
					[]string{"trafficPolicies/baseline"},
				) || (current.EgressRouting != nil) != routing {
				return false
			}
			if action == noTrafficPolicy {
				if current.TrafficPolicy != nil {
					return false
				}
			} else if len(current.GetTrafficPolicy().GetEgress().GetRules()) != 1 || current.TrafficPolicy.Egress.Rules[0].Action != action {
				return false
			}
			hosts := []string{"shared.example"}
			if domain != "" {
				hosts = append([]string{domain}, hosts...)
			}
			if len(current.Extensions) != len(hosts) {
				return false
			}
			for i, host := range hosts {
				sni := new(extensionsv1.SniTrafficPolicy)
				if err := current.Extensions[i].UnmarshalTo(sni); err != nil {
					t.Fatal(err)
				}
				if len(sni.Rules) != 1 || !reflect.DeepEqual(sni.Rules[0].GetMatch().GetSni(), []string{host}) {
					return false
				}
			}
			return true
		}, "runtime metadata and healthy policy updates progress independently")
	}
	await(securityv1.TrafficPolicy_ALLOW, "first.example", true)
	baseline := manifestAt(t, fixture.compiler, sandbox.UID)
	var withdrawn atomic.Int64
	registration := fixture.compiler.Resources().RegisterBatch(func(events []krt.Event[model.Resource]) {
		for _, event := range events {
			if event.Latest().Key != (model.ResourceKey{TypeURL: model.SandboxType, Name: sandbox.UID}) {
				continue
			}
			current := new(sandboxv1.Sandbox)
			if event.New == nil || event.New.Value.UnmarshalTo(current) != nil || len(current.Extensions) == 0 ||
				!reflect.DeepEqual(trafficPolicyRefs(current), []string{"trafficPolicies/baseline"}) ||
				!proto.Equal(current.Extensions[len(current.Extensions)-1], baseline.Extensions[1]) {
				withdrawn.Add(1)
				continue
			}
			// Gateway discovery follows the current routing, including its removal on error.
			if (current.EgressRouting == nil && len(event.New.Facts.Sandbox.GatewayReferences) != 0) ||
				(current.EgressRouting != nil && (!proto.Equal(current.EgressRouting, baseline.EgressRouting) ||
					!reflect.DeepEqual(event.New.Facts.Sandbox.GatewayReferences, []string{"agentio-system/egress"}))) {
				withdrawn.Add(1)
			}
		}
	}, false)
	unregister := sync.OnceFunc(registration.UnregisterHandler)
	t.Cleanup(unregister)
	awaitFailure := func(kind string) {
		t.Helper()
		eventually(
			t,
			func() bool { return fixture.compiler.Failures()[kind] != "" },
			"invalid policy records its own failure",
		)
	}

	inlineSecurity.Spec.Rules = security("*bad.example")
	inlineTraffic.Spec = traffic(agentsv1alpha1.RuleActionReject)
	sandbox.Attester = &model.Attester{WorkloadUID: "worker-b"}
	sandbox.State = model.SandboxStatePaused
	update()
	awaitFailure("SecurityProfile/" + inlineSecurity.ResourceName())
	await(securityv1.TrafficPolicy_DENY, "", true)

	// A source parse error removes its profile input and must not prevent an unbind.
	inlineSecurity.Spec.Rules = security("before-parse-error.example")
	update()
	await(securityv1.TrafficPolicy_DENY, "before-parse-error.example", true)
	inlineSecurity.Spec.Rules = nil
	sandbox.Attester = nil
	update()
	await(securityv1.TrafficPolicy_DENY, "", true)

	inlineSecurity.Spec.Rules = security("second.example")
	inlineTraffic.Spec = traffic("invalid")
	update()
	awaitFailure("TrafficPolicy/" + inlineTraffic.ResourceName())
	await(noTrafficPolicy, "second.example", true)

	// DENY is a legacy EgressPolicy action that cannot be represented as Sandbox routing.
	config.Value = proto.Clone(config.Value).(*configv1.AgentioConfig)
	config.Value.EgressPolicies[0].Policy = extensionsv1.EgressPolicyAction_DENY
	config.Value.EgressPolicies[0].Gateway = nil
	fixture.agentioConfig.ConditionalUpdateObject(config)
	awaitFailure("SandboxEgressPolicy/isolated")
	inlineTraffic.Spec = traffic(agentsv1alpha1.RuleActionAllow)
	inlineSecurity.Spec.Rules = security("third.example")
	sandbox.Attester = &model.Attester{WorkloadUID: "worker-c"}
	sandbox.State = model.SandboxStateRunning
	update()
	await(securityv1.TrafficPolicy_ALLOW, "third.example", false)

	// Shared policy failures also preserve their bodies and selected references.
	sharedSNI.Spec = *sharedSNI.Spec.DeepCopy()
	sharedSNI.Spec.Rules = security("*bad.example")
	fixture.securityProfiles.ConditionalUpdateObject(sharedSNI)
	awaitFailure("SecurityProfile/namespaced/tenant/shared")
	sharedTraffic.Spec = *sharedTraffic.Spec.DeepCopy()
	sharedTraffic.Spec.Egress = traffic("invalid").Egress
	fixture.trafficPolicies.ConditionalUpdateObject(sharedTraffic)
	awaitFailure("TrafficPolicy/global/baseline")
	inlineSecurity.Spec.Rules = security("fourth.example")
	update()
	await(securityv1.TrafficPolicy_ALLOW, "fourth.example", false)
	if shared := trafficPolicyAt(
		t,
		fixture.compiler,
		"trafficPolicies/baseline",
	); len(
		shared.GetEgress().GetRules(),
	) != 1 ||
		shared.Egress.Rules[0].Action != securityv1.TrafficPolicy_DENY {
		t.Fatal("invalid shared update removed the last valid policy")
	}
	config.Value = proto.Clone(config.Value).(*configv1.AgentioConfig)
	config.Value.EgressPolicies[0].Policy = extensionsv1.EgressPolicyAction_GATEWAY
	config.Value.EgressPolicies[0].Gateway = &extensionsv1.GatewayAddress{
		Service: "egress.agentio-system.svc.cluster.local",
		Port:    15008,
	}
	fixture.agentioConfig.ConditionalUpdateObject(config)
	await(securityv1.TrafficPolicy_ALLOW, "fourth.example", true)
	eventually(
		t,
		func() bool { return fixture.compiler.Failures()["SandboxEgressPolicy/isolated"] == "" },
		"corrected routing clears the failure",
	)
	settle()
	if withdrawn.Load() != 0 {
		t.Fatalf("invalid updates published %d Sandbox withdrawals or removed unrelated policies", withdrawn.Load())
	}
	unregister()

	// Explicit removals still work even after failed updates.
	inlineTraffic.Spec = agentsv1alpha1.TrafficPolicySpec{}
	inlineSecurity.Spec.Rules = nil
	update()
	fixture.trafficPolicies.DeleteObject(sharedTraffic.ResourceName())
	fixture.securityProfiles.DeleteObject(sharedSNI.ResourceName())
	fixture.agentioConfig.DeleteObject(config.ResourceName())
	eventually(t, func() bool {
		current := manifestAt(t, fixture.compiler, sandbox.UID)
		return current != nil && current.TrafficPolicy == nil && len(current.Extensions) == 0 &&
			len(
				trafficPolicyRefs(current),
			) == 0 && current.EgressRouting == nil && len(fixture.compiler.Failures()) == 0
	}, "explicit policy deletion removes policies and diagnostics")
	inlineSecurity.Spec.Rules = security("*bad.example")
	update()
	awaitFailure("SecurityProfile/" + inlineSecurity.ResourceName())
	fixture.sandboxes.DeleteObject(sandbox.UID)
	fixture.securityProfiles.DeleteObject(inlineSecurity.ResourceName())
	fixture.trafficPolicies.DeleteObject(inlineTraffic.ResourceName())
	eventually(t, func() bool {
		return manifestAt(t, fixture.compiler, sandbox.UID) == nil && len(fixture.compiler.Failures()) == 0
	}, "Sandbox deletion removes policies and diagnostics")
}

func sandboxAttesterUID(sandbox model.Sandbox) string {
	if sandbox.Attester == nil {
		return ""
	}
	return sandbox.Attester.WorkloadUID
}

func TestSandboxSharedPoliciesWithoutWorkerAndBodyUpdate(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(
		model.Sandbox{UID: "a", Namespace: "tenant", Labels: map[string]string{"app": "a"}},
	)
	fixture.sandboxes.ConditionalUpdateObject(
		model.Sandbox{UID: "b", Namespace: "tenant", Labels: map[string]string{"app": "b"}},
	)
	policy := model.TrafficPolicy{
		Name:      "allow",
		Namespace: "tenant",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: []agentsv1alpha1.TrafficPolicyRule{
					{
						Action: agentsv1alpha1.RuleActionAllow,
						To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
					},
				},
			},
		},
	}
	fixture.trafficPolicies.ConditionalUpdateObject(policy)
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		a, b := manifestAt(t, fixture.compiler, "a"), manifestAt(t, fixture.compiler, "b")
		return a != nil &&
			reflect.DeepEqual(trafficPolicyRefs(a), []string{"namespaces/tenant/trafficPolicies/allow"}) &&
			a.TrafficPolicy == nil &&
			b != nil &&
			len(trafficPolicyRefs(b)) == 0 &&
			trafficPolicyAt(t, fixture.compiler, "namespaces/tenant/trafficPolicies/allow") != nil
	}, "paused Sandbox manifests compiled independently")
	first := trafficPolicyAt(t, fixture.compiler, "namespaces/tenant/trafficPolicies/allow")
	if len(currentSnapshot(t, fixture.compiler).List(model.WorkloadAuthorizationType)) != 0 {
		t.Fatal("unbound Sandboxes emitted legacy Authorization")
	}
	worker := testWorkload("workers", "worker", "10.1.0.1")
	for _, uid := range []string{"a", "b"} {
		sandbox := *fixture.sandboxes.GetKey(uid)
		sandbox.Attester = &model.Attester{WorkloadUID: worker.UID}
		fixture.sandboxes.ConditionalUpdateObject(sandbox)
	}
	fixture.workloads.ConditionalUpdateObject(worker)
	eventually(t, func() bool {
		_, ok := currentSnapshot(
			t,
			fixture.compiler,
		).Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
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
	want := []string{model.TrafficPolicyType + "|namespaces/tenant/trafficPolicies/allow"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("changed resources %v, want %v", names, want)
	}
}

func TestMultiSandboxFailureDeletionAndShrinkRetainNetworking(t *testing.T) {
	fixture := newIncrementalFixture(t)
	a := model.Sandbox{UID: "actor-a", Namespace: "tenant"}
	b := model.Sandbox{
		UID:        "actor-b",
		Namespace:  "tenant",
		PolicyRefs: []model.PolicyRef{{Kind: model.PolicyKindSNIPolicy, Name: "missing"}},
	}
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
		return ma != nil && mb != nil && mb.GetAttester().GetWorkloadUid() == worker.UID && len(mb.Extensions) == 0
	}, "unresolved policy does not remove Sandbox identity")
	a.Attester = nil
	fixture.sandboxes.ConditionalUpdateObject(a)
	fixture.workloads.ConditionalUpdateObject(worker)
	eventually(t, func() bool {
		r, ok := currentSnapshot(
			t,
			fixture.compiler,
		).Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
		return ok && r.Facts.Workload != nil && manifestAt(t, fixture.compiler, b.UID) != nil
	}, "unresolved policy does not remove networking")
	fixture.sandboxes.DeleteObject(b.UID)
	eventually(
		t,
		func() bool { return manifestAt(t, fixture.compiler, b.UID) == nil },
		"deleted actor must not become an implicit Pod Sandbox",
	)
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
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Sandbox/ "]
		return !failed
	}, "removed malformed UID clears diagnostic")
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
	global := model.TrafficPolicy{
		Name:   "baseline",
		Global: true,
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: 10,
			Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: []agentsv1alpha1.TrafficPolicyRule{
					{
						Action: agentsv1alpha1.RuleActionReject,
						To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}},
					},
				},
			},
		},
	}
	local := model.TrafficPolicy{
		Name:      "local",
		Namespace: "tenant",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: 100,
			Ingress:  &agentsv1alpha1.TrafficPolicyDirection{},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: []agentsv1alpha1.TrafficPolicyRule{
					{
						Action: agentsv1alpha1.RuleActionAllow,
						To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}},
					},
				},
			},
		},
	}
	fixture.trafficPolicies.ConditionalUpdateObject(global)
	fixture.trafficPolicies.ConditionalUpdateObject(local)
	profile := func(name, domain string) model.SecurityProfile {
		return model.SecurityProfile{
			Name:      name,
			Namespace: "tenant",
			Spec: agentsv1alpha1.SecurityProfileSpec{
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{"not": "selected"}},
				Rules: []agentsv1alpha1.SecurityRule{
					{Name: "rule", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{domain}}}},
				},
			},
		}
	}
	first, second := profile("first", "first.example"), profile("second", "second.example")
	fixture.securityProfiles.ConditionalUpdateObject(first)
	fixture.securityProfiles.ConditionalUpdateObject(second)
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		a, b := manifestAt(t, fixture.compiler, "a"), manifestAt(t, fixture.compiler, "b")
		return a != nil && len(trafficPolicyRefs(a)) == 2 && len(a.Extensions) == 2 && b != nil &&
			len(trafficPolicyRefs(b)) == 1
	}, "inline global/local policies and explicit SNI order")
	a := manifestAt(t, fixture.compiler, "a")
	if a.TrafficPolicy != nil ||
		!reflect.DeepEqual(
			trafficPolicyRefs(a),
			[]string{"trafficPolicies/baseline", "namespaces/tenant/trafficPolicies/local"},
		) {
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
			reflect.DeepEqual(
				trafficPolicyRefs(a),
				[]string{"namespaces/tenant/trafficPolicies/local", "trafficPolicies/baseline"},
			)
	}, "lower numeric priority moves the local policy ahead of the global policy")
	local.Spec.Priority = global.Spec.Priority
	fixture.trafficPolicies.ConditionalUpdateObject(local)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && len(trafficPolicyRefs(a)) == 2 &&
			reflect.DeepEqual(
				trafficPolicyRefs(a),
				[]string{"trafficPolicies/baseline", "namespaces/tenant/trafficPolicies/local"},
			)
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
		return a != nil && len(a.Extensions) == 1 && sniAt(a, 0).Rules[0].Match.Sni[0] == "first.example" &&
			len(trafficPolicyRefs(a)) == 2
	}, "deleting one explicit policy preserves the remaining policies")
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
	sandboxes.UpdateObject(
		model.Sandbox{
			UID:       workload.UID,
			Namespace: "sandbox-namespace",
			Labels:    map[string]string{"source": "sandbox"},
		},
	)
	eventually(t, func() bool { return manifestAt(t, compiler, workload.UID) != nil }, "provider Sandbox appears")
	sandboxes.DeleteObject(workload.UID)
	eventually(t, func() bool {
		return manifestAt(t, compiler, workload.UID) == nil && compiler.Bindings().GetKey(workload.UID) == nil
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
		binding := fixture.compiler.Bindings().GetKey(sandbox.UID)
		return binding != nil && reflect.DeepEqual(
			binding.PolicyNames(policy.PolicyKindTrafficPolicy),
			[]string{"namespaces/sandbox-namespace/trafficPolicies/allow"},
		)
	}, "explicit Sandbox namespace and labels select policy")

	sandbox.Labels = map[string]string{"app": "other"}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	eventually(t, func() bool {
		binding := fixture.compiler.Bindings().GetKey(sandbox.UID)
		return binding != nil && binding.Valid() && len(binding.PolicyNames(policy.PolicyKindTrafficPolicy)) == 0
	}, "Sandbox label update removes selector-derived binding")
}

func TestSandboxTrafficPolicyUsesUnifiedInputs(t *testing.T) {
	fixture := newIncrementalFixture(t)
	sandbox := model.Sandbox{UID: "a", Namespace: "tenant"}
	inline := model.TrafficPolicy{
		Dedicated:  true,
		SandboxUID: sandbox.UID,
		Namespace:  sandbox.Namespace,
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Ingress: &agentsv1alpha1.TrafficPolicyDirection{},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "192.0.2.0/24"}},
			}}},
		},
	}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	fixture.trafficPolicies.ConditionalUpdateObject(inline)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "b", Namespace: "tenant"})
	shared := model.TrafficPolicy{Name: "global",
		Global: true,
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: 0,
			Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: []agentsv1alpha1.TrafficPolicyRule{
					{
						Action: agentsv1alpha1.RuleActionReject,
						To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}},
					},
				},
			},
		}}
	fixture.trafficPolicies.ConditionalUpdateObject(shared)
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		a, b := manifestAt(t, fixture.compiler, "a"), manifestAt(t, fixture.compiler, "b")
		return a != nil && len(a.GetTrafficPolicy().GetEgress().GetRules()) == 1 && b != nil &&
			b.TrafficPolicy == nil &&
			reflect.DeepEqual(trafficPolicyRefs(a), []string{"trafficPolicies/global"}) &&
			reflect.DeepEqual(trafficPolicyRefs(b), []string{"trafficPolicies/global"})
	}, "direct Sandbox rules coexist with shared references")
	a := manifestAt(t, fixture.compiler, "a")
	if a.TrafficPolicy.Ingress != nil ||
		a.TrafficPolicy.Egress.Rules[0].Action != securityv1.TrafficPolicy_ALLOW {
		t.Fatalf("inline directions or action lost: %v", a.TrafficPolicy)
	}
	if got := fixture.compiler.Bindings().
		GetKey("a").
		PolicyNames(model.PolicyKindTrafficPolicy); !reflect.DeepEqual(
		got,
		[]string{"trafficPolicies/global"},
	) {
		t.Fatalf("inline policy entered the shared binding graph: %v", got)
	}
	if got := currentSnapshot(t, fixture.compiler).List(model.TrafficPolicyType); len(got) != 1 {
		t.Fatalf("inline policy produced an independent xDS resource: %v", got)
	}
	other := manifestAt(t, fixture.compiler, "b")

	inline.Spec = agentsv1alpha1.TrafficPolicySpec{Egress: inline.Spec.Egress.DeepCopy()}
	inline.Spec.Egress.Rules[0].Action = agentsv1alpha1.RuleActionReject
	fixture.trafficPolicies.ConditionalUpdateObject(inline)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return len(a.GetTrafficPolicy().GetEgress().GetRules()) == 1 &&
			a.TrafficPolicy.Egress.Rules[0].Action == securityv1.TrafficPolicy_DENY &&
			a.TrafficPolicy.Ingress == nil
	}, "owned policy update changes its Sandbox body")

	invalid := inline
	invalid.Spec = agentsv1alpha1.TrafficPolicySpec{Egress: inline.Spec.Egress.DeepCopy()}
	invalid.Spec.Egress.Rules = append(invalid.Spec.Egress.Rules, agentsv1alpha1.TrafficPolicyRule{
		Action: "invalid",
		To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}},
	})
	fixture.trafficPolicies.ConditionalUpdateObject(invalid)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && a.TrafficPolicy == nil &&
			reflect.DeepEqual(trafficPolicyRefs(a), []string{"trafficPolicies/global"}) &&
			fixture.compiler.Failures()["TrafficPolicy/"+inline.ResourceName()] != ""
	}, "invalid inline rules are omitted without removing shared policies")

	inline.Spec = agentsv1alpha1.TrafficPolicySpec{Egress: &agentsv1alpha1.TrafficPolicyDirection{}}
	fixture.trafficPolicies.ConditionalUpdateObject(inline)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && a.TrafficPolicy != nil && a.TrafficPolicy.Egress == nil &&
			fixture.compiler.Failures()["TrafficPolicy/"+inline.ResourceName()] == ""
	}, "empty source direction stops enforcement after recovery")

	fixture.trafficPolicies.DeleteObject(inline.ResourceName())
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && a.TrafficPolicy == nil &&
			reflect.DeepEqual(trafficPolicyRefs(a), []string{"trafficPolicies/global"})
	}, "inline removal preserves shared references")
	if !proto.Equal(other, manifestAt(t, fixture.compiler, "b")) {
		t.Fatal("inline changes affected an unrelated Sandbox")
	}
}

func TestSandboxTrafficPolicyTracksPeerUpdates(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.setResolved("api.example.com", netip.MustParseAddr("192.0.2.1"))
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "a", Namespace: "tenant"})
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Dedicated:  true,
		SandboxUID: "a",
		Namespace:  "tenant",
		Spec: agentsv1alpha1.TrafficPolicySpec{
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
	calls := fixture.resolutionCount("api.example.com")
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "a",
		Namespace: "tenant",
		State:     model.SandboxStatePending,
		Attester:  &model.Attester{WorkloadUID: "new-worker"}})
	eventually(t, func() bool {
		return manifestAt(t, fixture.compiler, "a").GetAttester().GetWorkloadUid() == "new-worker"
	}, "runtime binding advances independently of policy compilation")
	if got := fixture.resolutionCount("api.example.com"); got != calls {
		t.Fatalf("runtime-only update repeated peer resolution: %d -> %d", calls, got)
	}
	fixture.setResolved("api.example.com", netip.MustParseAddr("192.0.2.2"))
	awaitAddress(2)
}
