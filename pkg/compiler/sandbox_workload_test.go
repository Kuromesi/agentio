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
	"net/netip"
	"slices"
	"strings"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func compatibilityWorkload(
	t *testing.T,
	snapshot model.ResourceSet,
	uid string,
) (*workloadv1.Workload, model.Resource) {
	t.Helper()
	r, ok := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: uid})
	if !ok {
		return nil, model.Resource{}
	}
	a := &workloadv1.Address{}
	if err := r.Value.UnmarshalTo(a); err != nil {
		t.Fatal(err)
	}
	return a.GetWorkload(), r
}

func compatibilityExtension(t *testing.T, workload *workloadv1.Workload, name string, out proto.Message) bool {
	t.Helper()
	for _, ext := range workload.GetExtensions() {
		if ext.Name == name {
			if err := ext.Config.UnmarshalTo(out); err != nil {
				t.Fatal(err)
			}
			return true
		}
	}
	return false
}

func compatibilityTraffic(
	action agentsv1alpha1.RuleAction,
	peer agentsv1alpha1.TrafficPolicyPeer,
) agentsv1alpha1.TrafficPolicySpec {
	return agentsv1alpha1.TrafficPolicySpec{Egress: &agentsv1alpha1.TrafficPolicyDirection{
		Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: action, To: []agentsv1alpha1.TrafficPolicyPeer{peer}}},
	}}
}

func compatibilitySecurity(domain string) agentsv1alpha1.SecurityProfileSpec {
	return agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{
		Name:  "https",
		Match: []agentsv1alpha1.RuleMatch{{Domains: []string{domain}}},
	}}}
}

func TestSandboxWorkloadCompatibilityModes(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%v", native), func(t *testing.T) {
			f := newIncrementalFixture(t, func(i *Inputs) { i.NativeSandboxPolicies = native })
			host := testWorkload("demo", "pool", "10.0.0.1")
			ordinary := testWorkload("demo", "ordinary", "10.0.0.2")
			f.workloads.UpdateObject(host)
			f.workloads.UpdateObject(ordinary)
			sandbox := model.Sandbox{
				UID:       "actor",
				Namespace: "demo",
				Labels:    map[string]string{"app": "actor"},
				Attester:  &model.Attester{WorkloadUID: host.UID},
			}
			f.sandboxes.UpdateObject(sandbox)
			f.trafficPolicies.UpdateObject(model.TrafficPolicy{
				Dedicated:  true,
				SandboxUID: sandbox.UID,
				Namespace:  "demo",
				Spec: compatibilityTraffic(
					agentsv1alpha1.RuleActionAllow,
					agentsv1alpha1.TrafficPolicyPeer{CIDR: "192.0.2.0/24"},
				),
			})
			f.trafficPolicies.UpdateObject(model.TrafficPolicy{
				Name:   "baseline",
				Global: true,
				Spec: compatibilityTraffic(
					agentsv1alpha1.RuleActionReject,
					agentsv1alpha1.TrafficPolicyPeer{CIDR: "203.0.113.0/24"},
				),
			})
			selected := model.TrafficPolicy{
				Name:      "selected",
				Namespace: "demo",
				Spec: compatibilityTraffic(
					agentsv1alpha1.RuleActionAllow,
					agentsv1alpha1.TrafficPolicyPeer{CIDR: "198.51.100.0/24"},
				),
			}
			selected.Spec.Priority = 10
			selected.Spec.Selector = metav1.LabelSelector{MatchLabels: sandbox.Labels}
			f.trafficPolicies.UpdateObject(selected)
			f.securityProfiles.UpdateObject(
				model.SecurityProfile{
					Dedicated:  true,
					SandboxUID: sandbox.UID,
					Namespace:  "demo",
					Spec:       compatibilitySecurity("dedicated.example"),
				},
			)
			profile := model.SecurityProfile{
				Name:      "shared",
				Namespace: "demo",
				Spec:      compatibilitySecurity("shared.example"),
			}
			profile.Spec.Selector = selected.Spec.Selector
			f.securityProfiles.UpdateObject(profile)
			f.agentioConfig.UpdateObject(
				model.AgentioConfiguration{Value: &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{
					{
						Namespaces: []string{"demo"},
						Policy:     extensionsv1.EgressPolicyAction_GATEWAY,
						Gateway: &extensionsv1.GatewayAddress{
							Service: "egress.agentio-system.svc.cluster.local",
							Port:    15008,
						},
					},
				}}},
			)
			var snapshot model.ResourceSet
			eventually(t, func() bool {
				snapshot = currentSnapshot(t, f.compiler)
				m := manifestAt(t, f.compiler, "actor")
				w, _ := compatibilityWorkload(t, snapshot, host.UID)
				if m == nil || m.TrafficPolicy == nil || len(m.Extensions) != 2 || len(trafficPolicyRefs(m)) != 2 ||
					len(m.GetEgressRouting().GetRoutes()) != 1 ||
					w == nil {
					return false
				}
				if native {
					return true
				}
				sni := &extensionsv1.SniTrafficPolicy{}
				if len(w.AuthorizationPolicies) != 2 || !compatibilityExtension(t, w, "sni-traffic-policy", sni) ||
					len(sni.Rules) != 2 ||
					len(snapshot.List(model.SniTrafficPolicyType)) != 0 {
					return false
				}
				r, ok := snapshot.Get(
					model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: w.AuthorizationPolicies[0]},
				)
				auth := &securityv1.Authorization{}
				return ok && proto.Unmarshal(r.Value.Value, auth) == nil && len(auth.Groups) == 1
			}, "both policy representations converge")
			w, _ := compatibilityWorkload(t, snapshot, host.UID)
			visible := snapshot.HasWorkload(
				model.AddressType,
				model.WorkloadQuery{WorkloadUID: host.UID, AuthorizationRefsOnly: true},
			)
			if visible == native {
				t.Fatalf("Workload policy visibility = %v, native = %v", visible, native)
			}
			if native {
				if len(w.AuthorizationPolicies) != 0 || len(w.Extensions) != 1 ||
					len(snapshot.List(model.SniTrafficPolicyType)) != 0 {
					t.Fatalf("native-only mode emitted compatibility: %v", w)
				}
				return
			}
			if compatibilityExtension(t, w, "traffic-policy-reference", &extensionsv1.PolicyReference{}) ||
				len(snapshot.List(model.TrafficPolicyType)) != 2 {
				t.Fatal("compatibility added native Workload fallback resources")
			}
			for _, name := range w.AuthorizationPolicies {
				r, ok := snapshot.Get(model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: name})
				if !ok {
					t.Fatalf("missing legacy authorization %s", name)
				}
				auth := &securityv1.Authorization{}
				if err := proto.Unmarshal(r.Value.Value, auth); err != nil {
					t.Fatal(err)
				}
				ext := &extensionsv1.TrafficPolicyExtension{}
				if err := auth.AuthExtensions[0].Config.UnmarshalTo(ext); err != nil {
					t.Fatal(err)
				}
				wantPriority := int32(-1)
				if name == "demo/selected-egress" {
					wantPriority = 10
				}
				if auth.Scope != securityv1.Scope_WORKLOAD_SELECTOR || ext.Priority != wantPriority ||
					ext.Mode != extensionsv1.TrafficPolicyMode_CLIENT ||
					len(auth.Groups) != 1 {
					t.Fatalf("independent authorization = %v, extension = %v", auth, ext)
				}
			}
			sni := &extensionsv1.SniTrafficPolicy{}
			if !compatibilityExtension(t, w, "sni-traffic-policy", sni) || len(sni.Rules) != 2 ||
				sni.Rules[0].Match.Sni[0] != "dedicated.example" ||
				sni.Rules[1].Match.Sni[0] != "shared.example" {
				t.Fatalf("SNI order = %v", sni)
			}
			if compatibilityExtension(t, w, "sni-policy-reference", &extensionsv1.PolicyReference{}) {
				t.Fatal("compatibility introduced a new SNI delivery protocol")
			}
			egress := &extensionsv1.EgressPolicies{}
			if !compatibilityExtension(t, w, "egress-policies", egress) || len(egress.EgressPolicies) != 1 ||
				egress.EgressPolicies[0].Gateway.Port != 15008 {
				t.Fatalf("egress = %v", egress)
			}
			normal, _ := compatibilityWorkload(t, snapshot, ordinary.UID)
			for _, name := range normal.AuthorizationPolicies {
				if slices.Contains(w.AuthorizationPolicies, name) {
					t.Fatalf("compatibility leaked to ordinary Workload: %v", normal)
				}
			}
			if compatibilityExtension(t, normal, "sni-traffic-policy", &extensionsv1.SniTrafficPolicy{}) {
				t.Fatal("Sandbox selector was rebound to an ordinary Workload")
			}
		})
	}
}

func TestSandboxCompatibilityLifecycleAndFailureIsolation(t *testing.T) {
	f := newIncrementalFixture(t, func(i *Inputs) { i.NativeSandboxPolicies = false })
	a, b := testWorkload("demo", "a", "10.0.0.1"), testWorkload("demo", "b", "10.0.0.2")
	f.workloads.UpdateObject(a)
	f.workloads.UpdateObject(b)
	s := model.Sandbox{UID: "actor", Namespace: "demo", Attester: &model.Attester{WorkloadUID: a.UID}}
	f.sandboxes.UpdateObject(s)
	f.setResolved("api.example", netip.MustParseAddr("192.0.2.1"))
	shared := model.TrafficPolicy{
		Name:      "shared",
		Namespace: "demo",
		Spec: compatibilityTraffic(
			agentsv1alpha1.RuleActionAllow,
			agentsv1alpha1.TrafficPolicyPeer{FQDN: "api.example"},
		),
	}
	shared.Spec.Selector = metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "missing", Operator: metav1.LabelSelectorOpDoesNotExist},
		},
	}
	f.trafficPolicies.UpdateObject(shared)
	security := model.SecurityProfile{
		Dedicated:  true,
		SandboxUID: s.UID,
		Namespace:  "demo",
		Spec:       compatibilitySecurity("first.example"),
	}
	f.securityProfiles.UpdateObject(security)
	await := func(uid string, sniCount int) model.ResourceSet {
		t.Helper()
		var snap model.ResourceSet
		eventually(t, func() bool {
			snap = currentSnapshot(t, f.compiler)
			w, _ := compatibilityWorkload(t, snap, uid)
			sni := &extensionsv1.SniTrafficPolicy{}
			compatibilityExtension(t, w, "sni-traffic-policy", sni)
			return len(w.GetAuthorizationPolicies()) == 1 && len(sni.Rules) == sniCount &&
				len(snap.List(model.SniTrafficPolicyType)) == 0
		}, "compatibility follows binding")
		return snap
	}
	initial := await(a.UID, 1)
	m, _ := initial.Get(model.ResourceKey{TypeURL: model.SandboxType, Name: s.UID})
	wa, waResource := compatibilityWorkload(t, initial, a.UID)
	authKey := model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: wa.AuthorizationPolicies[0]}
	auth, _ := initial.Get(authKey)
	settle()
	calls := f.resolutionCount("api.example")
	shared.Spec = *shared.Spec.DeepCopy()
	shared.Spec.Egress.Rules[0].Action = agentsv1alpha1.RuleActionReject
	f.trafficPolicies.UpdateObject(shared)
	eventually(t, func() bool {
		r, ok := currentSnapshot(t, f.compiler).Get(authKey)
		return ok && r.Hash != auth.Hash
	}, "shared body updates compatibility")
	current := currentSnapshot(t, f.compiler)
	newManifest, _ := current.Get(m.Key)
	_, newWorkload := compatibilityWorkload(t, current, a.UID)
	if newManifest.Hash != m.Hash || newWorkload.Hash != waResource.Hash {
		t.Fatal("body-only update republished Sandbox or Workload references")
	}
	if got := f.resolutionCount("api.example") - calls; got != 1 {
		t.Fatalf("policy was re-resolved during projection: %d calls", got)
	}
	security.Spec = compatibilitySecurity("*bad.example")
	f.securityProfiles.UpdateObject(security)
	await(a.UID, 0)
	if manifestAt(t, f.compiler, s.UID) == nil {
		t.Fatal("SNI failure removed Sandbox")
	}
	if _, ok := currentSnapshot(t, f.compiler).Get(authKey); !ok {
		t.Fatal("SNI failure removed TrafficPolicy compatibility")
	}
	security.Spec = compatibilitySecurity("restored.example")
	f.securityProfiles.UpdateObject(security)
	await(a.UID, 1)
	s.Attester = &model.Attester{WorkloadUID: b.UID}
	f.sandboxes.UpdateObject(s)
	await(b.UID, 1)
	eventually(t, func() bool {
		snap := currentSnapshot(t, f.compiler)
		w, _ := compatibilityWorkload(t, snap, a.UID)
		_, authExists := snap.Get(authKey)
		sniExists := compatibilityExtension(t, w, "sni-traffic-policy", &extensionsv1.SniTrafficPolicy{})
		return len(w.GetAuthorizationPolicies()) == 0 && authExists && !sniExists
	}, "move withdraws old owner's compatibility")
	s.Attester = nil
	f.sandboxes.UpdateObject(s)
	eventually(t, func() bool {
		w, _ := compatibilityWorkload(t, currentSnapshot(t, f.compiler), b.UID)
		return len(w.GetAuthorizationPolicies()) == 0
	}, "unbind withdraws references")
	s.Attester = &model.Attester{WorkloadUID: b.UID}
	f.sandboxes.UpdateObject(s)
	await(b.UID, 1)
	f.sandboxes.DeleteObject(s.UID)
	eventually(t, func() bool {
		snap := currentSnapshot(t, f.compiler)
		w, _ := compatibilityWorkload(t, snap, b.UID)
		for _, r := range snap.List(model.WorkloadAuthorizationType) {
			if strings.Contains(r.Key.Name, "/sandbox-") {
				return false
			}
		}
		return len(w.GetAuthorizationPolicies()) == 0 && len(snap.List(model.SniTrafficPolicyType)) == 0
	}, "delete removes generated policies")
}

func TestSandboxCompatibilityReportsAmbiguousWorkload(t *testing.T) {
	f := newIncrementalFixture(t, func(i *Inputs) { i.NativeSandboxPolicies = false })
	host := testWorkload("demo", "pool", "10.0.0.1")
	f.workloads.UpdateObject(host)
	for _, uid := range []string{"a", "b"} {
		f.sandboxes.UpdateObject(
			model.Sandbox{UID: uid, Namespace: "demo", Attester: &model.Attester{WorkloadUID: host.UID}},
		)
	}
	eventually(t, func() bool {
		snapshot := currentSnapshot(t, f.compiler)
		w, _ := compatibilityWorkload(t, snapshot, host.UID)
		if w == nil || len(snapshot.List(model.SandboxType)) != 2 || len(w.GetAuthorizationPolicies()) != 0 {
			return false
		}
		return len(snapshot.List(model.WorkloadAuthorizationType)) == 0 && len(f.compiler.Failures()) > 0
	}, "ambiguous binding is reported without generating policies")
	f.sandboxes.DeleteObject("b")
	eventually(t, func() bool {
		w, _ := compatibilityWorkload(t, currentSnapshot(t, f.compiler), host.UID)
		return !compatibilityExtension(t, w, "traffic-policy-reference", &extensionsv1.PolicyReference{}) &&
			len(f.compiler.Failures()) == 0
	}, "single binding recovers")
}

// Shared policy rules must not be copied into one Authorization per Workload.
func TestLegacyTrafficPolicySharedAcrossWorkloads(t *testing.T) {
	f := newIncrementalFixture(t, func(i *Inputs) { i.NativeSandboxPolicies = false })
	const count = 16
	var workloads []model.Workload
	for i := range count {
		w := testWorkload("demo", fmt.Sprintf("client-%d", i), fmt.Sprintf("10.0.0.%d", i+1))
		w.Labels = map[string]string{"app": "client"}
		workloads = append(workloads, w)
		f.workloads.UpdateObject(w)
		f.sandboxes.UpdateObject(testSandboxForWorkload(w))
	}
	spec := compatibilityTraffic(agentsv1alpha1.RuleActionAllow, agentsv1alpha1.TrafficPolicyPeer{CIDR: "192.0.2.0/24"})
	f.trafficPolicies.UpdateObject(model.TrafficPolicy{Name: "global", Global: true, Spec: spec})
	f.trafficPolicies.UpdateObject(model.TrafficPolicy{Name: "namespace", Namespace: "demo", Spec: spec})
	selected := model.TrafficPolicy{Name: "selected", Namespace: "demo", Spec: *spec.DeepCopy()}
	selected.Spec.Selector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}
	f.trafficPolicies.UpdateObject(selected)
	var before model.ResourceSet
	eventually(t, func() bool {
		before = currentSnapshot(t, f.compiler)
		if len(before.List(model.WorkloadAuthorizationType)) != 3 {
			return false
		}
		for _, w := range workloads {
			wire, _ := compatibilityWorkload(t, before, w.UID)
			if !slices.Equal(wire.GetAuthorizationPolicies(), []string{"demo/selected-egress"}) {
				return false
			}
		}
		return true
	}, "all Workloads reference the same shared policy")
	key := model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: "demo/selected-egress"}
	old, _ := before.Get(key)
	selected.Spec = *selected.Spec.DeepCopy()
	selected.Spec.Egress.Rules[0].Action = agentsv1alpha1.RuleActionReject
	f.trafficPolicies.UpdateObject(selected)
	eventually(t, func() bool {
		r, found := currentSnapshot(t, f.compiler).Get(key)
		return found && r.Hash != old.Hash
	}, "body update replaces the one shared Authorization")
	settle()
	after := currentSnapshot(t, f.compiler)
	for _, w := range workloads {
		_, a := compatibilityWorkload(t, before, w.UID)
		_, b := compatibilityWorkload(t, after, w.UID)
		if a.Hash != b.Hash {
			t.Fatal("shared body update changed Workload references")
		}
	}
	f.trafficPolicies.DeleteObject(selected.ResourceName())
	eventually(t, func() bool {
		snapshot := currentSnapshot(t, f.compiler)
		if len(snapshot.List(model.WorkloadAuthorizationType)) != 2 {
			return false
		}
		for _, w := range workloads {
			wire, _ := compatibilityWorkload(t, snapshot, w.UID)
			if len(wire.GetAuthorizationPolicies()) != 0 {
				return false
			}
		}
		return true
	}, "deletion withdraws selector policy while retaining baselines")
}
