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

package policy

import (
	"slices"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestTrafficPolicyBindingsPriorityCreationTimeOrder(t *testing.T) {
	const rootNamespace = "agentio-system"
	inputs := testTrafficPolicyInputs(rootNamespace, nil, nil, nil, nil)
	// Arrival order, selector specificity, and AIP-122 prefixes must not override
	// priority -> creation time -> source namespace -> source name.
	sources := []model.TrafficPolicy{
		{Name: "z-local", Namespace: "tenant", CreationTime: time.Unix(200, 0), Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: 20, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
		}},
		{Name: "z-global", Global: true, CreationTime: time.Unix(200, 0), Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 20}},
		{Name: "a-local", Namespace: "tenant", CreationTime: time.Unix(200, 0), Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 20}},
		{Name: "z-root", Namespace: rootNamespace, CreationTime: time.Unix(200, 0), Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 20}},
		{Name: "a-global", Global: true, CreationTime: time.Unix(200, 0), Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 20}},
		{Name: "z-old-local", Namespace: "tenant", CreationTime: time.Unix(100, 0), Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 20}},
		{Name: "z-old-global", Global: true, CreationTime: time.Unix(100, 0), Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 20}},
		{Name: "priority-first", Namespace: "tenant", CreationTime: time.Unix(300, 0), Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 10}},
	}
	var attachments []PolicyAttachment
	for _, source := range sources {
		compiled, err := CompileTrafficPolicy(krt.TestingDummyContext{}, source, inputs)
		if err != nil {
			t.Fatal(err)
		}
		attachments = append(attachments, *compiled.Attachment)
	}
	stop := t.Context().Done()
	options := []krt.CollectionOption{krt.WithStop(stop)}
	bindings := NewPolicyBindingsCollection(
		krt.NewStaticCollection(nil, []model.Sandbox{{
			UID: "sandbox", Namespace: "tenant", Labels: map[string]string{"app": "client"},
		}}, options...),
		krt.NewStaticCollection(nil, attachments, options...),
		krt.NewOptionsBuilder(stop, "traffic-policy-order", nil),
	)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("policy bindings did not sync")
	}
	want := []string{
		"namespaces/tenant/trafficPolicies/priority-first",
		"trafficPolicies/z-old-global",
		"namespaces/tenant/trafficPolicies/z-old-local",
		"trafficPolicies/a-global",
		"trafficPolicies/z-global",
		"namespaces/agentio-system/trafficPolicies/z-root",
		"namespaces/tenant/trafficPolicies/a-local",
		"namespaces/tenant/trafficPolicies/z-local",
	}
	binding := bindings.GetKey("sandbox")
	if binding == nil || !binding.Valid() {
		t.Fatalf("Sandbox has no valid binding: %+v", binding)
	}
	if got := binding.PolicyNames(PolicyKindTrafficPolicy); !slices.Equal(got, want) {
		t.Fatalf("Sandbox TrafficPolicy order = %v, want %v", got, want)
	}
}

func TestNativeTrafficPolicyPreservesActionsAndSkipsEmptyDirection(t *testing.T) {
	source := model.TrafficPolicy{
		Name:      "p",
		Namespace: "tenant",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Ingress: &agentsv1alpha1.TrafficPolicyDirection{},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{
				{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/8"}}},
				{Action: agentsv1alpha1.RuleActionReject, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}}},
			}},
		},
	}
	compiled, err := CompileTrafficPolicy(krt.TestingDummyContext{}, source, testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	p := compiled.Policy
	if p.Ingress != nil || len(p.Egress.Rules) != 2 {
		t.Fatalf("directions: %v", p)
	}
	if p.Egress.Rules[0].Action != securityv1.TrafficPolicy_ALLOW || len(p.Egress.Rules[0].Match.DestinationIps) != 1 {
		t.Fatal("allow rule lost address constraint")
	}
	deny := p.Egress.Rules[1]
	if deny.Action != securityv1.TrafficPolicy_DENY || len(deny.GetMatch().GetDestinationIps()) != 1 || deny.Match.DestinationIps[0].Length != 0 {
		t.Fatal("explicit reject-all lost its action or CIDR")
	}
	if compiled.Attachment == nil {
		t.Fatal("namespace baseline must have an attachment")
	}
}

func TestTrafficPolicyEmptyPeerSemantics(t *testing.T) {
	inputs := testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil)
	for _, ingress := range []bool{false, true} {
		for _, action := range []agentsv1alpha1.RuleAction{agentsv1alpha1.RuleActionAllow, agentsv1alpha1.RuleActionReject} {
			for _, name := range []string{"absent", "empty", "peerless", "ports-only", "opposite-peer", "unresolved-peer", "explicit-all"} {
				directionName := "egress"
				if ingress {
					directionName = "ingress"
				}
				t.Run(directionName+"/"+string(action)+"/"+name, func(t *testing.T) {
					rule := agentsv1alpha1.TrafficPolicyRule{Action: action}
					direction := &agentsv1alpha1.TrafficPolicyDirection{}
					peers := []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}}
					switch name {
					case "absent":
						direction = nil
					case "ports-only":
						rule.Ports = []agentsv1alpha1.TrafficPolicyPort{{Protocol: "TCP"}}
					case "opposite-peer":
						if ingress {
							rule.To = peers
						} else {
							rule.From = peers
						}
					case "unresolved-peer", "explicit-all":
						if name == "unresolved-peer" {
							peers = []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "missing.example"}}
						}
						if ingress {
							rule.From = peers
						} else {
							rule.To = peers
						}
					}
					if direction != nil && name != "empty" {
						direction.Rules = []agentsv1alpha1.TrafficPolicyRule{rule}
					}
					source := model.TrafficPolicy{Name: "p", Namespace: "tenant"}
					if ingress {
						source.Spec.Ingress = direction
					} else {
						source.Spec.Egress = direction
					}
					compiled, err := CompileTrafficPolicy(krt.TestingDummyContext{}, source, inputs)
					if err != nil {
						t.Fatal(err)
					}
					body := compiled.Policy.Egress
					if ingress {
						body = compiled.Policy.Ingress
					}
					configured := name == "unresolved-peer" || name == "explicit-all"
					if (body != nil) != configured {
						t.Fatalf("direction presence disagrees with Poseidon: %v", compiled.Policy)
					}
					if name == "unresolved-peer" && len(body.Rules) != 0 {
						t.Fatal("unresolved peers must remain non-matching in both formats")
					}
					if name == "explicit-all" && len(body.Rules) != 1 {
						t.Fatal("explicit match-all peer lost its rule")
					}
				})
			}
		}
	}
}

func TestNativeTrafficPolicyOmitsUnresolvedRuleWithoutLosingDirection(t *testing.T) {
	for _, action := range []string{"allow", "reject"} {
		source := model.TrafficPolicy{Name: "p", Namespace: "tenant", Spec: agentsv1alpha1.TrafficPolicySpec{Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "missing.example"}}}}}}}
		if action == "reject" {
			source.Spec.Egress.Rules[0].Action = agentsv1alpha1.RuleActionReject
		}
		compiled, err := CompileTrafficPolicy(krt.TestingDummyContext{}, source, testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil))
		if err != nil {
			t.Fatal(err)
		}
		if compiled.Policy.Egress == nil || len(compiled.Policy.Egress.Rules) != 0 || compiled.Policy.Ingress != nil {
			t.Fatalf("empty resolution widened rule: %v", compiled.Policy)
		}
	}
}

func TestNativeTrafficPolicyPortPresence(t *testing.T) {
	p, e := int32(80), int32(443)
	ports, err := compileNativePorts([]agentsv1alpha1.TrafficPolicyPort{
		{Protocol: "TCP", Port: &p}, {Protocol: "TCP", EndPort: &e}, {Protocol: "TCP", Port: &p, EndPort: &e}, {Protocol: "ICMP"}, {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ports[0].Port == nil || ports[0].EndPort != nil || ports[1].Port != nil || ports[1].EndPort == nil || ports[2].Port == nil || ports[2].EndPort == nil || ports[3].Port != nil || ports[3].EndPort != nil {
		t.Fatalf("port presence lost: %v", ports)
	}
	if ports[4].Protocol != securityv1.TrafficPolicy_ALL || ports[4].Port != nil || ports[4].EndPort != nil {
		t.Fatal("empty entry must remain unconstrained in OR list")
	}
	for _, bad := range []agentsv1alpha1.TrafficPolicyPort{{Protocol: "ICMP", Port: &p}, {Protocol: "BOGUS"}, {Port: &e, EndPort: &p}} {
		if _, err := compileNativePorts([]agentsv1alpha1.TrafficPolicyPort{bad}); err == nil {
			t.Fatalf("accepted invalid port match: %+v", bad)
		}
	}
}

func TestTrafficPolicyAuthorizationPortEncoding(t *testing.T) {
	start, end := int32(80), int32(443)
	compiled, err := CompileTrafficPolicy(krt.TestingDummyContext{}, model.TrafficPolicy{
		Name: "ports", Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionReject,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}},
				Ports: []agentsv1alpha1.TrafficPolicyPort{
					{Port: &start}, {Protocol: "TCP", EndPort: &end},
					{Protocol: "UDP", Port: &start, EndPort: &end}, {Protocol: "ICMP"}, {Protocol: "SCTP"},
				},
			}}},
		},
	}, testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := &securityv1.Match{NotDestinationPortRanges: []*securityv1.PortRange{
		{Start: 80, End: 80, Protocol: securityv1.Protocol_ALL},
		{Start: 0, End: 443, Protocol: securityv1.Protocol_TCP},
		{Start: 80, End: 443, Protocol: securityv1.Protocol_UDP},
		{Start: 0, End: 65535, Protocol: securityv1.Protocol_ICMP},
		{Start: 0, End: 65535, Protocol: securityv1.Protocol_SCTP},
	}}
	got := compiledRuleAuthorization(t, compiled).Policy.Groups[0].Rules[1].Matches[0]
	if !proto.Equal(got, want) {
		t.Fatalf("legacy reject port encoding = %v, want %v", got, want)
	}
}
