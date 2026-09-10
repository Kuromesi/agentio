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
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestNativeTrafficPolicyPreservesActionsAndEmptyDirection(t *testing.T) {
	source := model.TrafficPolicy{
		Name:      "p",
		Namespace: "tenant",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Ingress: &agentsv1alpha1.TrafficPolicyDirection{},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{
				{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/8"}}},
				{Action: agentsv1alpha1.RuleActionReject},
			}},
		},
	}
	compiled, err := CompileTrafficPolicy(krt.TestingDummyContext{}, source, testTrafficPolicyInputs("agentio-system", nil, nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	p := compiled.Policy
	if p.Ingress == nil || len(p.Ingress.Rules) != 0 || len(p.Egress.Rules) != 2 {
		t.Fatalf("directions: %v", p)
	}
	if p.Egress.Rules[0].Action != securityv1.TrafficPolicy_ALLOW || len(p.Egress.Rules[0].Match.DestinationIps) != 1 {
		t.Fatal("allow rule lost address constraint")
	}
	deny := p.Egress.Rules[1]
	if deny.Action != securityv1.TrafficPolicy_DENY || deny.Match == nil || len(deny.Match.SourceIps)+len(deny.Match.DestinationIps)+len(deny.Match.Ports) != 0 {
		t.Fatal("unconditional reject lost its action")
	}
	if compiled.Attachment == nil {
		t.Fatal("namespace baseline must have an attachment")
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
