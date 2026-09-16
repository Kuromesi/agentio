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
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestTrafficPolicyLegacyProjection(t *testing.T) {
	body := &securityv1.TrafficPolicy{Egress: &securityv1.TrafficPolicy_RuleSet{Rules: []*securityv1.TrafficPolicy_Rule{
		{
			Match: &securityv1.TrafficPolicy_Match{
				DestinationIps: []*securityv1.TrafficPolicy_Address{{Address: []byte{192, 0, 2, 0}, Length: 24}},
			},
		},
		{
			Action: securityv1.TrafficPolicy_DENY,
			Match: &securityv1.TrafficPolicy_Match{
				DestinationIps: []*securityv1.TrafficPolicy_Address{{Address: make([]byte, 4)}},
			},
		},
	}}}
	before := proto.Clone(body)
	for _, tc := range []struct {
		name      string
		source    model.TrafficPolicy
		scope     securityv1.Scope
		namespace string
		priority  int32
	}{
		{name: "namespace", source: model.TrafficPolicy{Namespace: "demo"}, scope: securityv1.Scope_NAMESPACE, namespace: "demo", priority: 42},
		{name: "global", source: model.TrafficPolicy{Global: true}, scope: securityv1.Scope_GLOBAL, namespace: "agentio-system", priority: 42},
		{name: "root namespace", source: model.TrafficPolicy{Namespace: "agentio-system"}, scope: securityv1.Scope_GLOBAL, namespace: "agentio-system", priority: 42},
		{name: "selector", source: model.TrafficPolicy{Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}}, scope: securityv1.Scope_WORKLOAD_SELECTOR, namespace: "demo", priority: 42},
		{name: "global selector", source: model.TrafficPolicy{Global: true, Spec: agentsv1alpha1.TrafficPolicySpec{Selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpExists}}}}}, scope: securityv1.Scope_WORKLOAD_SELECTOR, namespace: "agentio-system", priority: 42},
		{name: "dedicated", source: model.TrafficPolicy{Dedicated: true, SandboxUID: "kruise:actor", Namespace: "demo"}, scope: securityv1.Scope_WORKLOAD_SELECTOR, namespace: "demo", priority: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.source.Name, tc.source.Spec.Priority = "api", 42
			converted, err := TrafficPolicyAsAuthorizations(
				CompiledTrafficPolicy{CompiledPolicy: CompiledPolicy[*securityv1.TrafficPolicy]{Policy: body}},
				tc.source,
				"agentio-system",
			)
			if err != nil || len(converted) != 1 {
				t.Fatalf("converted=%v err=%v", converted, err)
			}
			a := converted[0].Policy
			ext := &extensionsv1.TrafficPolicyExtension{}
			if err := a.AuthExtensions[0].Config.UnmarshalTo(ext); err != nil {
				t.Fatal(err)
			}
			if a.Scope != tc.scope || a.Namespace != tc.namespace || ext.Priority != tc.priority ||
				ext.Mode != extensionsv1.TrafficPolicyMode_CLIENT {
				t.Fatalf("authorization=%v extension=%v", a, ext)
			}
			if !tc.source.Dedicated && a.Name != "api-egress" {
				t.Fatalf("source name lost: %s", a.Name)
			}
			if len(a.Groups) != 2 || len(a.Groups[0].Rules[0].Matches[0].DestinationIps) != 1 ||
				len(a.Groups[1].Rules[0].Matches[0].NotDestinationIps) != 1 {
				t.Fatalf("rules changed or fallback added: %v", a.Groups)
			}
			if !proto.Equal(body, before) {
				t.Fatal("projection mutated shared body")
			}
		})
	}
}

func TestTrafficPolicyLegacyEmptyDirections(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  *securityv1.TrafficPolicy
		count int
	}{
		{"absent", &securityv1.TrafficPolicy{}, 0},
		{"unresolved egress", &securityv1.TrafficPolicy{Egress: &securityv1.TrafficPolicy_RuleSet{}}, 1},
		{"unresolved both", &securityv1.TrafficPolicy{Egress: &securityv1.TrafficPolicy_RuleSet{}, Ingress: &securityv1.TrafficPolicy_RuleSet{}}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			converted, err := TrafficPolicyAsAuthorizations(
				CompiledTrafficPolicy{CompiledPolicy: CompiledPolicy[*securityv1.TrafficPolicy]{Policy: tc.body}},
				model.TrafficPolicy{Name: "api", Namespace: "demo"},
				"agentio-system",
			)
			if err != nil || len(converted) != tc.count {
				t.Fatalf("converted=%v err=%v", converted, err)
			}
			for _, a := range converted {
				if len(a.Policy.Groups) != 0 {
					t.Fatal("synthetic fallback added")
				}
			}
		})
	}
}
