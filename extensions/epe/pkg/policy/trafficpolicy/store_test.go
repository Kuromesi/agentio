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

package trafficpolicy

import (
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

func int32Ptr(v int32) *int32 { return &v }

func testPolicy(t *testing.T, name, namespace string, priority int32, selector map[string]string, rules ...agentsv1alpha1.TrafficPolicyRule) Policy {
	t.Helper()
	obj := &agentsv1alpha1.TrafficPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: priority,
			Selector: metav1.LabelSelector{MatchLabels: selector},
			Egress:   &agentsv1alpha1.TrafficPolicyDirection{Rules: rules},
		},
	}
	p, err := compilePolicy(obj, &obj.Spec, false)
	if err != nil {
		t.Fatalf("compilePolicy: %v", err)
	}
	return *p
}

func TestStoreAuthorizeConnect(t *testing.T) {
	allowWeb := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "172.30.199.186/32"}},
		Ports: []agentsv1alpha1.TrafficPolicyPort{{
			Protocol: "TCP",
			Port:     int32Ptr(80),
		}},
	}
	rejectAll := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionReject,
		To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}},
	}
	allowDocs := agentsv1alpha1.TrafficPolicyRule{
		Action: agentsv1alpha1.RuleActionAllow,
		To:     []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "*.example.com"}},
		Ports: []agentsv1alpha1.TrafficPolicyPort{{
			Protocol: "TCP",
			Port:     int32Ptr(443),
			EndPort:  int32Ptr(444),
		}},
	}

	tests := []struct {
		name     string
		policies []Policy
		pod      inputs.Pod
		req      httpreq.HTTPRequest
		want     Decision
	}{
		{
			name: "no selected policy preserves compatibility",
			pod:  inputs.Pod{Namespace: "sandbox", Labels: map[string]string{"app": "actor"}},
			req:  httpreq.HTTPRequest{Method: "CONNECT", Host: "172.30.199.186", Port: 80},
			want: Decision{Allowed: true},
		},
		{
			name: "matching cidr and port is allowed",
			policies: []Policy{testPolicy(t, "allow-web", "sandbox", 100,
				map[string]string{"kruise.io/actor-name": "actor-a"}, allowWeb, rejectAll)},
			pod: inputs.Pod{Namespace: "sandbox", Labels: map[string]string{
				"kruise.io/actor-name": "actor-a",
			}},
			req:  httpreq.HTTPRequest{Method: "CONNECT", Host: "172.30.199.186", Port: 80},
			want: Decision{Enforced: true, Allowed: true, Policy: "sandbox/allow-web", Rule: 0},
		},
		{
			name: "fallback reject blocks another connect address",
			policies: []Policy{testPolicy(t, "allow-web", "sandbox", 100,
				map[string]string{"kruise.io/actor-name": "actor-a"}, allowWeb, rejectAll)},
			pod: inputs.Pod{Namespace: "sandbox", Labels: map[string]string{
				"kruise.io/actor-name": "actor-a",
			}},
			req:  httpreq.HTTPRequest{Method: "CONNECT", Host: "172.30.17.196", Port: 9000},
			want: Decision{Enforced: true, Allowed: false, Policy: "sandbox/allow-web", Rule: 1},
		},
		{
			name: "selected policy defaults to reject when no rule matches",
			policies: []Policy{testPolicy(t, "allow-web", "sandbox", 100,
				map[string]string{"kruise.io/actor-name": "actor-a"}, allowWeb)},
			pod: inputs.Pod{Namespace: "sandbox", Labels: map[string]string{
				"kruise.io/actor-name": "actor-a",
			}},
			req:  httpreq.HTTPRequest{Method: "CONNECT", Host: "172.30.17.196", Port: 9000},
			want: Decision{Enforced: true, Allowed: false},
		},
		{
			name: "selector mismatch does not enforce",
			policies: []Policy{testPolicy(t, "allow-web", "sandbox", 100,
				map[string]string{"kruise.io/actor-name": "actor-a"}, rejectAll)},
			pod: inputs.Pod{Namespace: "sandbox", Labels: map[string]string{
				"kruise.io/actor-name": "actor-b",
			}},
			req:  httpreq.HTTPRequest{Method: "CONNECT", Host: "172.30.17.196", Port: 9000},
			want: Decision{Allowed: true},
		},
		{
			name: "higher priority matching reject wins",
			policies: []Policy{
				testPolicy(t, "allow", "sandbox", 100, map[string]string{"app": "actor"}, allowWeb),
				testPolicy(t, "reject", "sandbox", 200, map[string]string{"app": "actor"}, rejectAll),
			},
			pod:  inputs.Pod{Namespace: "sandbox", Labels: map[string]string{"app": "actor"}},
			req:  httpreq.HTTPRequest{Method: "CONNECT", Host: "172.30.199.186", Port: 80},
			want: Decision{Enforced: true, Allowed: false, Policy: "sandbox/reject", Rule: 0},
		},
		{
			name: "higher priority no-match falls through to lower policy",
			policies: []Policy{
				testPolicy(t, "allow", "sandbox", 100, map[string]string{"app": "actor"}, allowWeb),
				testPolicy(t, "specific-reject", "sandbox", 200, map[string]string{"app": "actor"}, agentsv1alpha1.TrafficPolicyRule{
					Action: agentsv1alpha1.RuleActionReject,
					To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "192.0.2.0/24"}},
				}),
			},
			pod:  inputs.Pod{Namespace: "sandbox", Labels: map[string]string{"app": "actor"}},
			req:  httpreq.HTTPRequest{Method: "CONNECT", Host: "172.30.199.186", Port: 80},
			want: Decision{Enforced: true, Allowed: true, Policy: "sandbox/allow", Rule: 0},
		},
		{
			name: "fqdn wildcard and port range",
			policies: []Policy{testPolicy(t, "docs", "sandbox", 100,
				map[string]string{"app": "actor"}, allowDocs)},
			pod:  inputs.Pod{Namespace: "sandbox", Labels: map[string]string{"app": "actor"}},
			req:  httpreq.HTTPRequest{Method: "CONNECT", Host: "api.example.com", Port: 444},
			want: Decision{Enforced: true, Allowed: true, Policy: "sandbox/docs", Rule: 0},
		},
		{
			name: "non connect request stays on security profile path",
			policies: []Policy{testPolicy(t, "reject", "sandbox", 100,
				map[string]string{"app": "actor"}, rejectAll)},
			pod:  inputs.Pod{Namespace: "sandbox", Labels: map[string]string{"app": "actor"}},
			req:  httpreq.HTTPRequest{Method: "GET", Host: "172.30.199.186", Port: 80},
			want: Decision{Allowed: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewStore()
			s.replace(tt.policies)
			if got := s.Authorize(tt.pod, &tt.req); got != tt.want {
				t.Fatalf("Authorize() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
