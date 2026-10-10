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
	"fmt"
	"net/netip"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestTrafficPolicyPeerOrdering(t *testing.T) {
	opts := []krt.CollectionOption{krt.WithStop(t.Context().Done())}
	pods := krt.NewMutableCollection[*corev1.Pod](nil, nil, opts...)
	services := krt.NewMutableCollection[*corev1.Service](nil, nil, opts...)
	endpointSlices := krt.NewMutableCollection[*discoveryv1.EndpointSlice](nil, nil, opts...)
	var want []*securityv1.TrafficPolicy_Address
	addExpected := func(ip string) {
		want = append(want, &securityv1.TrafficPolicy_Address{Address: netip.MustParseAddr(ip).AsSlice(), Length: 32})
	}
	// Multiple objects exercise all three unordered index lookups independently.
	for i := range 8 {
		name := fmt.Sprintf("peer-%d", i)
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		pods.UpdateObject(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name},
			Status:     corev1.PodStatus{PodIP: ip},
		})
		addExpected(ip)
		services.UpdateObject(&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name},
			Spec:       corev1.ServiceSpec{ClusterIP: fmt.Sprintf("10.1.0.%d", i+1)},
		})
		endpointSlices.UpdateObject(&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns",
				Name:      name,
				Labels:    map[string]string{discoveryv1.LabelServiceName: "peer-0"},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{fmt.Sprintf("10.2.0.%d", i+1)}}},
		})
	}
	addExpected("10.1.0.1")
	for i := range 8 {
		addExpected(fmt.Sprintf("10.2.0.%d", i+1))
	}
	for i := 1; i < 8; i++ {
		addExpected(fmt.Sprintf("10.1.0.%d", i+1))
	}
	source := model.TrafficPolicy{
		Name:      "peers",
		Namespace: "ns",
		Spec: agentsv1alpha1.TrafficPolicySpec{Egress: &agentsv1alpha1.TrafficPolicyDirection{
			Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow,
				To: []agentsv1alpha1.TrafficPolicyPeer{
					{Workload: &agentsv1alpha1.TrafficPolicyWorkloadRef{Namespace: "ns"}},
					{Service: &agentsv1alpha1.TrafficPolicyServiceRef{Name: "*"}},
				},
			}},
		}},
	}
	inputs := testTrafficPolicyInputs(
		"root",
		services.AsCollection(),
		endpointSlices.AsCollection(),
		pods.AsCollection(),
		nil,
	)
	// Unchanged inputs must retain the same wire ordering on every recomputation.
	for range 32 {
		compiled, err := CompileTrafficPolicy(krt.TestingDummyContext{}, source, inputs)
		if err != nil {
			t.Fatal(err)
		}
		got := compiled.Policy.GetEgress().GetRules()[0].GetMatch()
		expected := &securityv1.TrafficPolicy_Match{DestinationIps: want}
		if !proto.Equal(got, expected) {
			t.Fatalf("peer ordering changed: got %v, want %v", got, expected)
		}
	}
}
