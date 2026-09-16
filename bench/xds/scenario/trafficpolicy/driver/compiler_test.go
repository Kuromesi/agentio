// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"encoding/json"
	"testing"

	ads "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/types/known/anypb"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/openkruise/agentio/bench/xds/scenario/trafficpolicy"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	policycompiler "github.com/openkruise/agentio/pkg/policy"
)

// Exercise the generated Kubernetes spec against the real compiler and client
// assertions, so compiler semantics cannot silently turn benchmark rules into no-ops.
func TestGeneratedPolicyCompilesIntoExpectedRound(t *testing.T) {
	options := []krt.CollectionOption{krt.WithStop(t.Context().Done())}
	services := krt.NewStaticCollection[*corev1.Service](nil, nil, options...)
	endpoints := krt.NewStaticCollection[*discoveryv1.EndpointSlice](nil, nil, options...)
	pods := krt.NewStaticCollection[*corev1.Pod](nil, nil, options...)
	inputs := policycompiler.TrafficPolicyInputs{
		RootNamespace: "agentio-system", Services: services, EndpointSlices: endpoints, Pods: pods,
		ServicesByNamespace: krt.NewIndex(services, "services", func(s *corev1.Service) []string { return []string{s.Namespace} }),
		EndpointSlicesByService: krt.NewIndex(endpoints, "endpoints", func(e *discoveryv1.EndpointSlice) []string {
			return []string{e.Namespace + "/" + e.Labels[discoveryv1.LabelServiceName]}
		}),
		PodsByNamespace: krt.NewIndex(pods, "pods", func(p *corev1.Pod) []string { return []string{p.Namespace} }),
	}
	d, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	rounds, err := d.Rounds(1)
	if err != nil {
		t.Fatal(err)
	}
	config, err := d.ClientConfig("test", "client")
	if err != nil {
		t.Fatal(err)
	}
	factory, err := trafficpolicy.New(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range rounds {
		t.Run(string(raw), func(t *testing.T) {
			expected, err := factory.PrepareRound(raw)
			if err != nil {
				t.Fatal(err)
			}
			round := expected.(trafficpolicy.Round)
			data, err := json.Marshal(policy("test", round).Object["spec"])
			if err != nil {
				t.Fatal(err)
			}
			var spec agentsv1alpha1.TrafficPolicySpec
			if err = json.Unmarshal(data, &spec); err != nil {
				t.Fatal(err)
			}
			compiled, err := policycompiler.CompileTrafficPolicy(krt.TestingDummyContext{}, model.TrafficPolicy{Name: "test", Global: true, Spec: spec}, inputs)
			if err != nil {
				t.Fatal(err)
			}
			body, err := anypb.New(compiled.Policy)
			if err != nil {
				t.Fatal(err)
			}
			observation, err := factory.New().Observe(&ads.DeltaDiscoveryResponse{
				TypeUrl:   trafficpolicy.PolicyType,
				Resources: []*ads.Resource{{Name: compiled.Name, Version: "test", Resource: body}},
			}, expected)
			if err != nil || observation.Sample == nil {
				t.Fatalf("compiled policy did not satisfy round: observation=%+v err=%v", observation, err)
			}
		})
	}
}
