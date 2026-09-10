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

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
)

// HostnameResolver resolves one hostname while registering any krt dependency
// carried by ctx. Production resolvers use a hostname-keyed DNS collection;
// tests may provide an in-memory implementation.
type HostnameResolver func(krt.HandlerContext, string) []netip.Addr

// TrafficPolicyInputs carries the collections and indexes a TrafficPolicy uses to resolve peers.
type TrafficPolicyInputs struct {
	RootNamespace string

	Services       krt.Collection[*corev1.Service]
	EndpointSlices krt.Collection[*discoveryv1.EndpointSlice]
	Pods           krt.Collection[*corev1.Pod]

	ServicesByNamespace     krt.Index[string, *corev1.Service]
	EndpointSlicesByService krt.Index[string, *discoveryv1.EndpointSlice]
	PodsByNamespace         krt.Index[string, *corev1.Pod]

	Resolve HostnameResolver
}

// validate reports missing collections up front.
func (i TrafficPolicyInputs) validate() error {
	switch {
	case i.Services == nil || i.ServicesByNamespace == nil:
		return fmt.Errorf("Kubernetes Service collection and namespace index are required")
	case i.EndpointSlices == nil || i.EndpointSlicesByService == nil:
		return fmt.Errorf("EndpointSlice collection and service index are required")
	case i.Pods == nil || i.PodsByNamespace == nil:
		return fmt.Errorf("Pod collection and namespace index are required")
	}
	return nil
}

// Peer resolution keeps Pod readiness and deletion state from removing a
// selected IP from policy control; namespace and labels define the peer set.
func resolvePeers(ctx krt.HandlerContext, peers []agentsv1alpha1.TrafficPolicyPeer, policyNamespace string, inputs TrafficPolicyInputs) []*securityv1.Address {
	result := make([]*securityv1.Address, 0)
	add := func(value string) {
		prefix, err := parsePrefix(value)
		if err != nil {
			return
		}
		result = append(result, &securityv1.Address{Address: prefix.Addr().AsSlice(), Length: uint32(prefix.Bits())})
	}
	for _, peer := range peers {
		switch {
		case peer.CIDR != "":
			add(peer.CIDR)
		case peer.Service != nil:
			namespace := peer.Service.Namespace
			if namespace == "" {
				namespace = policyNamespace
			}
			services := []*corev1.Service(nil)
			if peer.Service.Name == "" || peer.Service.Name == "*" {
				services = krt.Fetch(ctx, inputs.Services,
					krt.FilterIndex(inputs.ServicesByNamespace, namespace))
			} else if service := krt.FetchOne(ctx, inputs.Services,
				krt.FilterKey(namespace+"/"+peer.Service.Name)); service != nil {
				services = append(services, *service)
			}
			for _, service := range services {
				if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != corev1.ClusterIPNone {
					add(service.Spec.ClusterIP)
				}
				for _, slice := range krt.Fetch(ctx, inputs.EndpointSlices,
					krt.FilterIndex(inputs.EndpointSlicesByService, service.Namespace+"/"+service.Name)) {
					if slice.AddressType == discoveryv1.AddressTypeFQDN {
						continue
					}
					for _, endpoint := range slice.Endpoints {
						for _, address := range endpoint.Addresses {
							add(address)
						}
					}
				}
			}
		case peer.FQDN != "":
			resolved := []netip.Addr(nil)
			if inputs.Resolve != nil {
				resolved = inputs.Resolve(ctx, peer.FQDN)
			}
			for _, address := range resolved {
				if address.IsValid() {
					add(address.String())
				}
			}
		case peer.Workload != nil:
			pods := krt.Fetch(ctx, inputs.Pods,
				krt.FilterLabel(peer.Workload.Selector),
				krt.FilterIndex(inputs.PodsByNamespace, peer.Workload.Namespace),
			)
			for _, pod := range pods {
				if len(pod.Status.PodIPs) > 0 {
					for _, address := range pod.Status.PodIPs {
						add(address.IP)
					}
				} else if pod.Status.PodIP != "" {
					add(pod.Status.PodIP)
				}
			}
		}
	}
	return result
}

func parsePrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix, nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(address, address.BitLen()), nil
}
