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

// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

// gatewayMembership is observed state, never an administrator-maintained UID
// list. The Kubernetes permissions protecting gateway declarations and Pod
// gateway-name labels are part of the identity authorization boundary.
type gatewayMembership struct {
	PodUID     string
	GatewayKey string
	Conflict   bool
}

func (m gatewayMembership) ResourceName() string { return m.PodUID }

func (r *Registry) gatewayMemberships(options ...krt.CollectionOption) krt.Collection[gatewayMembership] {
	return krt.NewCollection(r.Pods, func(ctx krt.HandlerContext, pod *corev1.Pod) *gatewayMembership {
		name := pod.Labels[podsource.LabelGatewayName]
		if pod.UID == "" || name == "" || pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			return nil
		}
		// Resolve declarations in the Pod's namespace; labels cannot create gateways
		// or use a Service's routing selector as authorization evidence.
		gateway := krt.FetchOne(ctx, r.Gateways, krt.FilterKey(pod.Namespace+"/"+name))
		if gateway == nil {
			return nil
		}
		member := gatewayMembership{
			PodUID:     string(pod.UID),
			GatewayKey: gateway.ResourceName(),
			Conflict:   gateway.ValidateForUse() != nil,
		}
		// No readiness or Gateway status dependency: certificates are needed to
		// start the proxy, before either resource can become ready.
		return &member
	}, options...)
}
