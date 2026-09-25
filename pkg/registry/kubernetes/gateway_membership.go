// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

// gatewayMembership is observed state, never an administrator-maintained UID
// list. The Kubernetes permissions protecting gateway declarations, Services,
// and matching Pods are part of the identity authorization boundary.
type gatewayMembership struct {
	PodUID     string
	GatewayKey string
	Conflict   bool
}

func (m gatewayMembership) ResourceName() string { return m.PodUID }

func (r *Registry) gatewayMemberships(options ...krt.CollectionOption) krt.Collection[gatewayMembership] {
	byNamespace := krt.NewIndex(r.Gateways, "gatewaysByNamespace", func(g model.Gateway) []string {
		return []string{g.Namespace}
	})
	return krt.NewCollection(r.Pods, func(ctx krt.HandlerContext, pod *corev1.Pod) *gatewayMembership {
		if pod.UID == "" || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			return nil
		}
		member := gatewayMembership{PodUID: string(pod.UID)}
		for _, gateway := range krt.Fetch(ctx, r.Gateways, krt.FilterIndex(byNamespace, pod.Namespace)) {
			matched := false
			if gateway.Source == model.GatewaySourceGatewayAPI || gateway.Source == model.GatewaySourceConflict {
				matched = pod.Labels[podsource.LabelGatewayName] == gateway.Name
			}
			if gateway.Source != model.GatewaySourceGatewayAPI {
				service := krt.FetchOne(ctx, r.KubernetesServices, krt.FilterKey(gateway.ResourceName()))
				if service != nil && (*service).Spec.Type != corev1.ServiceTypeExternalName && len((*service).Spec.Selector) > 0 {
					matched = matched || labels.SelectorFromSet((*service).Spec.Selector).Matches(labels.Set(pod.Labels))
				}
			}
			if !matched {
				continue
			}
			if member.GatewayKey != "" || gateway.ValidateForUse() != nil {
				member.Conflict = true
			}
			if name := pod.Labels[podsource.LabelGatewayName]; name != "" && name != gateway.Name {
				member.Conflict = true
			}
			if member.GatewayKey == "" || gateway.ResourceName() < member.GatewayKey {
				member.GatewayKey = gateway.ResourceName()
			}
		}
		if member.GatewayKey == "" {
			return nil
		}
		// No readiness or Gateway status dependency: certificates are needed to
		// start the proxy, before either resource can become ready.
		return &member
	}, options...)
}
