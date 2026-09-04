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

package kubernetes

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

// DelegatedIdentityAuthorizer is the Kubernetes implementation of the
// delegated-identity seam: a trusted shared ztunnel may request a certificate
// for a service-account identity only when a live ambient workload owning
// that identity runs on its node.
type DelegatedIdentityAuthorizer struct {
	pods                   krt.Collection[*corev1.Pod]
	targetsByNodePrincipal krt.Index[string, *corev1.Pod]
	rootNamespace          string
	ztunnelServiceAccount  string
}

func (r *Registry) DelegatedIdentityAuthorizer() *DelegatedIdentityAuthorizer {
	return &DelegatedIdentityAuthorizer{
		pods:                   r.Pods,
		targetsByNodePrincipal: r.delegationPodsByNodePrincipal,
		rootNamespace:          r.options.RootNamespace,
		ztunnelServiceAccount:  r.options.ZTunnelServiceAccount,
	}
}

// newDelegationTargetIndex indexes eligible ambient Pods by node and owned
// principal so authorization is a single lookup instead of a Pod scan.
func newDelegationTargetIndex(pods krt.Collection[*corev1.Pod], trustDomain string) krt.Index[string, *corev1.Pod] {
	return krt.NewIndex(pods, "delegationPodsByNodePrincipal", func(pod *corev1.Pod) []string {
		if !eligibleDelegationTarget(pod) {
			return nil
		}
		principal := model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: trustDomain,
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      pod.Namespace,
				ServiceAccount: pod.Spec.ServiceAccountName,
			},
		}
		return []string{pod.Spec.NodeName + "|" + principal.String()}
	})
}

func eligibleDelegationTarget(pod *corev1.Pod) bool {
	if pod.Spec.NodeName == "" || pod.Spec.ServiceAccountName == "" || pod.DeletionTimestamp != nil ||
		pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return false
	}
	return podsource.AmbientRedirectionEnabled(pod) || podsource.HasInjectedZTunnel(pod)
}

// Authorize decides whether caller may request a certificate for requested.
func (a *DelegatedIdentityAuthorizer) Authorize(ctx context.Context, caller model.PeerIdentity, requested model.Principal) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("authorize delegated identity: %w", err)
	}
	if caller.AttestedBy != model.AttestationKubernetes {
		return fmt.Errorf("authorize delegated identity: unsupported caller attestation %q", caller.AttestedBy)
	}
	if err := caller.Principal.Validate(); err != nil {
		return fmt.Errorf("authorize delegated identity: caller principal: %w", err)
	}
	if err := requested.Validate(); err != nil {
		return fmt.Errorf("authorize delegated identity: requested principal: %w", err)
	}
	if caller.Principal.Kind != model.PrincipalServiceAccount ||
		requested.Kind != model.PrincipalServiceAccount {
		return fmt.Errorf("authorize delegated identity: registry only owns service account identities")
	}
	if requested.TrustDomain != caller.Principal.TrustDomain {
		return fmt.Errorf("authorize delegated identity: requested trust domain %q does not match caller trust domain %q", requested.TrustDomain, caller.Principal.TrustDomain)
	}
	if caller.Principal.ServiceAccount.Namespace != a.rootNamespace || caller.Principal.ServiceAccount.ServiceAccount != a.ztunnelServiceAccount {
		return fmt.Errorf("authorize delegated identity: caller %s is not a trusted node service account", caller.Principal.String())
	}
	if caller.Kubernetes.WorkloadName == "" || caller.Kubernetes.WorkloadUID == "" {
		return fmt.Errorf("authorize delegated identity: trusted node requires a bound Pod name and UID")
	}
	ztunnel := a.pods.GetKey(caller.Principal.ServiceAccount.Namespace + "/" + caller.Kubernetes.WorkloadName)
	if ztunnel == nil {
		return fmt.Errorf("authorize delegated identity: trusted node Pod %s/%s is not cached", caller.Principal.ServiceAccount.Namespace, caller.Kubernetes.WorkloadName)
	}
	if string((*ztunnel).UID) != caller.Kubernetes.WorkloadUID ||
		(*ztunnel).Spec.ServiceAccountName != a.ztunnelServiceAccount || (*ztunnel).Spec.NodeName == "" {
		return fmt.Errorf("authorize delegated identity: trusted node token is not bound to the active ztunnel Pod")
	}
	node := (*ztunnel).Spec.NodeName
	if len(a.targetsByNodePrincipal.Lookup(node+"|"+requested.String())) > 0 {
		return nil
	}
	return fmt.Errorf("authorize delegated identity: no active ambient workload on node %s owns %s", node, requested.String())
}
