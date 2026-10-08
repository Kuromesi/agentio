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
	"github.com/openkruise/agentio/pkg/security/attestation"
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
	clusterID              string
	trustDomain            string
}

func (r *Registry) DelegatedIdentityAuthorizer() *DelegatedIdentityAuthorizer {
	return &DelegatedIdentityAuthorizer{
		pods:                   r.Pods,
		targetsByNodePrincipal: newDelegationTargetIndex(r.Pods, r.options.TrustDomain),
		rootNamespace:          r.options.RootNamespace,
		ztunnelServiceAccount:  r.options.ZTunnelServiceAccount,
		clusterID:              r.options.ClusterID,
		trustDomain:            r.options.TrustDomain,
	}
}

// newDelegationTargetIndex indexes eligible ambient Pods by node and owned
// principal so authorization is a single lookup instead of a Pod scan.
func newDelegationTargetIndex(pods krt.Collection[*corev1.Pod], trustDomain string) krt.Index[string, *corev1.Pod] {
	return krt.NewIndex(pods, "delegationPodsByNodePrincipal", func(pod *corev1.Pod) []string {
		if !eligibleDelegationTarget(pod) {
			return nil
		}
		principal, err := podsource.ServiceAccountPrincipal(trustDomain, pod.Namespace, pod.Spec.ServiceAccountName)
		if err != nil {
			return nil
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
func (a *DelegatedIdentityAuthorizer) Authorize(
	ctx context.Context,
	caller model.PeerIdentity,
	target attestation.CertificateTarget,
) error {
	requested := target.Principal
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("authorize delegated identity: %w", err)
	}
	if caller.AttestedBy != model.AttestationKubernetes {
		return fmt.Errorf("authorize delegated identity: unsupported caller attestation %q", caller.AttestedBy)
	}
	if err := caller.Kubernetes.Validate(); err != nil {
		return err
	}
	if _, err := model.ParsePrincipal(requested.String(), a.trustDomain); err != nil {
		return err
	}
	if _, _, ok := podsource.ServiceAccountFromPrincipal(requested); !ok {
		return fmt.Errorf("Kubernetes registry only owns service account identities")
	}
	callerPrincipal, err := podsource.ServiceAccountPrincipal(
		a.trustDomain,
		caller.Kubernetes.Namespace,
		caller.Kubernetes.ServiceAccount,
	)
	if err != nil {
		return err
	}
	if target.Source != (model.SourceRef{}) {
		if err := target.Source.Validate(); err != nil {
			return err
		}
		if target.Source.Registry != "kubernetes/"+a.clusterID {
			return fmt.Errorf("authorize certificate source: registry does not match this cluster")
		}
	}
	pod, err := activeCallerPod(a.pods, caller)
	if err != nil {
		return err
	}
	if requested == callerPrincipal && (target.Source == (model.SourceRef{}) || target.Source.Key == string(pod.UID)) {
		return nil
	}
	if caller.Kubernetes.Namespace != a.rootNamespace || caller.Kubernetes.ServiceAccount != a.ztunnelServiceAccount {
		return fmt.Errorf(
			"authorize delegated identity: caller %s is not a trusted node service account",
			callerPrincipal.String(),
		)
	}
	if pod.Spec.NodeName == "" {
		return fmt.Errorf("trusted node Pod has no assigned node")
	}
	node := pod.Spec.NodeName
	for _, pod := range a.targetsByNodePrincipal.Lookup(node + "|" + requested.String()) {
		if target.Source == (model.SourceRef{}) || target.Source.Key == string(pod.UID) {
			return nil
		}
	}
	return fmt.Errorf(
		"authorize delegated identity: no active ambient workload on node %s owns %s",
		node,
		requested.String(),
	)
}

// activeCallerPod returns an active Pod matching the TokenReview name, UID, and service account.
func activeCallerPod(pods krt.Collection[*corev1.Pod], caller model.PeerIdentity) (*corev1.Pod, error) {
	if caller.AttestedBy != model.AttestationKubernetes {
		return nil, fmt.Errorf("unsupported caller attestation %q", caller.AttestedBy)
	}
	if err := caller.Kubernetes.Validate(); err != nil {
		return nil, err
	}
	evidence := caller.Kubernetes
	if evidence.WorkloadName == "" || evidence.WorkloadUID == "" {
		return nil, fmt.Errorf("a Pod-bound token is required")
	}
	pod := pods.GetKey(evidence.Namespace + "/" + evidence.WorkloadName)
	if pod == nil || string((*pod).UID) != evidence.WorkloadUID ||
		(*pod).Spec.ServiceAccountName != evidence.ServiceAccount ||
		(*pod).DeletionTimestamp != nil ||
		(*pod).Status.Phase == corev1.PodFailed ||
		(*pod).Status.Phase == corev1.PodSucceeded {
		return nil, fmt.Errorf("token is not bound to an active Pod")
	}
	return *pod, nil
}
