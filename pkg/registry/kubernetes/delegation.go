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

// DelegatedIdentityAuthorizer authorizes every target certificate identity
// against active Workloads, including self issuance. Kubernetes token evidence
// proves Pod ownership; only a trusted node proxy can delegate node-local
// workload identities. Gateway identities are never node-delegatable.
type DelegatedIdentityAuthorizer struct {
	pods                  krt.Collection[*corev1.Pod]
	clusterID             string
	trustDomain           string
	rootNamespace         string
	ztunnelServiceAccount string
	workloads             krt.Collection[model.Workload]
	workloadsByIdentity   krt.Index[string, model.Workload]
}

func (r *Registry) DelegatedIdentityAuthorizer() *DelegatedIdentityAuthorizer {
	return &DelegatedIdentityAuthorizer{
		workloads:   r.Workloads,
		clusterID:   r.options.ClusterID,
		trustDomain: r.options.TrustDomain,
		workloadsByIdentity: krt.NewIndex(r.Workloads, "certificateWorkloadsByIdentity", func(w model.Workload) []string {
			if w.Principal == (model.Principal{}) {
				return nil
			}
			return []string{w.Principal.String()}
		}),
		pods:                  r.Pods,
		rootNamespace:         r.options.RootNamespace,
		ztunnelServiceAccount: r.options.ZTunnelServiceAccount,
	}
}

func eligibleDelegationTarget(pod *corev1.Pod) bool {
	if pod.Spec.NodeName == "" || pod.Spec.ServiceAccountName == "" || pod.DeletionTimestamp != nil ||
		pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return false
	}
	return podsource.AmbientRedirectionEnabled(pod) || podsource.HasInjectedZTunnel(pod)
}

// Authorize decides whether caller may request a certificate for requested.
func (a *DelegatedIdentityAuthorizer) Authorize(ctx context.Context, caller model.PeerIdentity, requested attestation.CertificateTarget) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("authorize delegated identity: %w", err)
	}
	if _, err := model.ParsePrincipal(requested.Principal.String(), a.trustDomain); err != nil {
		return fmt.Errorf("authorize certificate target: %w", err)
	}
	if requested.Source != (model.SourceRef{}) {
		if err := requested.Source.Validate(); err != nil {
			return fmt.Errorf("authorize certificate source: %w", err)
		}
	}
	return a.authorizeWorkload(caller, requested)
}

// activeCallerPod resolves only the Pod named and bound by TokenReview. Client
// metadata, a shared SA, and a node assertion cannot substitute for this binding.
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
	if pod == nil || string((*pod).UID) != evidence.WorkloadUID || (*pod).Spec.ServiceAccountName != evidence.ServiceAccount ||
		(*pod).DeletionTimestamp != nil || (*pod).Status.Phase == corev1.PodFailed || (*pod).Status.Phase == corev1.PodSucceeded {
		return nil, fmt.Errorf("token is not bound to an active Pod")
	}
	return *pod, nil
}

func (a *DelegatedIdentityAuthorizer) authorizeWorkload(caller model.PeerIdentity, requested attestation.CertificateTarget) error {
	if a.workloads == nil || !a.workloads.HasSynced() {
		return fmt.Errorf("workload identity registry is not synced")
	}
	pod, err := activeCallerPod(a.pods, caller)
	if err != nil {
		return err
	}
	for _, w := range a.workloadsByIdentity.Lookup(requested.Principal.String()) {
		if requested.Source != (model.SourceRef{}) && w.Source != requested.Source {
			continue
		}
		target := a.pods.GetKey(w.Namespace + "/" + w.Name)
		if target == nil || podsource.SourceRef(a.clusterID, string((*target).UID)) != w.Source || (*target).DeletionTimestamp != nil || (*target).Status.Phase == corev1.PodFailed || (*target).Status.Phase == corev1.PodSucceeded {
			continue
		}
		if w.Source == podsource.SourceRef(a.clusterID, string(pod.UID)) {
			return nil
		}
		if w.GatewayKey == "" &&
			pod.Namespace == a.rootNamespace && pod.Spec.ServiceAccountName == a.ztunnelServiceAccount &&
			pod.Spec.NodeName != "" && pod.Spec.NodeName == (*target).Spec.NodeName && eligibleDelegationTarget(*target) {
			return nil
		}
	}
	return fmt.Errorf("caller does not own or delegate active identity %s", requested.Principal.String())
}
