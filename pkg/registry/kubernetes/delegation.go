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
	"github.com/openkruise/agentio/pkg/registry/kubernetes/kruise"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
	"github.com/openkruise/agentio/pkg/security/attestation"
)

// DelegatedIdentityAuthorizer authorizes self and same-node certificate requests.
type DelegatedIdentityAuthorizer struct {
	pods                   krt.Collection[*corev1.Pod]
	workloads              krt.Collection[model.Workload]
	targetsByNodePrincipal krt.Index[string, *corev1.Pod]
	rootNamespace          string
	ztunnelServiceAccount  string
	clusterID              string
	trustDomain            string
	enableKruise           bool
}

func (r *Registry) DelegatedIdentityAuthorizer() *DelegatedIdentityAuthorizer {
	return &DelegatedIdentityAuthorizer{
		pods:                   r.Pods,
		workloads:              r.Workloads,
		targetsByNodePrincipal: newDelegationTargetIndex(r.Pods, r.options.TrustDomain),
		rootNamespace:          r.options.RootNamespace,
		ztunnelServiceAccount:  r.options.ZTunnelServiceAccount,
		clusterID:              r.options.ClusterID,
		trustDomain:            r.options.TrustDomain,
		enableKruise:           r.options.EnableKruise,
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

// Authorize checks the requested principal and returns the selected Pod's identity.
func (a *DelegatedIdentityAuthorizer) Authorize(
	ctx context.Context,
	caller model.PeerIdentity,
	target attestation.CertificateTarget,
) (attestation.WorkloadIdentity, error) {
	requested := target.Principal
	if err := ctx.Err(); err != nil {
		return attestation.WorkloadIdentity{}, err
	}
	if _, err := model.ParsePrincipal(requested.String(), a.trustDomain); err != nil {
		return attestation.WorkloadIdentity{}, err
	}
	namespace, serviceAccount, ok := podsource.ServiceAccountFromPrincipal(requested)
	if !ok {
		return attestation.WorkloadIdentity{}, fmt.Errorf("Kubernetes registry only owns service account identities")
	}
	pod, err := activeCallerPod(a.pods, caller)
	if err != nil {
		return attestation.WorkloadIdentity{}, err
	}
	trustedNode := caller.Kubernetes.Namespace == a.rootNamespace &&
		caller.Kubernetes.ServiceAccount == a.ztunnelServiceAccount && pod.Spec.NodeName != ""
	if ref := target.Workload; ref != nil {
		if ref.Namespace == "" || ref.Name == "" {
			return attestation.WorkloadIdentity{}, fmt.Errorf("workload namespace and name are required")
		}
		selected := a.pods.GetKey(ref.Namespace + "/" + ref.Name)
		if selected == nil || (*selected).UID == "" || (*selected).DeletionTimestamp != nil ||
			(*selected).Status.Phase == corev1.PodSucceeded || (*selected).Status.Phase == corev1.PodFailed {
			return attestation.WorkloadIdentity{}, fmt.Errorf("certificate target is not an active Pod")
		}
		targetPod := *selected
		if targetPod.Namespace != namespace || targetPod.Spec.ServiceAccountName != serviceAccount {
			return attestation.WorkloadIdentity{}, fmt.Errorf(
				"certificate identity does not match target Pod service account",
			)
		}
		if targetPod.UID != pod.UID &&
			(!trustedNode || targetPod.Spec.NodeName != pod.Spec.NodeName || !eligibleDelegationTarget(targetPod)) {
			return attestation.WorkloadIdentity{}, fmt.Errorf(
				"caller may only delegate to managed Workloads on its node",
			)
		}
		return a.workloadIdentity(targetPod), nil
	}
	if namespace == pod.Namespace && serviceAccount == pod.Spec.ServiceAccountName {
		return attestation.WorkloadIdentity{}, nil
	}
	if trustedNode && len(a.targetsByNodePrincipal.Lookup(pod.Spec.NodeName+"|"+requested.String())) != 0 {
		return attestation.WorkloadIdentity{}, nil
	}
	return attestation.WorkloadIdentity{}, fmt.Errorf("caller cannot delegate the requested service account identity")
}

func (a *DelegatedIdentityAuthorizer) workloadIdentity(pod *corev1.Pod) attestation.WorkloadIdentity {
	identity := attestation.WorkloadIdentity{Registry: "kubernetes/" + a.clusterID, UID: string(pod.UID)}
	key := podsource.WorkloadUID(a.clusterID, pod)
	workload := a.workloads.GetKey(key)
	if workload != nil && workload.Source == podsource.SourceRef(a.clusterID, string(pod.UID)) &&
		workload.GatewayKey != "" {
		identity.Role = attestation.RoleEgressGateway
	} else if a.enableKruise &&
		kruise.OwnsPod(pod) {
		identity.Role = attestation.RoleSandboxAttester
	}
	return identity
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
