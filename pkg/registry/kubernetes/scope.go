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
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

// PodScopeResolver proves an authenticated identity owns the live Pod behind an xDS client claim.
type PodScopeResolver struct {
	pods                  krt.Collection[*corev1.Pod]
	podsByNode            krt.Index[string, *corev1.Pod]
	workloadsBySourceUID  krt.Index[string, model.Workload]
	gateways              krt.Collection[model.Gateway]
	clusterID             string
	rootNamespace         string
	ztunnelServiceAccount string
	synced                func() bool
}

func (r *Registry) PodScopeResolver(workloads krt.Collection[model.Workload]) *PodScopeResolver {
	workloadsBySourceUID := krt.NewIndex(workloads, "scopeWorkloadsBySourceUID", func(workload model.Workload) []string {
		if workload.SourceUID == "" {
			return nil
		}
		return []string{workload.SourceUID}
	})
	return &PodScopeResolver{
		pods:                  r.Pods,
		podsByNode:            r.podsByNode,
		workloadsBySourceUID:  workloadsBySourceUID,
		gateways:              r.Gateways,
		clusterID:             r.options.ClusterID,
		rootNamespace:         r.options.RootNamespace,
		ztunnelServiceAccount: r.options.ZTunnelServiceAccount,
		synced: func() bool {
			return r.HasSynced() && workloads.HasSynced()
		},
	}
}

// ResolveScope proves which xDS client the authenticated identity owns.
// nodeName is the client's verified node assertion: it gates the shared ztunnel
// class and narrows the candidate search; everything else comes from the
// token-bound identity.
func (s *PodScopeResolver) ResolveScope(peer model.PeerIdentity, nodeName string) (model.ClientScope, error) {
	if peer.AttestedBy != model.AttestationKubernetes {
		return model.ClientScope{}, fmt.Errorf("registry cannot resolve %q client attestation", peer.AttestedBy)
	}
	principal := peer.Principal
	if err := principal.Validate(); err != nil {
		return model.ClientScope{}, err
	}
	if principal.Kind != model.PrincipalServiceAccount {
		return model.ClientScope{}, fmt.Errorf("registry cannot resolve %q identities", principal.Kind)
	}
	if !s.synced() {
		return model.ClientScope{}, fmt.Errorf("registry is not synced")
	}
	pods, err := s.candidatePods(principal, peer, nodeName)
	if err != nil {
		return model.ClientScope{}, err
	}
	for _, pod := range pods {
		if pod.DeletionTimestamp != nil {
			continue
		}
		if pod.Namespace != principal.ServiceAccount.Namespace || pod.Spec.ServiceAccountName != principal.ServiceAccount.ServiceAccount {
			continue
		}
		// A pod-bound token proves which Pod the client runs in. Without the
		// binding, client metadata cannot establish Pod or node ownership.
		podBound := peer.Kubernetes.WorkloadUID != "" && string(pod.UID) == peer.Kubernetes.WorkloadUID
		if nodeName != "" && pod.Spec.NodeName != nodeName {
			continue
		}
		if podBound {
			name := principal.ServiceAccount.ServiceAccount
			key := pod.Namespace + "/" + name
			gateway := s.gateways.GetKey(key)
			if gateway != nil && gateway.ValidateForUse() == nil {
				if explicit := pod.Labels[podsource.LabelGatewayName]; explicit != "" && explicit != name {
					continue
				}
				return model.ClientScope{
					Class:      model.ClientEgressGateway,
					Principal:  principal,
					GatewayKey: key,
				}, nil
			}
		}
		if pod.Namespace == s.rootNamespace && pod.Spec.ServiceAccountName == s.ztunnelServiceAccount {
			if !podBound {
				continue
			}
			if nodeName == "" {
				continue
			}
			return model.ClientScope{
				Class:     model.ClientSharedZTunnel,
				Principal: principal,
				NodeName:  pod.Spec.NodeName,
			}, nil
		}
		if !podBound {
			continue
		}
		sandboxUID, err := s.singleSandboxBinding(pod, principal)
		if err != nil {
			return model.ClientScope{}, err
		}
		return model.ClientScope{
			Class:      model.ClientDedicatedZTunnel,
			Principal:  principal,
			SandboxUID: sandboxUID,
		}, nil
	}
	return model.ClientScope{}, fmt.Errorf("authenticated identity %s does not own the requested xDS client", principal.String())
}

// singleSandboxBinding resolves the dedicated ztunnel's Sandbox UID from the live Workload binding.
func (s *PodScopeResolver) singleSandboxBinding(pod *corev1.Pod, principal model.Principal) (string, error) {
	workloads := s.workloadsBySourceUID.Lookup(string(pod.UID))
	if len(workloads) != 1 {
		return "", fmt.Errorf("client Pod %s/%s resolves to %d active Workloads", pod.Namespace, pod.Name, len(workloads))
	}
	workload := workloads[0]
	if workload.SourceUID != string(pod.UID) || workload.UID != podsource.WorkloadUID(s.clusterID, pod) ||
		workload.Namespace != pod.Namespace || workload.Name != pod.Name || workload.Principal != principal {
		return "", fmt.Errorf("client Pod %s/%s does not match its active Workload", pod.Namespace, pod.Name)
	}
	if len(workload.SandboxBindings) != 1 {
		return "", fmt.Errorf("client Workload %s has %d Sandbox bindings; dedicated compatibility scope requires exactly one",
			workload.UID, len(workload.SandboxBindings))
	}
	binding := workload.SandboxBindings[0]
	if err := binding.Validate(); err != nil {
		return "", fmt.Errorf("client Workload %s has an invalid Sandbox binding: %w", workload.UID, err)
	}
	return binding.SandboxUID, nil
}

// candidatePods returns the narrowest Pod set the authenticated identity permits; hints never prove ownership.
func (s *PodScopeResolver) candidatePods(principal model.Principal, peer model.PeerIdentity, nodeName string) ([]*corev1.Pod, error) {
	if peer.Kubernetes.WorkloadName != "" {
		pod := s.pods.GetKey(principal.ServiceAccount.Namespace + "/" + peer.Kubernetes.WorkloadName)
		if pod == nil {
			return nil, fmt.Errorf("client pod %s/%s does not exist", principal.ServiceAccount.Namespace, peer.Kubernetes.WorkloadName)
		}
		return []*corev1.Pod{*pod}, nil
	}
	var result []*corev1.Pod
	if nodeName != "" {
		result = s.podsByNode.Lookup(nodeName)
	} else {
		result = s.pods.List()
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Namespace != result[j].Namespace {
			return result[i].Namespace < result[j].Namespace
		}
		return result[i].Name < result[j].Name
	})
	return result, nil
}
