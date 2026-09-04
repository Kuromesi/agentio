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

// Package pod translates ordinary Kubernetes Pods into Workload attesters.
package pod

import (
	"maps"
	"net/netip"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

const (
	LabelGatewayName = "gateway.networking.k8s.io/gateway-name"

	ambientRedirectionAnnotation = "ambient.istio.io/redirection"
)

// NewWorkloads translates eligible, unclaimed Pods into Workloads; claimedByRuntime excludes runtime-owned Pods.
func NewWorkloads(
	pods krt.Collection[*corev1.Pod],
	clusterID, trustDomain string,
	claimedByRuntime func(*corev1.Pod) bool,
	options ...krt.CollectionOption,
) krt.Collection[model.Workload] {
	return krt.NewCollection(pods, func(_ krt.HandlerContext, pod *corev1.Pod) *model.Workload {
		if claimedByRuntime != nil && claimedByRuntime(pod) {
			return nil
		}
		if !IsEligible(pod) {
			return nil
		}
		return workloadFromPod(clusterID, trustDomain, pod)
	}, options...)
}

// IsEligible reports whether a Pod has usable networking state for a
// Workload projection.
func IsEligible(pod *corev1.Pod) bool {
	if pod == nil || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return false
	}
	addresses := pod.Status.PodIPs
	if len(addresses) == 0 && pod.Status.PodIP != "" {
		addresses = []corev1.PodIP{{IP: pod.Status.PodIP}}
	}
	if len(addresses) == 0 {
		return false
	}
	for _, address := range addresses {
		if _, err := netip.ParseAddr(address.IP); err != nil {
			return false
		}
	}
	return true
}

// WorkloadUID returns the stable WDS identity used for a Pod-shaped Workload.
func WorkloadUID(clusterID string, pod *corev1.Pod) string {
	return clusterID + "//Pod/" + pod.Namespace + "/" + pod.Name
}

// BaseWorkloadFromPod projects only the Pod-owned networking and
// attester state. Runtime adapters add their own Sandbox bindings afterwards.
func BaseWorkloadFromPod(clusterID, trustDomain string, pod *corev1.Pod) *model.Workload {
	addresses := make([]string, 0, len(pod.Status.PodIPs))
	for _, address := range pod.Status.PodIPs {
		if address.IP != "" {
			addresses = append(addresses, address.IP)
		}
	}
	if len(addresses) == 0 && pod.Status.PodIP != "" {
		addresses = append(addresses, pod.Status.PodIP)
	}
	ready := false
	if pod.DeletionTimestamp == nil {
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				ready = true
			}
		}
	}
	uid := WorkloadUID(clusterID, pod)
	injected := HasInjectedZTunnel(pod)
	canonicalName, canonicalRevision := canonicalIdentity(pod)
	workload := &model.Workload{
		UID: uid,
		Principal: model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: trustDomain,
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      pod.Namespace,
				ServiceAccount: pod.Spec.ServiceAccountName,
			},
		},
		SourceUID:         string(pod.UID),
		Namespace:         pod.Namespace,
		Name:              pod.Name,
		CanonicalName:     canonicalName,
		CanonicalRevision: canonicalRevision,
		NodeName:          pod.Spec.NodeName,
		Addresses:         addresses,
		Labels:            cloneStringMap(pod.Labels),
		HostNetwork:       pod.Spec.HostNetwork,
		TunnelProtocol:    tunnelProtocol(pod, injected),
		NativeTunnel:      injected,
		Ready:             ready,
	}
	return workload
}

func canonicalIdentity(pod *corev1.Pod) (string, string) {
	name := firstNonEmptyLabel(pod.Labels, "app.kubernetes.io/name", "app")
	if name == "" {
		name = pod.Name
	}
	revision := firstNonEmptyLabel(pod.Labels, "app.kubernetes.io/version", "version")
	if revision == "" {
		revision = "latest"
	}
	return name, revision
}

func firstNonEmptyLabel(labels map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := labels[key]; value != "" {
			return value
		}
	}
	return ""
}

// HasInjectedZTunnel reports whether the Pod runs a sandbox-injected ztunnel.
func HasInjectedZTunnel(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for _, containers := range [][]corev1.Container{pod.Spec.Containers, pod.Spec.InitContainers} {
		for _, container := range containers {
			if isDedicatedZTunnelContainer(container) {
				return true
			}
		}
	}
	return false
}

func isDedicatedZTunnelContainer(container corev1.Container) bool {
	if (container.Name != "agentio-proxy" && container.Name != "istio-proxy") || len(container.Args) < 2 ||
		container.Args[0] != "proxy" || container.Args[1] != "ztunnel" {
		return false
	}
	sidecarMode, proxyMode := false, false
	for _, env := range container.Env {
		switch env.Name {
		case "ENABLE_SIDECAR_MODE":
			sidecarMode = env.Value == "true"
		case "PROXY_MODE":
			proxyMode = env.Value == "dedicated"
		}
	}
	return sidecarMode && proxyMode
}

// AmbientRedirectionEnabled reports whether ambient redirection makes a Pod
// HBONE-capable.
func AmbientRedirectionEnabled(pod *corev1.Pod) bool {
	return pod != nil && pod.Annotations[ambientRedirectionAnnotation] == "enabled"
}

func workloadFromPod(clusterID, trustDomain string, pod *corev1.Pod) *model.Workload {
	workload := BaseWorkloadFromPod(clusterID, trustDomain, pod)
	workload.SandboxBindings = []model.SandboxBinding{
		{
			SandboxUID: workload.UID,
		},
	}
	return workload
}

func tunnelProtocol(pod *corev1.Pod, injected bool) model.TunnelProtocol {
	if injected || AmbientRedirectionEnabled(pod) {
		return model.TunnelProtocolHBONE
	}
	return model.TunnelProtocolNone
}

func cloneStringMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	maps.Copy(result, input)
	return result
}
