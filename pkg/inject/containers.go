// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package inject

import (
	corev1 "k8s.io/api/core/v1"

	"istio.io/istio/pkg/slices"
)

type ContainerReorder int

const (
	MoveFirst ContainerReorder = iota
	MoveLast
	Remove
)

func moveContainer(from, to []corev1.Container, name string) ([]corev1.Container, []corev1.Container) {
	var container *corev1.Container
	for i, c := range from {
		if from[i].Name == name {
			from = slices.Delete(from, i)
			container = &c
			break
		}
	}
	if container != nil {
		to = append(to, *container)
	}
	return from, to
}

func modifyContainers(cl []corev1.Container, name string, modifier ContainerReorder) []corev1.Container {
	containers := []corev1.Container{}
	var match *corev1.Container
	for _, c := range cl {
		if c.Name != name {
			containers = append(containers, c)
		} else {
			match = &c
		}
	}
	if match == nil {
		return containers
	}
	switch modifier {
	case MoveFirst:
		return append([]corev1.Container{*match}, containers...)
	case MoveLast:
		return append(containers, *match)
	case Remove:
		return containers
	default:
		return cl
	}
}

func hasContainer(cl []corev1.Container, name string) bool {
	for _, c := range cl {
		if c.Name == name {
			return true
		}
	}
	return false
}

// reorderPod ensures containers are properly ordered after merging
func reorderPod(pod *corev1.Pod, req InjectionParameters) error {
	holdPod := req.settings.HoldApplicationUntilProxyStarts

	proxyLocation := MoveLast
	// If HoldApplicationUntilProxyStarts is set, reorder the proxy location
	if holdPod {
		proxyLocation = MoveFirst
	}

	// Proxy container should be last, unless HoldApplicationUntilProxyStarts is set
	// This is to ensure `kubectl exec` and similar commands continue to default to the user's container
	proxyName := proxyContainerName(pod.Spec)
	pod.Spec.Containers = modifyContainers(pod.Spec.Containers, proxyName, proxyLocation)
	if hasContainer(pod.Spec.InitContainers, proxyName) {
		// This is using native sidecar support in Kubernetes.
		// We want istio to be first in this case, so init containers are part of the mesh
		// This is {agentio-init/agentio-validation} => proxy => rest.
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, EnableCoreDumpName, MoveFirst)
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, proxyName, MoveFirst)
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, ValidationContainerName, MoveFirst)
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, InitContainerName, MoveFirst)
	} else {
		// Else, we want iptables setup last so we do not blackhole init containers
		// This is agentio-validation => rest => agentio-init (note: only one of agentio-init or agentio-validation should be present)
		// Validation container must be first to block any user containers
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, ValidationContainerName, MoveFirst)
		// Init container must be last to allow any traffic to pass before iptables is setup
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, InitContainerName, MoveLast)
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, EnableCoreDumpName, MoveLast)
	}

	return nil
}
