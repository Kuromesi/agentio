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

package pod

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// IsManaged reports actual ztunnel injection or ambient redirection, rather
// than enrollment intent on the namespace.
func IsManaged(pod *corev1.Pod) bool {
	return HasInjectedZTunnel(pod) || AmbientRedirectionEnabled(pod)
}

// NewSandboxes is the legacy ordinary-Pod Sandbox derivation helper.
// The registry no longer calls it: ordinary Pods select policies as Workloads.
// Retained temporarily while the Sandbox-centric tests are migrated.
func NewSandboxes(
	pods krt.Collection[*corev1.Pod],
	clusterID string,
	runtimeOwned func(*corev1.Pod) bool,
	options ...krt.CollectionOption,
) krt.Collection[model.Sandbox] {
	return krt.NewCollection(pods, func(_ krt.HandlerContext, pod *corev1.Pod) *model.Sandbox {
		if runtimeOwned != nil && runtimeOwned(pod) {
			return nil
		}
		return sandboxFromPod(clusterID, pod)
	}, options...)
}

func sandboxFromPod(clusterID string, pod *corev1.Pod) *model.Sandbox {
	if !IsEligible(pod) || !IsManaged(pod) || pod.UID == "" {
		return nil
	}
	return &model.Sandbox{
		// Pod UID prevents a same-name replacement from reusing policy identity.
		UID:       model.SandboxUID(model.SandboxKindWorkload, string(pod.UID)),
		Namespace: pod.Namespace,
		Attester:  &model.Attester{WorkloadUID: WorkloadUID(clusterID, pod)},
	}
}
