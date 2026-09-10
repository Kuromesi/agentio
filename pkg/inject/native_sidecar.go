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
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	klabels "k8s.io/apimachinery/pkg/labels"

	"github.com/openkruise/agentio/pkg/kube/kclient"
)

// detectNativeSidecar requires every node's kubelet to be at least 1.33 in
// auto mode; otherwise native sidecars are disabled.
func detectNativeSidecar(nodes kclient.Reader[*corev1.Node], mode NativeSidecarMode, podNodeName string) bool {
	switch mode {
	case NativeSidecarModeDisabled:
		return false
	case NativeSidecarModeEnabled:
		return true
	}

	if nodes == nil {
		log.Warn("cannot auto-detect native sidecar support without a Kubernetes client")
		return false
	}

	// Native sidecars feature graduated to stable in Kubernetes 1.33
	const minVersion = 33

	checkNodeVersion := func(n *corev1.Node) bool {
		minor, err := kubeletMinorVersion(n.Status.NodeInfo.KubeletVersion)
		if err != nil {
			log.Warn("read node version", "node", n.Name,
				"kubelet_version", n.Status.NodeInfo.KubeletVersion, "error", err)
			return false
		}
		if minor < minVersion {
			log.Debug("native sidecars disabled because kubelet is below the minimum version",
				"node", n.Name, "kubelet_minor", minor, "minimum_minor", minVersion)
			return false
		}
		return true
	}

	if podNodeName != "" {
		node := nodes.Get(podNodeName, "")
		if node != nil {
			return checkNodeVersion(node)
		}
		log.Warn("pod node not found in cluster", "node", podNodeName)
	}
	// Check all nodes to see if they are eligible to support native sidecars. If any node is below the minimum version, we disable the feature.
	// This avoids issues with mixed clusters where some nodes support native sidecars and others do not.
	for _, n := range nodes.List(metav1.NamespaceAll, klabels.Everything()) {
		if !checkNodeVersion(n) {
			return false
		}
	}
	return true
}

// kubeletMinorVersion parses the minor version out of a kubelet version
// string such as "v1.33.1" or "v1.28.3+k3s1".
func kubeletMinorVersion(version string) (int, error) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return 0, fmt.Errorf("unparseable kubelet version %q", version)
	}
	digits := parts[1]
	for i, r := range digits {
		if r < '0' || r > '9' {
			digits = digits[:i]
			break
		}
	}
	return strconv.Atoi(digits)
}
