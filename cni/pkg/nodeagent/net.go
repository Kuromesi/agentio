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

package nodeagent

import (
	"strings"

	corev1 "k8s.io/api/core/v1"

	"istio.io/api/annotation"
	"istio.io/istio/cni/pkg/config"
	"istio.io/istio/cni/pkg/util"
)

const bridgePortPrefixesAnnotation = "agentio.io/reroute-bridge-port-prefixes"

func getPodLevelTrafficOverrides(pod *corev1.Pod) config.PodLevelOverrides {
	// If true, the pod will run in 'ingress mode'. This is intended to be used for "ingress" type workloads which handle
	// non-mesh traffic on inbound, and send to the mesh on outbound.
	// Basically, this just disables inbound redirection.
	podCfg := config.PodLevelOverrides{IngressMode: false}

	if ingressMode, present := util.CheckBooleanAnnotation(pod, annotation.AmbientBypassInboundCapture.Name); present {
		podCfg.IngressMode = ingressMode
	}

	podCfg.DNSProxy = config.PodDNSUnset

	if dnsCapture, present := util.CheckBooleanAnnotation(pod, annotation.AmbientDnsCapture.Name); present {
		if dnsCapture {
			podCfg.DNSProxy = config.PodDNSEnabled
		} else {
			podCfg.DNSProxy = config.PodDNSDisabled
		}
	}

	if virt, hasVirt := pod.Annotations[annotation.IoIstioRerouteVirtualInterfaces.Name]; hasVirt {
		virtInterfaces := strings.Split(virt, ",")
		for _, splitVirt := range virtInterfaces {
			trim := strings.TrimSpace(splitVirt)
			if trim != "" {
				podCfg.VirtualInterfaces = append(podCfg.VirtualInterfaces, trim)
			}
		}
	}

	if bridgePorts, found := pod.Annotations[bridgePortPrefixesAnnotation]; found {
		valid, invalid := parseBridgePortPrefixes(bridgePorts)
		podCfg.BridgePortPrefixes = valid
		if len(invalid) > 0 {
			log.WithLabels("namespace", pod.Namespace, "name", pod.Name).Warnf(
				"ignoring invalid %s values: %s", bridgePortPrefixesAnnotation, strings.Join(invalid, ","))
		}
	}

	return podCfg
}

func parseBridgePortPrefixes(raw string) ([]string, []string) {
	valid := make([]string, 0)
	invalid := make([]string, 0)
	seen := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		prefix := strings.TrimSpace(item)
		if prefix == "" {
			continue
		}
		if !isValidBridgePortPrefix(prefix) {
			invalid = append(invalid, prefix)
			continue
		}
		if _, found := seen[prefix]; found {
			continue
		}
		seen[prefix] = struct{}{}
		valid = append(valid, prefix)
	}
	return valid, invalid
}

func isValidBridgePortPrefix(prefix string) bool {
	if len(prefix) == 0 || len(prefix) > 14 || !isASCIILetterOrDigit(prefix[0]) {
		return false
	}
	for i := 1; i < len(prefix); i++ {
		if isASCIILetterOrDigit(prefix[i]) {
			continue
		}
		switch prefix[i] {
		case '.', '_', '-':
		default:
			return false
		}
	}
	return true
}

func isASCIILetterOrDigit(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}
