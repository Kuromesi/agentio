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

package envoyfilter

import (
	"fmt"
	"strconv"
	"strings"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

func ApplyClusters(patches *Patches, input []*clusterv3.Cluster) ([]*clusterv3.Cluster, error) {
	clusters := make([]*clusterv3.Cluster, 0, len(input))
	for _, cluster := range input {
		if cluster == nil {
			continue
		}
		current := proto.Clone(cluster).(*clusterv3.Cluster)
		removed, err := applyClusterPatches(patches, current)
		if err != nil {
			return nil, err
		}
		if !removed {
			clusters = append(clusters, current)
		}
	}
	for _, patch := range patches.For(clusterTarget) {
		if patch.Operation != model.PatchAdd {
			continue
		}
		value := patch.cluster().Value
		clusters = append(clusters, proto.Clone(value).(*clusterv3.Cluster))
	}
	if err := uniqueClusterNames(clusters); err != nil {
		return nil, err
	}
	return clusters, nil
}

func applyClusterPatches(patches *Patches, cluster *clusterv3.Cluster) (bool, error) {
	for _, patch := range patches.For(clusterTarget) {
		if !clusterMatches(cluster, patch) {
			continue
		}
		switch patch.Operation {
		case model.PatchRemove:
			return true, nil
		case model.PatchMerge:
			value := patch.cluster().Value
			merged, err := mergeTransportSocketCluster(cluster, value)
			if err != nil {
				return false, fmt.Errorf("EnvoyFilter %s: %w", patch.FullName, err)
			}
			if !merged {
				Merge(cluster, value)
			}
		}
	}
	return false, nil
}

func clusterMatches(cluster *clusterv3.Cluster, patch Patch) bool {
	match := patch.cluster().Match
	if match == nil {
		return true
	}
	if match.Name != "" {
		return match.Name == cluster.GetName()
	}
	_, port, subset, hostname := parseSubsetKey(cluster.GetName())
	if match.Subset != "" && match.Subset != subset {
		return false
	}
	if match.Service != "" && match.Service != hostname {
		return false
	}
	return match.PortNumber == 0 || int(match.PortNumber) == port
}

func parseSubsetKey(name string) (direction string, port int, subset, hostname string) {
	separator := "|"
	if strings.HasPrefix(name, "outbound_.") || strings.HasPrefix(name, "inbound_.") {
		separator = "_."
	}
	direction, remainder, found := strings.Cut(name, separator)
	if !found {
		return "", 0, "", ""
	}
	portText, remainder, found := strings.Cut(remainder, separator)
	if !found {
		return direction, 0, "", ""
	}
	port, _ = strconv.Atoi(portText)
	subset, hostname, found = strings.Cut(remainder, separator)
	if !found || strings.Contains(hostname, separator) {
		return direction, port, subset, ""
	}
	return direction, port, subset, hostname
}

func mergeTransportSocketCluster(destination, patch *clusterv3.Cluster) (bool, error) {
	if patch.GetTransportSocket() == nil {
		return false, nil
	}
	var target *corev3.TransportSocket
	if len(destination.GetTransportSocketMatches()) > 0 {
		for _, candidate := range destination.GetTransportSocketMatches() {
			if candidate.GetTransportSocket() != nil &&
				candidate.GetTransportSocket().GetName() == patch.GetTransportSocket().GetName() {
				target = candidate.GetTransportSocket()
				break
			}
		}
		if target == nil {
			return true, nil
		}
	} else if destination.GetTransportSocket() != nil &&
		destination.GetTransportSocket().GetName() == patch.GetTransportSocket().GetName() {
		target = destination.GetTransportSocket()
	}
	if target == nil {
		destination.TransportSocket = proto.Clone(patch.GetTransportSocket()).(*corev3.TransportSocket)
		return true, nil
	}
	if target.GetTypedConfig() == nil || patch.GetTransportSocket().GetTypedConfig() == nil {
		return true, nil
	}
	merged, err := mergeAny(target.GetTypedConfig(), patch.GetTransportSocket().GetTypedConfig())
	if err != nil {
		return false, fmt.Errorf("merge transport socket: %w", err)
	}
	target.ConfigType = &corev3.TransportSocket_TypedConfig{TypedConfig: merged}
	return true, nil
}

func mergeAny(destination, patch *anypb.Any) (*anypb.Any, error) {
	if destination.GetTypeUrl() != patch.GetTypeUrl() {
		return nil, fmt.Errorf("type mismatch %q != %q", destination.GetTypeUrl(), patch.GetTypeUrl())
	}
	destinationMessage, err := anypb.UnmarshalNew(destination, proto.UnmarshalOptions{})
	if err != nil {
		return nil, err
	}
	patchMessage, err := anypb.UnmarshalNew(patch, proto.UnmarshalOptions{})
	if err != nil {
		return nil, err
	}
	Merge(destinationMessage, patchMessage)
	return anypb.New(destinationMessage)
}

func uniqueClusterNames(clusters []*clusterv3.Cluster) error {
	seen := sets.NewWithLength[string](len(clusters))
	for _, cluster := range clusters {
		if cluster.GetName() == "" {
			return fmt.Errorf("EnvoyFilter produced a cluster with an empty name")
		}
		if seen.Contains(cluster.GetName()) {
			return fmt.Errorf("EnvoyFilter produced duplicate cluster %q", cluster.GetName())
		}
		seen.Insert(cluster.GetName())
	}
	return nil
}
