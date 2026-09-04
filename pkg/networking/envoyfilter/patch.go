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
	"sort"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"github.com/openkruise/agentio/pkg/model"
)

type patchTarget uint8

const (
	clusterTarget patchTarget = iota + 1
	listenerTarget
	listenerFilterTarget
	filterChainTarget
	networkFilterTarget
	httpFilterTarget
	routeConfigurationTarget
	virtualHostTarget
	httpRouteTarget
	extensionConfigurationTarget
)

type Patch struct {
	Target    model.PatchTarget
	Operation model.PatchOperation
	FullName  string
}

type PatchSet struct{ byTarget map[patchTarget][]Patch }

// Patches is an alias of PatchSet used by the application functions.
type Patches = PatchSet

func NewPatchSet(patches []model.GatewayPatch) *PatchSet {
	ordered := append([]model.GatewayPatch(nil), patches...)
	sort.SliceStable(ordered, func(left, right int) bool {
		if ordered[left].Priority != ordered[right].Priority {
			return ordered[left].Priority < ordered[right].Priority
		}
		if !ordered[left].CreationTime.Equal(ordered[right].CreationTime) {
			return ordered[left].CreationTime.Before(ordered[right].CreationTime)
		}
		return ordered[left].LogicalName() < ordered[right].LogicalName()
	})
	result := &PatchSet{byTarget: make(map[patchTarget][]Patch)}
	for _, declaration := range ordered {
		for _, patch := range declaration.Patches {
			target := targetKind(patch.Target)
			if target == 0 {
				continue
			}
			result.byTarget[target] = append(result.byTarget[target], Patch{
				Target: patch.Target, Operation: patch.Operation, FullName: declaration.LogicalName(),
			})
		}
	}
	return result
}

func (p *PatchSet) For(target patchTarget) []Patch {
	if p == nil {
		return nil
	}
	return p.byTarget[target]
}

func (p *PatchSet) Names(target patchTarget) []string {
	patches := p.For(target)
	result := make([]string, 0, len(patches))
	for _, patch := range patches {
		result = append(result, patch.FullName)
	}
	return result
}

func targetKind(target model.PatchTarget) patchTarget {
	switch target.(type) {
	case model.ClusterPatch:
		return clusterTarget
	case model.ListenerPatch:
		return listenerTarget
	case model.ListenerFilterPatch:
		return listenerFilterTarget
	case model.FilterChainPatch:
		return filterChainTarget
	case model.NetworkFilterPatch:
		return networkFilterTarget
	case model.HTTPFilterPatch:
		return httpFilterTarget
	case model.RouteConfigurationPatch:
		return routeConfigurationTarget
	case model.VirtualHostPatch:
		return virtualHostTarget
	case model.HTTPRoutePatch:
		return httpRouteTarget
	case model.ExtensionConfigurationPatch:
		return extensionConfigurationTarget
	default:
		return 0
	}
}

func (p Patch) cluster() model.ClusterPatch { return p.Target.(model.ClusterPatch) }

func (p Patch) listener() model.ListenerPatch { return p.Target.(model.ListenerPatch) }

func (p Patch) listenerFilter() model.ListenerFilterPatch {
	return p.Target.(model.ListenerFilterPatch)
}

func (p Patch) filterChain() model.FilterChainPatch { return p.Target.(model.FilterChainPatch) }

func (p Patch) networkFilter() model.NetworkFilterPatch {
	return p.Target.(model.NetworkFilterPatch)
}

func (p Patch) httpFilter() model.HTTPFilterPatch { return p.Target.(model.HTTPFilterPatch) }

func (p Patch) routeConfiguration() model.RouteConfigurationPatch {
	return p.Target.(model.RouteConfigurationPatch)
}

func (p Patch) virtualHost() model.VirtualHostPatch { return p.Target.(model.VirtualHostPatch) }

func (p Patch) httpRoute() model.HTTPRoutePatch { return p.Target.(model.HTTPRoutePatch) }

func (p Patch) extensionConfiguration() model.ExtensionConfigurationPatch {
	return p.Target.(model.ExtensionConfigurationPatch)
}

func (p Patch) listenerMatch() *model.ListenerMatch {
	switch target := p.Target.(type) {
	case model.ListenerPatch:
		return target.Match
	case model.ListenerFilterPatch:
		return target.Match
	case model.FilterChainPatch:
		return target.Match
	case model.NetworkFilterPatch:
		return target.Match
	case model.HTTPFilterPatch:
		return target.Match
	default:
		return nil
	}
}

func (p Patch) routeMatch() *model.RouteConfigurationMatch {
	switch target := p.Target.(type) {
	case model.RouteConfigurationPatch:
		return target.Match
	case model.VirtualHostPatch:
		return target.Match
	case model.HTTPRoutePatch:
		return target.Match
	default:
		return nil
	}
}

// Compile-time assignments keep the concrete Envoy values visible beside the
// internal target accessors and catch accidental model drift.
var (
	_ *clusterv3.Cluster           = model.ClusterPatch{}.Value
	_ *listenerv3.Listener         = model.ListenerPatch{}.Value
	_ *listenerv3.ListenerFilter   = model.ListenerFilterPatch{}.Value
	_ *listenerv3.FilterChain      = model.FilterChainPatch{}.Value
	_ *listenerv3.Filter           = model.NetworkFilterPatch{}.Value
	_ *hcmv3.HttpFilter            = model.HTTPFilterPatch{}.Value
	_ *routev3.RouteConfiguration  = model.RouteConfigurationPatch{}.Value
	_ *routev3.VirtualHost         = model.VirtualHostPatch{}.Value
	_ *routev3.Route               = model.HTTPRoutePatch{}.Value
	_ *corev3.TypedExtensionConfig = model.ExtensionConfigurationPatch{}.Value
)
