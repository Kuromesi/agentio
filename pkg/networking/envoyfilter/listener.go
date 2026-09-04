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
	"slices"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

const httpConnectionManagerFilter = "envoy.filters.network.http_connection_manager"

func ApplyListeners(patches *Patches, input []*listenerv3.Listener) ([]*listenerv3.Listener, error) {
	listeners := make([]*listenerv3.Listener, 0, len(input))
	for _, listener := range input {
		if listener == nil {
			continue
		}
		current := proto.Clone(listener).(*listenerv3.Listener)
		removed, err := applyListener(patches, current)
		if err != nil {
			return nil, err
		}
		if !removed {
			listeners = append(listeners, current)
		}
	}
	for _, patch := range patches.For(listenerTarget) {
		if patch.Operation != model.PatchAdd {
			continue
		}
		value := patch.listener().Value
		listeners = append(listeners, proto.Clone(value).(*listenerv3.Listener))
	}
	seen := sets.NewWithLength[string](len(listeners))
	for _, listener := range listeners {
		if listener.GetName() == "" {
			return nil, fmt.Errorf("EnvoyFilter produced a listener with an empty name")
		}
		if seen.Contains(listener.GetName()) {
			return nil, fmt.Errorf("EnvoyFilter produced duplicate listener %q", listener.GetName())
		}
		seen.Insert(listener.GetName())
	}
	return listeners, nil
}

func applyListener(patches *Patches, listener *listenerv3.Listener) (bool, error) {
	for _, patch := range patches.For(listenerTarget) {
		if !listenerMatches(listener, patch) {
			continue
		}
		switch patch.Operation {
		case model.PatchRemove:
			return true, nil
		case model.PatchMerge:
			value := patch.listener().Value
			Merge(listener, value)
		}
	}
	if err := applyListenerFilters(patches, listener); err != nil {
		return false, err
	}
	if err := applyFilterChains(patches, listener); err != nil {
		return false, err
	}
	return false, nil
}

func applyListenerFilters(patches *Patches, listener *listenerv3.Listener) error {
	for _, patch := range patches.For(listenerFilterTarget) {
		if !listenerMatches(listener, patch) {
			continue
		}
		value := patch.listenerFilter().Value
		switch patch.Operation {
		case model.PatchAdd:
			listener.ListenerFilters = append(listener.ListenerFilters, proto.Clone(value).(*listenerv3.ListenerFilter))
		case model.PatchInsertFirst:
			listener.ListenerFilters = append([]*listenerv3.ListenerFilter{proto.Clone(value).(*listenerv3.ListenerFilter)}, listener.ListenerFilters...)
		case model.PatchInsertAfter:
			if !hasListenerFilterMatch(patch) {
				listener.ListenerFilters = append(listener.ListenerFilters, proto.Clone(value).(*listenerv3.ListenerFilter))
				continue
			}
			listener.ListenerFilters, _ = insertAfter(listener.ListenerFilters, func(existing *listenerv3.ListenerFilter) (bool, *listenerv3.ListenerFilter) {
				return listenerFilterMatches(existing, patch), proto.Clone(value).(*listenerv3.ListenerFilter)
			})
		case model.PatchInsertBefore:
			if !hasListenerFilterMatch(patch) {
				listener.ListenerFilters = append([]*listenerv3.ListenerFilter{proto.Clone(value).(*listenerv3.ListenerFilter)}, listener.ListenerFilters...)
				continue
			}
			listener.ListenerFilters, _ = insertBefore(listener.ListenerFilters, func(existing *listenerv3.ListenerFilter) (bool, *listenerv3.ListenerFilter) {
				return listenerFilterMatches(existing, patch), proto.Clone(value).(*listenerv3.ListenerFilter)
			})
		case model.PatchReplace:
			if hasListenerFilterMatch(patch) {
				listener.ListenerFilters, _ = replaceFirst(listener.ListenerFilters, func(existing *listenerv3.ListenerFilter) (bool, *listenerv3.ListenerFilter) {
					return listenerFilterMatches(existing, patch), proto.Clone(value).(*listenerv3.ListenerFilter)
				})
			}
		case model.PatchRemove:
			if hasListenerFilterMatch(patch) {
				listener.ListenerFilters = filterSlice(listener.ListenerFilters,
					func(existing *listenerv3.ListenerFilter) bool { return !listenerFilterMatches(existing, patch) })
			}
		case model.PatchMerge:
			if hasListenerFilterMatch(patch) {
				for _, existing := range listener.ListenerFilters {
					if listenerFilterMatches(existing, patch) {
						if err := mergeListenerFilter(existing, value); err != nil {
							return fmt.Errorf("EnvoyFilter %s: %w", patch.FullName, err)
						}
					}
				}
			}
		}
	}
	return nil
}

func applyFilterChains(patches *Patches, listener *listenerv3.Listener) error {
	for _, chain := range listener.FilterChains {
		if chain == nil || chain.Filters == nil {
			continue
		}
		removed, err := applyFilterChain(patches, listener, chain)
		if err != nil {
			return err
		}
		if removed {
			chain.Filters = nil
		}
	}
	listener.FilterChains = filterSlice(listener.FilterChains,
		func(chain *listenerv3.FilterChain) bool { return chain != nil && chain.Filters != nil })
	if chain := listener.GetDefaultFilterChain(); chain != nil && chain.Filters != nil {
		removed, err := applyFilterChain(patches, listener, chain)
		if err != nil {
			return err
		}
		if removed {
			listener.DefaultFilterChain = nil
		}
	}
	for _, patch := range patches.For(filterChainTarget) {
		if patch.Operation != model.PatchAdd || !listenerMatches(listener, patch) {
			continue
		}
		value := patch.filterChain().Value
		listener.FilterChains = append(listener.FilterChains, proto.Clone(value).(*listenerv3.FilterChain))
	}
	return nil
}

func applyFilterChain(patches *Patches, listener *listenerv3.Listener, chain *listenerv3.FilterChain) (bool, error) {
	for _, patch := range patches.For(filterChainTarget) {
		if !listenerMatches(listener, patch) || !filterChainMatches(listener, chain, patch) {
			continue
		}
		switch patch.Operation {
		case model.PatchRemove:
			return true, nil
		case model.PatchMerge:
			value := patch.filterChain().Value
			merged, err := mergeFilterChainTransportSocket(chain, value)
			if err != nil {
				return false, fmt.Errorf("EnvoyFilter %s: %w", patch.FullName, err)
			}
			if !merged {
				Merge(chain, value)
			}
		}
	}
	return false, applyNetworkFilters(patches, listener, chain)
}

func applyNetworkFilters(patches *Patches, listener *listenerv3.Listener, chain *listenerv3.FilterChain) error {
	for _, patch := range patches.For(networkFilterTarget) {
		if !listenerMatches(listener, patch) || !filterChainMatches(listener, chain, patch) {
			continue
		}
		value := patch.networkFilter().Value
		switch patch.Operation {
		case model.PatchAdd:
			chain.Filters = append(chain.Filters, proto.Clone(value).(*listenerv3.Filter))
		case model.PatchInsertFirst:
			chain.Filters = append([]*listenerv3.Filter{proto.Clone(value).(*listenerv3.Filter)}, chain.Filters...)
		case model.PatchInsertAfter:
			if !hasNetworkFilterMatch(patch) {
				chain.Filters = append(chain.Filters, proto.Clone(value).(*listenerv3.Filter))
				continue
			}
			chain.Filters, _ = insertAfter(chain.Filters, func(existing *listenerv3.Filter) (bool, *listenerv3.Filter) {
				return networkFilterMatches(existing, patch), proto.Clone(value).(*listenerv3.Filter)
			})
		case model.PatchInsertBefore:
			if !hasNetworkFilterMatch(patch) {
				chain.Filters = append([]*listenerv3.Filter{proto.Clone(value).(*listenerv3.Filter)}, chain.Filters...)
				continue
			}
			chain.Filters, _ = insertBefore(chain.Filters, func(existing *listenerv3.Filter) (bool, *listenerv3.Filter) {
				return networkFilterMatches(existing, patch), proto.Clone(value).(*listenerv3.Filter)
			})
		case model.PatchReplace:
			if hasNetworkFilterMatch(patch) {
				chain.Filters, _ = replaceFirst(chain.Filters, func(existing *listenerv3.Filter) (bool, *listenerv3.Filter) {
					return networkFilterMatches(existing, patch), proto.Clone(value).(*listenerv3.Filter)
				})
			}
		case model.PatchRemove:
			if hasNetworkFilterMatch(patch) {
				chain.Filters = filterSlice(chain.Filters,
					func(existing *listenerv3.Filter) bool { return !networkFilterMatches(existing, patch) })
			}
		}
	}
	for _, filter := range chain.Filters {
		if err := mergeNetworkFilterAndPatchHTTP(patches, listener, chain, filter); err != nil {
			return err
		}
	}
	return nil
}

func mergeNetworkFilterAndPatchHTTP(patches *Patches, listener *listenerv3.Listener, chain *listenerv3.FilterChain, filter *listenerv3.Filter) error {
	for _, patch := range patches.For(networkFilterTarget) {
		if patch.Operation != model.PatchMerge ||
			!listenerMatches(listener, patch) || !filterChainMatches(listener, chain, patch) || !networkFilterMatches(filter, patch) {
			continue
		}
		if filter.GetTypedConfig() == nil {
			continue
		}
		value := patch.networkFilter().Value
		name := filter.GetName()
		if value.GetName() != "" {
			name = value.GetName()
		}
		if value.GetTypedConfig() != nil {
			merged, err := mergeAny(filter.GetTypedConfig(), value.GetTypedConfig())
			if err != nil {
				return fmt.Errorf("EnvoyFilter %s merge network filter: %w", patch.FullName, err)
			}
			filter.ConfigType = &listenerv3.Filter_TypedConfig{TypedConfig: merged}
		}
		filter.Name = name
	}
	if filter.GetName() == httpConnectionManagerFilter {
		return applyHTTPFilters(patches, listener, chain, filter)
	}
	return nil
}

func applyHTTPFilters(patches *Patches, listener *listenerv3.Listener, chain *listenerv3.FilterChain, networkFilter *listenerv3.Filter) error {
	if networkFilter.GetTypedConfig() == nil {
		return nil
	}
	manager := &hcmv3.HttpConnectionManager{}
	if err := networkFilter.GetTypedConfig().UnmarshalTo(manager); err != nil {
		return fmt.Errorf("unmarshal HTTP connection manager on listener %s: %w", listener.GetName(), err)
	}
	for _, patch := range patches.For(httpFilterTarget) {
		if !listenerMatches(listener, patch) || !filterChainMatches(listener, chain, patch) ||
			!networkFilterMatches(networkFilter, patch) {
			continue
		}
		value := patch.httpFilter().Value
		switch patch.Operation {
		case model.PatchAdd:
			manager.HttpFilters = append(manager.HttpFilters, proto.Clone(value).(*hcmv3.HttpFilter))
		case model.PatchInsertFirst:
			manager.HttpFilters = append([]*hcmv3.HttpFilter{proto.Clone(value).(*hcmv3.HttpFilter)}, manager.HttpFilters...)
		case model.PatchInsertAfter:
			if !hasHTTPFilterMatch(patch) {
				manager.HttpFilters = append(manager.HttpFilters, proto.Clone(value).(*hcmv3.HttpFilter))
				continue
			}
			manager.HttpFilters, _ = insertAfter(manager.HttpFilters, func(existing *hcmv3.HttpFilter) (bool, *hcmv3.HttpFilter) {
				return httpFilterMatches(existing, patch), proto.Clone(value).(*hcmv3.HttpFilter)
			})
		case model.PatchInsertBefore:
			if !hasHTTPFilterMatch(patch) {
				manager.HttpFilters = append([]*hcmv3.HttpFilter{proto.Clone(value).(*hcmv3.HttpFilter)}, manager.HttpFilters...)
				continue
			}
			manager.HttpFilters, _ = insertBefore(manager.HttpFilters, func(existing *hcmv3.HttpFilter) (bool, *hcmv3.HttpFilter) {
				return httpFilterMatches(existing, patch), proto.Clone(value).(*hcmv3.HttpFilter)
			})
		case model.PatchReplace:
			if hasHTTPFilterMatch(patch) {
				manager.HttpFilters, _ = replaceFirst(manager.HttpFilters, func(existing *hcmv3.HttpFilter) (bool, *hcmv3.HttpFilter) {
					return httpFilterMatches(existing, patch), proto.Clone(value).(*hcmv3.HttpFilter)
				})
			}
		case model.PatchRemove:
			if hasHTTPFilterMatch(patch) {
				manager.HttpFilters = filterSlice(manager.HttpFilters,
					func(existing *hcmv3.HttpFilter) bool { return !httpFilterMatches(existing, patch) })
			}
		}
	}
	for _, existing := range manager.HttpFilters {
		for _, patch := range patches.For(httpFilterTarget) {
			if patch.Operation != model.PatchMerge ||
				!listenerMatches(listener, patch) || !filterChainMatches(listener, chain, patch) ||
				!networkFilterMatches(networkFilter, patch) || !httpFilterMatches(existing, patch) {
				continue
			}
			value := patch.httpFilter().Value
			if existing.GetTypedConfig() == nil {
				continue
			}
			name := existing.GetName()
			if value.GetName() != "" {
				name = value.GetName()
			}
			if value.GetTypedConfig() != nil {
				merged, err := mergeAny(existing.GetTypedConfig(), value.GetTypedConfig())
				if err != nil {
					return fmt.Errorf("EnvoyFilter %s merge HTTP filter: %w", patch.FullName, err)
				}
				existing.ConfigType = &hcmv3.HttpFilter_TypedConfig{TypedConfig: merged}
			}
			existing.Name = name
		}
	}
	encoded, err := anypb.New(manager)
	if err != nil {
		return err
	}
	networkFilter.ConfigType = &listenerv3.Filter_TypedConfig{TypedConfig: encoded}
	return nil
}

func mergeListenerFilter(destination, patch *listenerv3.ListenerFilter) error {
	if destination.GetTypedConfig() == nil {
		return nil
	}
	name := destination.GetName()
	if patch.GetName() != "" {
		name = patch.GetName()
	}
	if patch.GetTypedConfig() != nil {
		merged, err := mergeAny(destination.GetTypedConfig(), patch.GetTypedConfig())
		if err != nil {
			return err
		}
		destination.ConfigType = &listenerv3.ListenerFilter_TypedConfig{TypedConfig: merged}
	}
	destination.Name = name
	return nil
}

func mergeFilterChainTransportSocket(destination, patch *listenerv3.FilterChain) (bool, error) {
	if patch.GetTransportSocket() == nil || destination.GetTransportSocket() == nil ||
		patch.GetTransportSocket().GetName() != destination.GetTransportSocket().GetName() {
		return false, nil
	}
	if patch.GetTransportSocket().GetTypedConfig() == nil || destination.GetTransportSocket().GetTypedConfig() == nil {
		return true, nil
	}
	merged, err := mergeAny(destination.GetTransportSocket().GetTypedConfig(), patch.GetTransportSocket().GetTypedConfig())
	if err != nil {
		return false, err
	}
	destination.TransportSocket.ConfigType = &corev3.TransportSocket_TypedConfig{TypedConfig: merged}
	return true, nil
}

func listenerMatches(listener *listenerv3.Listener, patch Patch) bool {
	match := patch.listenerMatch()
	if match == nil {
		return true
	}
	if match.Name != "" && match.Name != listener.GetName() {
		return false
	}
	if match.PortNumber != 0 {
		address := listener.GetAddress().GetSocketAddress()
		if address == nil || address.GetPortValue() != match.PortNumber {
			return false
		}
	}
	return true
}

func filterChainMatches(_ *listenerv3.Listener, chain *listenerv3.FilterChain, patch Patch) bool {
	listenerMatch := patch.listenerMatch()
	if listenerMatch == nil || listenerMatch.FilterChain == nil {
		return true
	}
	match := listenerMatch.FilterChain
	if match.Name != "" && match.Name != chain.GetName() {
		return false
	}
	if match.SNI != "" {
		matched := slices.Contains(chain.GetFilterChainMatch().GetServerNames(), match.SNI)
		if !matched {
			return false
		}
	}
	if match.TransportProtocol != "" && match.TransportProtocol != chain.GetFilterChainMatch().GetTransportProtocol() {
		return false
	}
	if match.ApplicationProtocols != "" {
		protocols := chain.GetFilterChainMatch().GetApplicationProtocols()
		for wanted := range strings.SplitSeq(match.ApplicationProtocols, ",") {
			found := slices.Contains(protocols, wanted)
			if !found {
				return false
			}
		}
	}
	if match.DestinationPort != 0 && match.DestinationPort != chain.GetFilterChainMatch().GetDestinationPort().GetValue() {
		return false
	}
	return true
}

func hasListenerFilterMatch(patch Patch) bool {
	return patch.listenerMatch() != nil && patch.listenerMatch().ListenerFilter != ""
}

func listenerFilterMatches(filter *listenerv3.ListenerFilter, patch Patch) bool {
	return !hasListenerFilterMatch(patch) || patch.listenerMatch().ListenerFilter == filter.GetName()
}

func hasNetworkFilterMatch(patch Patch) bool {
	match := patch.listenerMatch()
	return match != nil && match.FilterChain != nil && match.FilterChain.Filter != nil
}

func networkFilterMatches(filter *listenerv3.Filter, patch Patch) bool {
	return !hasNetworkFilterMatch(patch) || patch.listenerMatch().FilterChain.Filter.Name == filter.GetName()
}

func hasHTTPFilterMatch(patch Patch) bool {
	return hasNetworkFilterMatch(patch) && patch.listenerMatch().FilterChain.Filter.SubFilter != nil
}

func httpFilterMatches(filter *hcmv3.HttpFilter, patch Patch) bool {
	return !hasHTTPFilterMatch(patch) || patch.listenerMatch().FilterChain.Filter.SubFilter.Name == filter.GetName()
}
