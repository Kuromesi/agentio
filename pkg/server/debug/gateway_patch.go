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

package debug

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/openkruise/agentio/pkg/model"
)

func configDebugGatewayPatch(patch model.GatewayPatch) (configDebugItem, error) {
	patches := make([]configDebugEnvoyPatch, 0, len(patch.Patches))
	for index, envoyPatch := range patch.Patches {
		adapted, err := configDebugPatch(envoyPatch)
		if err != nil {
			return configDebugItem{}, fmt.Errorf("patch %d: %w", index, err)
		}
		patches = append(patches, adapted)
	}
	spec, err := marshalConfigDebugJSON(configDebugGatewayPatchSpec{
		Priority:       patch.Priority,
		TargetGateways: append([]string(nil), patch.TargetGateways...),
		Patches:        patches,
	})
	return configDebugItem{
		Kind: "EnvoyFilter",
		Metadata: configDebugMetadata{
			Namespace:         patch.Namespace,
			Name:              patch.Name,
			Source:            patch.Source,
			ResourceVersion:   patch.ResourceVersion,
			CreationTimestamp: configDebugTime(patch.CreationTime),
		},
		Spec: spec,
	}, err
}

type configDebugGatewayPatchSpec struct {
	Priority       int32                   `json:"priority,omitempty"`
	TargetGateways []string                `json:"targetGateways,omitempty"`
	Patches        []configDebugEnvoyPatch `json:"patches"`
}

type configDebugEnvoyPatch struct {
	Operation string          `json:"operation"`
	Target    string          `json:"target"`
	Match     any             `json:"match,omitempty"`
	Value     json.RawMessage `json:"value,omitempty"`
}

func configDebugPatch(patch model.EnvoyPatch) (configDebugEnvoyPatch, error) {
	result := configDebugEnvoyPatch{Operation: configDebugPatchOperation(patch.Operation)}
	var value proto.Message
	switch target := patch.Target.(type) {
	case model.ClusterPatch:
		result.Target, result.Match, value = "cluster", configDebugClusterMatchValue(target.Match), target.Value
	case model.ListenerPatch:
		result.Target, result.Match, value = "listener", configDebugListenerMatchValue(target.Match), target.Value
	case model.ListenerFilterPatch:
		result.Target, result.Match, value = "listenerFilter", configDebugListenerMatchValue(target.Match), target.Value
	case model.FilterChainPatch:
		result.Target, result.Match, value = "filterChain", configDebugListenerMatchValue(target.Match), target.Value
	case model.NetworkFilterPatch:
		result.Target, result.Match, value = "networkFilter", configDebugListenerMatchValue(target.Match), target.Value
	case model.HTTPFilterPatch:
		result.Target, result.Match, value = "httpFilter", configDebugListenerMatchValue(target.Match), target.Value
	case model.RouteConfigurationPatch:
		result.Target, result.Match, value = "routeConfiguration", configDebugRouteConfigurationMatchValue(target.Match), target.Value
	case model.VirtualHostPatch:
		result.Target, result.Match, value = "virtualHost", configDebugRouteConfigurationMatchValue(target.Match), target.Value
	case model.HTTPRoutePatch:
		result.Target, result.Match, value = "httpRoute", configDebugRouteConfigurationMatchValue(target.Match), target.Value
	case model.ExtensionConfigurationPatch:
		result.Target, value = "extensionConfiguration", target.Value
	default:
		return configDebugEnvoyPatch{}, fmt.Errorf("unsupported patch target %T", patch.Target)
	}
	if value != nil {
		encoded, err := marshalConfigDebugProto(value)
		if err != nil {
			return configDebugEnvoyPatch{}, err
		}
		result.Value = encoded
	}
	return result, nil
}

type configDebugClusterMatch struct {
	Name       string `json:"name,omitempty"`
	Service    string `json:"service,omitempty"`
	Subset     string `json:"subset,omitempty"`
	PortNumber uint32 `json:"portNumber,omitempty"`
}

type configDebugListenerMatch struct {
	Name           string                  `json:"name,omitempty"`
	PortNumber     uint32                  `json:"portNumber,omitempty"`
	ListenerFilter string                  `json:"listenerFilter,omitempty"`
	FilterChain    *configDebugFilterChain `json:"filterChain,omitempty"`
}

type configDebugFilterChain struct {
	Name                 string                    `json:"name,omitempty"`
	SNI                  string                    `json:"sni,omitempty"`
	TransportProtocol    string                    `json:"transportProtocol,omitempty"`
	ApplicationProtocols string                    `json:"applicationProtocols,omitempty"`
	DestinationPort      uint32                    `json:"destinationPort,omitempty"`
	Filter               *configDebugNetworkFilter `json:"filter,omitempty"`
}

type configDebugNetworkFilter struct {
	Name      string                `json:"name,omitempty"`
	SubFilter *configDebugSubFilter `json:"subFilter,omitempty"`
}

type configDebugSubFilter struct {
	Name string `json:"name,omitempty"`
}

type configDebugRouteConfigurationMatch struct {
	Name        string                  `json:"name,omitempty"`
	PortName    string                  `json:"portName,omitempty"`
	Gateway     string                  `json:"gateway,omitempty"`
	PortNumber  uint32                  `json:"portNumber,omitempty"`
	VirtualHost *configDebugVirtualHost `json:"virtualHost,omitempty"`
}

type configDebugVirtualHost struct {
	Name       string            `json:"name,omitempty"`
	DomainName string            `json:"domainName,omitempty"`
	Route      *configDebugRoute `json:"route,omitempty"`
}

type configDebugRoute struct {
	Name   string `json:"name,omitempty"`
	Action string `json:"action,omitempty"`
}

func configDebugClusterMatchValue(match *model.ClusterMatch) any {
	if match == nil {
		return nil
	}
	return configDebugClusterMatch{
		Name:       match.Name,
		Service:    match.Service,
		Subset:     match.Subset,
		PortNumber: match.PortNumber,
	}
}

func configDebugListenerMatchValue(match *model.ListenerMatch) any {
	if match == nil {
		return nil
	}
	return configDebugListenerMatch{
		Name:           match.Name,
		PortNumber:     match.PortNumber,
		ListenerFilter: match.ListenerFilter,
		FilterChain:    configDebugFilterChainValue(match.FilterChain),
	}
}

func configDebugFilterChainValue(match *model.FilterChainMatch) *configDebugFilterChain {
	if match == nil {
		return nil
	}
	return &configDebugFilterChain{
		Name:                 match.Name,
		SNI:                  match.SNI,
		TransportProtocol:    match.TransportProtocol,
		ApplicationProtocols: match.ApplicationProtocols,
		DestinationPort:      match.DestinationPort,
		Filter:               configDebugFilterValue(match.Filter),
	}
}

func configDebugFilterValue(match *model.FilterMatch) *configDebugNetworkFilter {
	if match == nil {
		return nil
	}
	result := &configDebugNetworkFilter{Name: match.Name}
	if match.SubFilter != nil {
		result.SubFilter = &configDebugSubFilter{Name: match.SubFilter.Name}
	}
	return result
}

func configDebugRouteConfigurationMatchValue(match *model.RouteConfigurationMatch) any {
	if match == nil {
		return nil
	}
	return configDebugRouteConfigurationMatch{
		Name:        match.Name,
		PortName:    match.PortName,
		Gateway:     match.Gateway,
		PortNumber:  match.PortNumber,
		VirtualHost: configDebugVirtualHostValue(match.VirtualHost),
	}
}

func configDebugVirtualHostValue(match *model.VirtualHostMatch) *configDebugVirtualHost {
	if match == nil {
		return nil
	}
	result := &configDebugVirtualHost{Name: match.Name, DomainName: match.DomainName}
	if match.Route != nil {
		result.Route = &configDebugRoute{Name: match.Route.Name, Action: configDebugRouteAction(match.Route.Action)}
	}
	return result
}

func configDebugPatchOperation(operation model.PatchOperation) string {
	switch operation {
	case model.PatchAdd:
		return "ADD"
	case model.PatchMerge:
		return "MERGE"
	case model.PatchRemove:
		return "REMOVE"
	case model.PatchReplace:
		return "REPLACE"
	case model.PatchInsertBefore:
		return "INSERT_BEFORE"
	case model.PatchInsertAfter:
		return "INSERT_AFTER"
	case model.PatchInsertFirst:
		return "INSERT_FIRST"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", operation)
	}
}

func configDebugRouteAction(action model.RouteAction) string {
	switch action {
	case model.RouteActionAny:
		return "ANY"
	case model.RouteActionRoute:
		return "ROUTE"
	case model.RouteActionRedirect:
		return "REDIRECT"
	case model.RouteActionDirectResponse:
		return "DIRECT_RESPONSE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", action)
	}
}
