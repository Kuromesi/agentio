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
	"encoding/json"
	"fmt"

	"github.com/openkruise/agentio/pkg/model"
)

type patchMatch struct {
	cluster  *model.ClusterMatch
	listener *model.ListenerMatch
	route    *model.RouteConfigurationMatch
}

type clusterMatch struct {
	Name string `json:"name,omitempty"`
}

type listenerMatch struct {
	Name           string            `json:"name,omitempty"`
	PortNumber     uint32            `json:"portNumber,omitempty"`
	ListenerFilter *string           `json:"listenerFilter,omitempty"`
	FilterChain    *filterChainMatch `json:"filterChain,omitempty"`
}

type filterChainMatch struct {
	Name                 string       `json:"name,omitempty"`
	SNI                  string       `json:"sni,omitempty"`
	TransportProtocol    string       `json:"transportProtocol,omitempty"`
	ApplicationProtocols string       `json:"applicationProtocols,omitempty"`
	DestinationPort      uint32       `json:"destinationPort,omitempty"`
	Filter               *filterMatch `json:"filter,omitempty"`
}

type filterMatch struct {
	Name      string          `json:"name"`
	SubFilter *subFilterMatch `json:"subFilter,omitempty"`
}

type subFilterMatch struct {
	Name string `json:"name"`
}

type routeConfigurationMatch struct {
	Name        string            `json:"name,omitempty"`
	VirtualHost *virtualHostMatch `json:"virtualHost,omitempty"`
}

type virtualHostMatch struct {
	Name       string      `json:"name,omitempty"`
	DomainName string      `json:"domainName,omitempty"`
	Route      *routeMatch `json:"route,omitempty"`
}

type routeMatch struct {
	Name   string `json:"name,omitempty"`
	Action string `json:"action,omitempty"`
}

func decodePatchMatch(target string, operation model.PatchOperation, raw json.RawMessage) (patchMatch, error) {
	var result patchMatch
	var err error
	switch target {
	case "cluster":
		if len(raw) > 0 {
			var match clusterMatch
			if err = decodePatchObject(raw, &match); err == nil {
				result.cluster = &model.ClusterMatch{Name: match.Name}
			}
			if operation == model.PatchAdd {
				err = fmt.Errorf("cluster ADD must omit match")
			}
		}
	case "listener", "listenerFilter", "filterChain", "networkFilter", "httpFilter":
		result.listener, err = decodeListenerMatch(target, operation, raw)
	case "routeConfiguration", "virtualHost", "httpRoute":
		result.route, err = decodeRouteMatch(target, operation, raw)
	case "extensionConfiguration":
		if len(raw) > 0 {
			err = fmt.Errorf("extensionConfiguration must omit match")
		}
	default:
		err = fmt.Errorf("unknown target %q", target)
	}
	return result, err
}

func decodeListenerMatch(target string, operation model.PatchOperation, raw json.RawMessage) (*model.ListenerMatch, error) {
	var match listenerMatch
	if len(raw) > 0 {
		if err := decodePatchObject(raw, &match); err != nil {
			return nil, err
		}
		if target == "listener" && operation == model.PatchAdd {
			return nil, fmt.Errorf("listener ADD must omit match")
		}
	}
	if err := validateListenerMatch(target, operation, match); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	result := &model.ListenerMatch{Name: match.Name, PortNumber: match.PortNumber}
	if match.ListenerFilter != nil {
		result.ListenerFilter = *match.ListenerFilter
	}
	if chain := match.FilterChain; chain != nil {
		result.FilterChain = &model.FilterChainMatch{
			Name: chain.Name, SNI: chain.SNI, TransportProtocol: chain.TransportProtocol,
			ApplicationProtocols: chain.ApplicationProtocols, DestinationPort: chain.DestinationPort,
		}
		if filter := chain.Filter; filter != nil {
			result.FilterChain.Filter = &model.FilterMatch{Name: filter.Name}
			if filter.SubFilter != nil {
				result.FilterChain.Filter.SubFilter = &model.SubFilterMatch{Name: filter.SubFilter.Name}
			}
		}
	}
	return result, nil
}

func validateListenerMatch(target string, operation model.PatchOperation, match listenerMatch) error {
	if match.PortNumber > 65535 {
		return fmt.Errorf("portNumber must be between 0 and 65535")
	}
	if match.ListenerFilter != nil && target != "listenerFilter" {
		return fmt.Errorf("listenerFilter is unused for target %s", target)
	}
	if target == "listenerFilter" {
		if match.FilterChain != nil {
			return fmt.Errorf("filterChain is unused for listenerFilter")
		}
		name := ""
		if match.ListenerFilter != nil {
			name = *match.ListenerFilter
		}
		return validateMatchAnchor(operation, name, match.ListenerFilter != nil, true)
	}
	if match.FilterChain != nil {
		if target == "listener" || (target == "filterChain" && operation == model.PatchAdd) {
			return fmt.Errorf("filterChain is unused for this target/operation")
		}
		if match.FilterChain.DestinationPort > 65535 {
			return fmt.Errorf("filterChain.destinationPort must be between 0 and 65535")
		}
	}
	if target == "networkFilter" || target == "httpFilter" {
		return validateFilterMatch(target, operation, match.FilterChain)
	}
	if match.FilterChain != nil && match.FilterChain.Filter != nil {
		return fmt.Errorf("filterChain.filter is unused for filterChain")
	}
	return nil
}

func validateFilterMatch(target string, operation model.PatchOperation, chain *filterChainMatch) error {
	var filter *filterMatch
	if chain != nil {
		filter = chain.Filter
	}
	if filter != nil && filter.Name == "" {
		return fmt.Errorf("filterChain.filter.name is required")
	}
	if target == "networkFilter" {
		if filter != nil && filter.SubFilter != nil {
			return fmt.Errorf("filterChain.filter.subFilter is unused for networkFilter")
		}
		name := ""
		if filter != nil {
			name = filter.Name
		}
		return validateMatchAnchor(operation, name, filter != nil, false)
	}
	name, present := "", false
	if filter != nil {
		if filter.Name != "envoy.filters.network.http_connection_manager" {
			return fmt.Errorf("httpFilter requires filterChain.filter.name envoy.filters.network.http_connection_manager")
		}
		if filter.SubFilter != nil {
			name, present = filter.SubFilter.Name, true
		}
	}
	return validateMatchAnchor(operation, name, present, false)
}

func validateMatchAnchor(operation model.PatchOperation, name string, present, mergeRequiresName bool) error {
	if present && name == "" {
		return fmt.Errorf("filter match name is required")
	}
	switch operation {
	case model.PatchAdd, model.PatchInsertFirst:
		if present {
			return fmt.Errorf("filter match is unused for ADD/INSERT_FIRST")
		}
	case model.PatchInsertBefore, model.PatchInsertAfter, model.PatchRemove, model.PatchReplace:
		if name == "" {
			return fmt.Errorf("operation requires a named filter match")
		}
	case model.PatchMerge:
		if mergeRequiresName && name == "" {
			return fmt.Errorf("MERGE requires a named listenerFilter match")
		}
	}
	return nil
}

func decodeRouteMatch(target string, operation model.PatchOperation, raw json.RawMessage) (*model.RouteConfigurationMatch, error) {
	if len(raw) == 0 {
		if operation == model.PatchInsertBefore || operation == model.PatchInsertAfter {
			return nil, fmt.Errorf("operation requires virtualHost.route.name")
		}
		return nil, nil
	}
	var match routeConfigurationMatch
	if err := decodePatchObject(raw, &match); err != nil {
		return nil, err
	}
	if err := validateRouteMatch(target, operation, match); err != nil {
		return nil, err
	}
	result := &model.RouteConfigurationMatch{Name: match.Name}
	if host := match.VirtualHost; host != nil {
		result.VirtualHost = &model.VirtualHostMatch{Name: host.Name, DomainName: host.DomainName}
		if route := host.Route; route != nil {
			action, err := parseRouteAction(route.Action)
			if err != nil {
				return nil, err
			}
			result.VirtualHost.Route = &model.RouteMatch{Name: route.Name, Action: action}
		}
	}
	return result, nil
}

func validateRouteMatch(target string, operation model.PatchOperation, match routeConfigurationMatch) error {
	host := match.VirtualHost
	if host != nil && (target == "routeConfiguration" || (target == "virtualHost" && operation == model.PatchAdd)) {
		return fmt.Errorf("virtualHost is unused for this target/operation")
	}
	var route *routeMatch
	if host != nil {
		route = host.Route
	}
	if route != nil && (target != "httpRoute" || operation == model.PatchAdd || operation == model.PatchInsertFirst) {
		return fmt.Errorf("virtualHost.route is unused for this target/operation")
	}
	if operation == model.PatchInsertBefore || operation == model.PatchInsertAfter {
		if route == nil || route.Name == "" {
			return fmt.Errorf("operation requires virtualHost.route.name")
		}
	}
	return nil
}

func parseRouteAction(action string) (model.RouteAction, error) {
	switch action {
	case "", "ANY":
		return model.RouteActionAny, nil
	case "ROUTE":
		return model.RouteActionRoute, nil
	case "REDIRECT":
		return model.RouteActionRedirect, nil
	case "DIRECT_RESPONSE":
		return model.RouteActionDirectResponse, nil
	default:
		return 0, fmt.Errorf("virtualHost.route.action: unknown action %q", action)
	}
}
