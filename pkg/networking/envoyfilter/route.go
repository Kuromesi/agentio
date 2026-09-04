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
	"strconv"
	"strings"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

func ApplyRoutes(patches *Patches, input []*routev3.RouteConfiguration) ([]*routev3.RouteConfiguration, error) {
	routes := make([]*routev3.RouteConfiguration, 0, len(input))
	seen := sets.NewWithLength[string](len(input))
	for _, configuration := range input {
		if configuration == nil {
			continue
		}
		current := proto.Clone(configuration).(*routev3.RouteConfiguration)
		if err := applyRouteConfiguration(patches, current); err != nil {
			return nil, err
		}
		if current.GetName() == "" {
			return nil, fmt.Errorf("EnvoyFilter produced a route configuration with an empty name")
		}
		if seen.Contains(current.GetName()) {
			return nil, fmt.Errorf("EnvoyFilter produced duplicate route configuration %q", current.GetName())
		}
		seen.Insert(current.GetName())
		routes = append(routes, current)
	}
	return routes, nil
}

func applyRouteConfiguration(patches *Patches, configuration *routev3.RouteConfiguration) error {
	for _, patch := range patches.For(routeConfigurationTarget) {
		if patch.Operation != model.PatchMerge ||
			!routeConfigurationMatches(configuration, patch) {
			continue
		}
		value := patch.routeConfiguration().Value
		Merge(configuration, value)
	}
	// Mirror release-0.1 patchVirtualHosts ordering: REMOVE/MERGE/REPLACE run
	// first and REMOVE records the virtual host *name* rather than nil-ing the
	// slot; ADDs run next; finally every virtual host whose name was removed is
	// dropped. This makes a REMOVE also drop a later ADD of the same name and
	// every duplicate, matching release-0.1 instead of keeping the new host.
	removed := sets.New[string]()
	for index := range configuration.VirtualHosts {
		wasRemoved, err := applyVirtualHost(patches, configuration, index)
		if err != nil {
			return err
		}
		if wasRemoved {
			removed.Insert(configuration.VirtualHosts[index].GetName())
		}
	}
	for _, patch := range patches.For(virtualHostTarget) {
		if patch.Operation != model.PatchAdd ||
			!routeConfigurationMatches(configuration, patch) {
			continue
		}
		value := patch.virtualHost().Value
		configuration.VirtualHosts = append(configuration.VirtualHosts, proto.Clone(value).(*routev3.VirtualHost))
	}
	if removed.Len() > 0 {
		configuration.VirtualHosts = slices.DeleteFunc(configuration.VirtualHosts,
			func(host *routev3.VirtualHost) bool { return removed.Contains(host.GetName()) })
	}
	return nil
}

func applyVirtualHost(patches *Patches, configuration *routev3.RouteConfiguration, index int) (bool, error) {
	host := configuration.VirtualHosts[index]
	for _, patch := range patches.For(virtualHostTarget) {
		if !routeConfigurationMatches(configuration, patch) || !virtualHostMatches(host, patch) {
			continue
		}
		switch patch.Operation {
		case model.PatchRemove:
			return true, nil
		case model.PatchMerge:
			value := patch.virtualHost().Value
			Merge(host, value)
		case model.PatchReplace:
			value := patch.virtualHost().Value
			host = proto.Clone(value).(*routev3.VirtualHost)
			configuration.VirtualHosts[index] = host
		}
	}
	return false, applyHTTPRoutes(patches, configuration, host)
}

func applyHTTPRoutes(patches *Patches, configuration *routev3.RouteConfiguration, host *routev3.VirtualHost) error {
	for index, route := range host.Routes {
		for _, patch := range patches.For(httpRouteTarget) {
			if !routeConfigurationMatches(configuration, patch) ||
				!virtualHostMatches(host, patch) || !httpRouteMatches(route, patch) {
				continue
			}
			switch patch.Operation {
			case model.PatchRemove:
				host.Routes[index] = nil
			case model.PatchMerge:
				value := patch.httpRoute().Value
				Merge(route, value)
			}
		}
	}
	host.Routes = filterSlice(host.Routes, func(route *routev3.Route) bool { return route != nil })
	for _, patch := range patches.For(httpRouteTarget) {
		if !routeConfigurationMatches(configuration, patch) || !virtualHostMatches(host, patch) {
			continue
		}
		value := patch.httpRoute().Value
		switch patch.Operation {
		case model.PatchAdd:
			host.Routes = append(host.Routes, proto.Clone(value).(*routev3.Route))
		case model.PatchInsertAfter:
			if !hasHTTPRouteMatch(patch) {
				host.Routes = append(host.Routes, proto.Clone(value).(*routev3.Route))
				continue
			}
			host.Routes, _ = insertAfter(host.Routes, func(existing *routev3.Route) (bool, *routev3.Route) {
				return httpRouteMatches(existing, patch), proto.Clone(value).(*routev3.Route)
			})
		case model.PatchInsertBefore:
			if !hasHTTPRouteMatch(patch) {
				host.Routes = append([]*routev3.Route{proto.Clone(value).(*routev3.Route)}, host.Routes...)
				continue
			}
			host.Routes, _ = insertBefore(host.Routes, func(existing *routev3.Route) (bool, *routev3.Route) {
				return httpRouteMatches(existing, patch), proto.Clone(value).(*routev3.Route)
			})
		case model.PatchInsertFirst:
			if !hasHTTPRouteMatch(patch) {
				host.Routes = append([]*routev3.Route{proto.Clone(value).(*routev3.Route)}, host.Routes...)
				continue
			}
			for _, existing := range host.Routes {
				if httpRouteMatches(existing, patch) {
					host.Routes = append([]*routev3.Route{proto.Clone(value).(*routev3.Route)}, host.Routes...)
					break
				}
			}
		}
	}
	return nil
}

func routeConfigurationMatches(configuration *routev3.RouteConfiguration, patch Patch) bool {
	match := patch.routeMatch()
	if match == nil {
		return true
	}
	if match.Name != "" && match.Name != configuration.GetName() {
		return false
	}
	port, portName, gateway := parseGatewayRouteName(configuration.GetName())
	if match.PortName != "" && match.PortName != portName {
		return false
	}
	if match.Gateway != "" && match.Gateway != gateway {
		return false
	}
	return match.PortNumber == 0 || int(match.PortNumber) == port
}

func parseGatewayRouteName(name string) (port int, portName, gateway string) {
	if after, ok := strings.CutPrefix(name, "http."); ok {
		port, _ = strconv.Atoi(after)
		return port, "", ""
	}
	if !strings.HasPrefix(name, "https.") || strings.Count(name, ".") != 4 {
		return 0, "", ""
	}
	parts := strings.Split(strings.TrimPrefix(name, "https."), ".")
	port, _ = strconv.Atoi(parts[0])
	return port, parts[1], parts[3] + "/" + parts[2]
}

func virtualHostMatches(host *routev3.VirtualHost, patch Patch) bool {
	configurationMatch := patch.routeMatch()
	if configurationMatch == nil || configurationMatch.VirtualHost == nil {
		return true
	}
	match := configurationMatch.VirtualHost
	if host == nil || (match.Name != "" && match.Name != host.GetName()) {
		return false
	}
	if match.DomainName == "" {
		return true
	}
	return slices.Contains(host.GetDomains(), match.DomainName)
}

func hasHTTPRouteMatch(patch Patch) bool {
	match := patch.routeMatch()
	return match != nil && match.VirtualHost != nil && match.VirtualHost.Route != nil
}

func httpRouteMatches(route *routev3.Route, patch Patch) bool {
	configurationMatch := patch.routeMatch()
	if configurationMatch == nil || configurationMatch.VirtualHost == nil || configurationMatch.VirtualHost.Route == nil {
		return true
	}
	match := configurationMatch.VirtualHost.Route
	if route == nil || (match.Name != "" && match.Name != route.GetName()) {
		return false
	}
	if match.Action == model.RouteActionAny {
		return true
	}
	switch route.GetAction().(type) {
	case *routev3.Route_Route:
		return match.Action == model.RouteActionRoute
	case *routev3.Route_Redirect:
		return match.Action == model.RouteActionRedirect
	case *routev3.Route_DirectResponse:
		return match.Action == model.RouteActionDirectResponse
	default:
		return false
	}
}
