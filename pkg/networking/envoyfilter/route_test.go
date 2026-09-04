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
	"testing"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/openkruise/agentio/pkg/model"
)

func TestApplyRoutesPreservesAgentioGatewayOrderingAndMatching(t *testing.T) {
	original := []*routev3.RouteConfiguration{{
		Name: "connect_terminate",
		VirtualHosts: []*routev3.VirtualHost{{
			Name: "primary", Domains: []string{"example.com"},
			Routes: []*routev3.Route{{Name: "existing"}},
		}},
	}}
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "demo", Name: "routes", Source: "source",
	}, 0, []string{"demo/gateway"}, []model.EnvoyPatch{
		{
			Operation: model.PatchMerge,
			Target: model.RouteConfigurationPatch{
				Match: routeMatch("connect_terminate", "", ""),
				Value: &routev3.RouteConfiguration{IgnorePortInHostMatching: true},
			},
		},
		{
			Operation: model.PatchMerge,
			Target: model.VirtualHostPatch{
				Match: routeMatch("connect_terminate", "primary", ""),
				Value: &routev3.VirtualHost{Domains: []string{"extra.example.com"}},
			},
		},
		{
			Operation: model.PatchInsertBefore,
			Target: model.HTTPRoutePatch{
				Match: routeMatch("connect_terminate", "primary", "existing"),
				Value: &routev3.Route{Name: "inserted"},
			},
		},
		{
			Operation: model.PatchAdd,
			Target: model.VirtualHostPatch{
				Match: routeMatch("connect_terminate", "", ""),
				Value: &routev3.VirtualHost{Name: "added", Domains: []string{"added.example.com"}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	patches := NewPatchSet([]model.GatewayPatch{policy})

	got, err := ApplyRoutes(patches, original)
	if err != nil {
		t.Fatal(err)
	}
	configuration := got[0]
	if !configuration.GetIgnorePortInHostMatching() || len(configuration.VirtualHosts) != 2 {
		t.Fatalf("route configuration = %+v", configuration)
	}
	primary := configuration.VirtualHosts[0]
	if len(primary.Domains) != 2 || primary.Domains[1] != "extra.example.com" {
		t.Fatalf("virtual host domains = %v", primary.Domains)
	}
	if len(primary.Routes) != 2 || primary.Routes[0].GetName() != "inserted" || primary.Routes[1].GetName() != "existing" {
		t.Fatalf("routes = %+v", primary.Routes)
	}
	if original[0].GetIgnorePortInHostMatching() || len(original[0].VirtualHosts[0].Domains) != 1 || len(original[0].VirtualHosts[0].Routes) != 1 {
		t.Fatalf("input route configuration mutated: %+v", original[0])
	}
}

func TestApplyRoutesSupportsDeployedSandboxConnectPatch(t *testing.T) {
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "sandbox-traffic-system", Name: "enable-sandbox-connect", Source: "sandbox-traffic-system/config-source",
	}, 0, []string{"sandbox-traffic-system/egress-gateway"}, []model.EnvoyPatch{{
		Operation: model.PatchInsertBefore,
		Target: model.HTTPRoutePatch{
			Match: routeMatch("http_dynamic_forward_proxy", "", "default"),
			Value: &routev3.Route{
				Name: "sandbox-connect",
				Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_ConnectMatcher_{
					ConnectMatcher: &routev3.RouteMatch_ConnectMatcher{},
				}},
				Action: &routev3.Route_Route{Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: "PassthroughCluster"},
					Timeout:          durationpb.New(0),
					UpgradeConfigs: []*routev3.RouteAction_UpgradeConfig{{
						UpgradeType: "CONNECT", ConnectConfig: &routev3.RouteAction_UpgradeConfig_ConnectConfig{},
					}},
				}},
			},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	input := []*routev3.RouteConfiguration{{
		Name: "http_dynamic_forward_proxy",
		VirtualHosts: []*routev3.VirtualHost{{
			Name: "default", Domains: []string{"*"}, Routes: []*routev3.Route{{Name: "default"}},
		}},
	}}

	got, err := ApplyRoutes(NewPatchSet([]model.GatewayPatch{policy}), input)
	if err != nil {
		t.Fatal(err)
	}
	routes := got[0].VirtualHosts[0].Routes
	if len(routes) != 2 || routes[0].GetName() != "sandbox-connect" || routes[1].GetName() != "default" {
		t.Fatalf("routes = %+v", routes)
	}
	inserted := routes[0]
	if inserted.GetMatch().GetConnectMatcher() == nil || inserted.GetRoute().GetCluster() != "PassthroughCluster" ||
		inserted.GetRoute().GetTimeout().AsDuration() != 0 || len(inserted.GetRoute().GetUpgradeConfigs()) != 1 ||
		inserted.GetRoute().GetUpgradeConfigs()[0].GetConnectConfig() == nil {
		t.Fatalf("inserted CONNECT route = %+v", inserted)
	}
}

func routeMatch(configurationName, virtualHostName, routeName string) *model.RouteConfigurationMatch {
	match := &model.RouteConfigurationMatch{Name: configurationName}
	if virtualHostName != "" || routeName != "" {
		match.VirtualHost = &model.VirtualHostMatch{Name: virtualHostName}
		if routeName != "" {
			match.VirtualHost.Route = &model.RouteMatch{Name: routeName}
		}
	}
	return match
}

// Release-0.1 records a removed virtual host by name before applying ADDs and
// only filters by name afterwards, so a REMOVE also drops a later ADD with the
// same name and every duplicate. These tests pin that ordering.
func TestApplyRoutesVirtualHostRemoveDropsLaterAddOfSameName(t *testing.T) {
	original := []*routev3.RouteConfiguration{{
		Name: "http_dynamic_forward_proxy",
		VirtualHosts: []*routev3.VirtualHost{
			{Name: "stale", Domains: []string{"stale.example.com"}},
			{Name: "keep", Domains: []string{"keep.example.com"}},
		},
	}}
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "demo", Name: "remove-vh", Source: "source",
	}, 0, []string{"demo/gateway"}, []model.EnvoyPatch{
		{
			Operation: model.PatchRemove,
			Target: model.VirtualHostPatch{
				Match: routeMatch("http_dynamic_forward_proxy", "stale", ""),
			},
		},
		{
			Operation: model.PatchAdd,
			Target: model.VirtualHostPatch{
				Match: routeMatch("http_dynamic_forward_proxy", "", ""),
				Value: &routev3.VirtualHost{Name: "stale", Domains: []string{"readded.example.com"}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := ApplyRoutes(NewPatchSet([]model.GatewayPatch{policy}), original)
	if err != nil {
		t.Fatal(err)
	}
	hosts := got[0].VirtualHosts
	if len(hosts) != 1 || hosts[0].GetName() != "keep" {
		t.Fatalf("virtual hosts = %+v, want only the untouched host", hosts)
	}
}

func TestApplyRoutesVirtualHostRemoveDropsEveryDuplicateName(t *testing.T) {
	original := []*routev3.RouteConfiguration{{
		Name: "http_dynamic_forward_proxy",
		VirtualHosts: []*routev3.VirtualHost{
			{Name: "dup", Domains: []string{"a.example.com"}},
			{Name: "dup", Domains: []string{"b.example.com"}},
			{Name: "keep", Domains: []string{"keep.example.com"}},
		},
	}}
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "demo", Name: "remove-dup", Source: "source",
	}, 0, []string{"demo/gateway"}, []model.EnvoyPatch{{
		Operation: model.PatchRemove,
		Target: model.VirtualHostPatch{
			Match: routeMatch("http_dynamic_forward_proxy", "dup", ""),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := ApplyRoutes(NewPatchSet([]model.GatewayPatch{policy}), original)
	if err != nil {
		t.Fatal(err)
	}
	hosts := got[0].VirtualHosts
	if len(hosts) != 1 || hosts[0].GetName() != "keep" {
		t.Fatalf("virtual hosts = %+v, want all duplicates removed", hosts)
	}
}
