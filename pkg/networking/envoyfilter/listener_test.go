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

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/model"
)

func TestApplyListenersPatchesNestedGatewayFilters(t *testing.T) {
	httpConnectionManager := &hcmv3.HttpConnectionManager{HttpFilters: []*hcmv3.HttpFilter{{Name: "envoy.filters.http.router"}}}
	httpAny, err := anypb.New(httpConnectionManager)
	if err != nil {
		t.Fatal(err)
	}
	original := []*listenerv3.Listener{{
		Name: "main",
		Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
			Address: "0.0.0.0", PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: 15001},
		}}},
		ListenerFilters: []*listenerv3.ListenerFilter{{Name: "original-listener-filter"}},
		FilterChains: []*listenerv3.FilterChain{{
			Name: "main-chain",
			Filters: []*listenerv3.Filter{
				{Name: "remove-me"},
				{Name: "envoy.filters.network.http_connection_manager", ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: httpAny}},
			},
		}},
	}}
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "demo", Name: "listeners", Source: "source",
	}, 0, []string{"demo/gateway"}, []model.EnvoyPatch{
		{
			Operation: model.PatchInsertBefore,
			Target: model.ListenerFilterPatch{
				Match: listenerMatch("main", "", "", "original-listener-filter"),
				Value: &listenerv3.ListenerFilter{Name: "inserted-listener-filter"},
			},
		},
		{
			Operation: model.PatchRemove,
			Target: model.NetworkFilterPatch{
				Match: listenerMatch("main", "main-chain", "remove-me", ""),
			},
		},
		{
			Operation: model.PatchInsertBefore,
			Target: model.HTTPFilterPatch{
				Match: listenerHTTPMatch("main", "main-chain", "envoy.filters.network.http_connection_manager", "envoy.filters.http.router"),
				Value: &hcmv3.HttpFilter{Name: "custom-http-filter"},
			},
		},
		{
			Operation: model.PatchAdd,
			Target:    model.ListenerPatch{Value: &listenerv3.Listener{Name: "inserted-listener"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	patches := NewPatchSet([]model.GatewayPatch{policy})

	got, err := ApplyListeners(patches, original)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].GetName() != "inserted-listener" {
		t.Fatalf("listeners = %+v", got)
	}
	main := got[0]
	if len(main.ListenerFilters) != 2 || main.ListenerFilters[0].GetName() != "inserted-listener-filter" {
		t.Fatalf("listener filters = %+v", main.ListenerFilters)
	}
	if len(main.FilterChains[0].Filters) != 1 {
		t.Fatalf("network filters = %+v", main.FilterChains[0].Filters)
	}
	patchedHCM := &hcmv3.HttpConnectionManager{}
	if err := main.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(patchedHCM); err != nil {
		t.Fatal(err)
	}
	if len(patchedHCM.HttpFilters) != 2 || patchedHCM.HttpFilters[0].GetName() != "custom-http-filter" ||
		patchedHCM.HttpFilters[1].GetName() != "envoy.filters.http.router" {
		t.Fatalf("HTTP filters = %+v", patchedHCM.HttpFilters)
	}
	if len(original[0].ListenerFilters) != 1 || len(original[0].FilterChains[0].Filters) != 2 {
		t.Fatalf("input listener was mutated: %+v", original[0])
	}
}

func listenerMatch(listenerName, chainName, filterName, listenerFilterName string) *model.ListenerMatch {
	match := &model.ListenerMatch{Name: listenerName, ListenerFilter: listenerFilterName}
	if chainName != "" || filterName != "" {
		match.FilterChain = &model.FilterChainMatch{Name: chainName}
		if filterName != "" {
			match.FilterChain.Filter = &model.FilterMatch{Name: filterName}
		}
	}
	return match
}

func listenerHTTPMatch(listenerName, chainName, filterName, subFilterName string) *model.ListenerMatch {
	match := listenerMatch(listenerName, chainName, filterName, "")
	match.FilterChain.Filter.SubFilter = &model.SubFilterMatch{Name: subFilterName}
	return match
}
