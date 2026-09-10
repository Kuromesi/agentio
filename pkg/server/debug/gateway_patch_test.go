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
	"strings"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"github.com/openkruise/agentio/pkg/model"
)

func TestConfigDebugPatchSupportsEverySealedTarget(t *testing.T) {
	for _, test := range []struct {
		name   string
		target model.PatchTarget
		want   string
	}{
		{name: "cluster", target: model.ClusterPatch{Value: &clusterv3.Cluster{}}, want: "cluster"},
		{name: "listener", target: model.ListenerPatch{Value: &listenerv3.Listener{}}, want: "listener"},
		{name: "listener filter", target: model.ListenerFilterPatch{Value: &listenerv3.ListenerFilter{}}, want: "listenerFilter"},
		{name: "filter chain", target: model.FilterChainPatch{Value: &listenerv3.FilterChain{}}, want: "filterChain"},
		{name: "network filter", target: model.NetworkFilterPatch{Value: &listenerv3.Filter{}}, want: "networkFilter"},
		{name: "HTTP filter", target: model.HTTPFilterPatch{Value: &hcmv3.HttpFilter{}}, want: "httpFilter"},
		{name: "route configuration", target: model.RouteConfigurationPatch{Value: &routev3.RouteConfiguration{}}, want: "routeConfiguration"},
		{name: "virtual host", target: model.VirtualHostPatch{Value: &routev3.VirtualHost{}}, want: "virtualHost"},
		{name: "HTTP route", target: model.HTTPRoutePatch{Value: &routev3.Route{}}, want: "httpRoute"},
		{name: "extension configuration", target: model.ExtensionConfigurationPatch{Value: &corev3.TypedExtensionConfig{}}, want: "extensionConfiguration"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := configDebugPatch(model.EnvoyPatch{Operation: model.PatchAdd, Target: test.target})
			if err != nil {
				t.Fatal(err)
			}
			if got.Target != test.want || got.Operation != "ADD" || string(got.Value) != "{}" {
				t.Fatalf("adapted patch = %#v, want target=%q operation=ADD value={}", got, test.want)
			}
		})
	}

	unknown, err := configDebugPatch(model.EnvoyPatch{
		Operation: model.PatchOperation(255),
		Target: model.HTTPRoutePatch{
			Match: &model.RouteConfigurationMatch{VirtualHost: &model.VirtualHostMatch{
				Route: &model.RouteMatch{Action: model.RouteAction(255)},
			}},
			Value: &routev3.Route{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	match, err := json.Marshal(unknown.Match)
	if err != nil {
		t.Fatal(err)
	}
	if unknown.Operation != "UNKNOWN(255)" || !strings.Contains(string(match), `"action":"UNKNOWN(255)"`) {
		t.Fatalf("unknown enum adaptation = %#v match=%s", unknown, match)
	}
}
