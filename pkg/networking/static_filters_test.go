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

package networking

import (
	"fmt"
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tlsinspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	dfpnetworkv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"istio.io/istio/pkg/test"

	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func TestConnectAuthorityCacheTracksFeatureSetting(t *testing.T) {
	for _, enabled := range []bool{false, true, false} {
		test.SetForTest(t, &features.EnableSNITrafficPolicy, enabled)
		want := buildConnectAuthorityFilter(enabled)
		if !proto.Equal(connectAuthorityFilter(), want) {
			t.Fatalf("cached filter differs for SNI policy enabled=%v", enabled)
		}
	}
}

// Exercise the mutation boundary with shared listener and network filters,
// while other builds marshal the same globals. Run with -race as well.
func TestStaticFiltersConcurrentBuildAndPatch(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	test.SetForTest(t, &features.GatewayRootCAPath, "/etc/ssl/cert.pem")
	inputs := Inputs{
		Gateway:          testGateway(nil),
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
	}
	want, err := Build(inputs)
	if err != nil {
		t.Fatal(err)
	}
	inspectorConfig, err := anypb.New(&tlsinspectorv3.TlsInspector{InitialReadBufferSize: wrapperspb.UInt32(32768)})
	if err != nil {
		t.Fatal(err)
	}
	dfpConfig, err := anypb.New(
		&dfpnetworkv3.FilterConfig{PortSpecifier: &dfpnetworkv3.FilterConfig_PortValue{PortValue: 8443}},
	)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "agentio-system",
		Name:      "static-filter-test",
		Source:    "test",
	}, 0, []string{"agentio-system/egress"}, []model.EnvoyPatch{
		{
			Operation: model.PatchMerge,
			Target: model.ListenerFilterPatch{
				Match: &model.ListenerMatch{Name: MainInternal, ListenerFilter: "envoy.filters.listener.tls_inspector"},
				Value: &listenerv3.ListenerFilter{
					Name:       "envoy.filters.listener.tls_inspector",
					ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: inspectorConfig},
				},
			},
		},
		{
			Operation: model.PatchMerge,
			Target: model.NetworkFilterPatch{
				Match: &model.ListenerMatch{
					Name: MainForward,
					FilterChain: &model.FilterChainMatch{
						Name:   forwardTCPChain,
						Filter: &model.FilterMatch{Name: sniDFPFilter.GetName()},
					},
				},
				Value: &listenerv3.Filter{
					Name:       sniDFPFilter.GetName(),
					ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: dfpConfig},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			patchedInputs := inputs
			patchedInputs.GatewayPatches = []model.GatewayPatch{patch}
			resources, err := Build(patchedInputs)
			if err != nil {
				t.Fatal(err)
			}
			listeners := messagesOf(
				t,
				resources,
				model.ListenerType,
				func() *listenerv3.Listener { return &listenerv3.Listener{} },
			)
			inspector := &tlsinspectorv3.TlsInspector{}
			if err := listeners[MainInternal].ListenerFilters[2].GetTypedConfig().UnmarshalTo(inspector); err != nil {
				t.Fatal(err)
			}
			if inspector.GetInitialReadBufferSize().GetValue() != 32768 {
				t.Fatal("listener filter patch was not applied")
			}
			var patchedPort uint32
			for _, chain := range listeners[MainForward].FilterChains {
				if chain.Name == forwardTCPChain {
					dfp := &dfpnetworkv3.FilterConfig{}
					if err := chain.Filters[0].GetTypedConfig().UnmarshalTo(dfp); err != nil {
						t.Fatal(err)
					}
					patchedPort = dfp.GetPortValue()
				}
			}
			if patchedPort != 8443 {
				t.Fatal("network filter patch was not applied")
			}
			got, err := Build(inputs)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(want) {
				t.Fatal("patch changed another build's resource count")
			}
			for i := range want {
				if !got[i].Equals(want[i]) {
					t.Errorf("patch contaminated another build's resource %s", want[i].XDSName)
				}
			}
		})
	}
}
