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
	"slices"
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	setstatecommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	"istio.io/istio/pkg/test"

	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func TestConnectIdentityFallbackTransfer(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, sni := range []bool{false, true} {
			t.Run(fmt.Sprintf("legacy=%v/sni=%v", legacy, sni), func(t *testing.T) {
				test.SetForTest(t, &features.EnableSNITrafficPolicy, sni)
				resources, err := Build(
					Inputs{
						LegacyGateway:    legacy,
						Gateway:          testGateway(nil),
						TrustDomain:      "cluster.local",
						DiscoveryAddress: "agentiod.agentio-system.svc:15012",
					},
				)
				if err != nil {
					t.Fatal(err)
				}
				listeners := messagesOf(
					t,
					resources,
					model.ListenerType,
					func() *listenerv3.Listener { return &listenerv3.Listener{} },
				)
				listener := listeners[ConnectTerminate]
				hcm := findHCM(t, listener)
				names := httpFilterNames(hcm)
				index := slices.Index(names, "connect_workload")
				peer := connectAuthorityStates(t, listener)["agentio.downstream.ip"]
				if legacy {
					if index >= 0 || peer != nil {
						t.Fatal("legacy gateway gained Porter identity fallback")
					}
					return
				}
				if peer.GetFormatString().
					GetTextFormatSource().
					GetInlineString() !=
					"%DOWNSTREAM_DIRECT_REMOTE_ADDRESS_WITHOUT_PORT%" ||
					peer.GetFactoryKey() != "envoy.string" ||
					peer.GetSharedWithUpstream() != setstatecommonv3.FilterStateValue_NONE {
					t.Fatalf("unexpected source IP capture: %v", peer)
				}
				if index < 1 || names[index-1] != "envoy.filters.http.ext_proc" ||
					index >= slices.Index(names, "envoy.filters.http.router") {
					t.Fatalf("identity must be restored after Porter and before routing: %v", names)
				}
				processor := &extprocv3.ExternalProcessor{}
				if err := hcm.HttpFilters[index-1].GetTypedConfig().UnmarshalTo(processor); err != nil {
					t.Fatal(err)
				}
				for _, attr := range []string{"filter_state['agentio.downstream.ip']", "filter_state['agentio.peer.principal']"} {
					if !slices.Contains(processor.RequestAttributes, attr) {
						t.Fatalf("Porter missing %s", attr)
					}
				}
				restored := &setstatehttpv3.Config{}
				if err := hcm.HttpFilters[index].GetTypedConfig().UnmarshalTo(restored); err != nil {
					t.Fatal(err)
				}
				if len(restored.OnRequestHeaders) != 2 {
					t.Fatalf("identity state=%v", restored)
				}
				for i, field := range []string{"name", "namespace"} {
					state := restored.OnRequestHeaders[i]
					if state.GetObjectKey() != "agentio.workload."+field ||
						state.GetFactoryKey() != "envoy.hashable_string" ||
						state.GetSharedWithUpstream() != setstatecommonv3.FilterStateValue_TRANSITIVE ||
						state.GetFormatString().
							GetTextFormatSource().
							GetInlineString() !=
							"%DYNAMIC_METADATA(agentio:workload:"+field+")%" {
						t.Fatalf("identity must survive internal hops and isolate connection pools: %v", state)
					}
				}
			})
		}
	}
}
