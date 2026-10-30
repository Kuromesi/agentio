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
	"slices"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestAdditionalExtProcChain(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		for _, disabled := range []bool{false, true} {
			gateway := &configv1.EgressGateway{
				TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"example.com"}},
			}
			if disabled {
				gateway.ExtProc = &configv1.ExtProcProvider{}
			}
			first := &configv1.ExtProcProvider{
				Name:             "first",
				Service:          "first.demo.svc",
				Port:             9010,
				MessageTimeout:   "350ms",
				FailureModeAllow: true,
				Response:         &configv1.ProcessingModeOptions{HeaderMode: configv1.HeaderSendMode_SEND},
			}
			second := &configv1.ExtProcProvider{Name: "second", Service: "second.demo.svc"}
			inputs := Inputs{
				LegacyGateway:      legacy,
				Gateway:            testGateway(gateway),
				GlobalExtProc:      &configv1.ExtProcProvider{Service: "epe.demo.svc"},
				AdditionalExtProcs: []*configv1.ExtProcProvider{first, second},
				DiscoveryAddress:   "agentiod:15012",
				TrustDomain:        "cluster.local",
			}
			resources, err := Build(inputs)
			if err != nil {
				t.Fatal(err)
			}
			clusters := messagesOf(
				t,
				resources,
				model.ClusterType,
				func() *clusterv3.Cluster { return &clusterv3.Cluster{} },
			)
			listeners := messagesOf(
				t,
				resources,
				model.ListenerType,
				func() *listenerv3.Listener { return &listenerv3.Listener{} },
			)
			found := 0
			for _, listener := range listeners {
				for _, chain := range listener.GetFilterChains() {
					for _, nf := range chain.GetFilters() {
						if nf.GetName() != "envoy.filters.network.http_connection_manager" {
							continue
						}
						hcm := &hcmv3.HttpConnectionManager{}
						if err := nf.GetTypedConfig().UnmarshalTo(hcm); err != nil {
							t.Fatal(err)
						}
						names := httpFilterNames(hcm)
						index := slices.Index(names, additionalExtProcName(first, legacy))
						if disabled || hcm.GetStatPrefix() == "connect_terminate" {
							if index != -1 {
								t.Fatalf("unexpected additional processor in %s: %v", listener.Name, names)
							}
							continue
						}
						// Only forward HTTP chains contain additional processors; CONNECT has its own HCM.
						if index < 0 {
							continue
						}
						found++
						if index == 0 || names[index-1] != "envoy.filters.http.ext_proc" || index+1 >= len(names) ||
							names[index+1] != additionalExtProcName(second, legacy) {
							t.Fatalf("wrong filter order: %v", names)
						}
						for j, provider := range inputs.AdditionalExtProcs {
							cfg := &extprocv3.ExternalProcessor{}
							if err := hcm.HttpFilters[index+j].GetTypedConfig().UnmarshalTo(cfg); err != nil {
								t.Fatal(err)
							}
							name := additionalExtProcName(provider, legacy)
							if cfg.GetGrpcService().GetEnvoyGrpc().GetClusterName() != name ||
								cfg.GetStatPrefix() != name ||
								!cfg.GetAllowModeOverride() {
								t.Fatalf("processor wiring: %v", cfg)
							}
							if len(cfg.GetMetadataOptions().GetReceivingNamespaces().GetUntyped()) != 0 {
								t.Fatal("additional processor can write EPE route metadata")
							}
							if cfg.GetProcessingMode().GetRequestBodyMode() != extprocv3.ProcessingMode_NONE ||
								cfg.GetProcessingMode().GetResponseBodyMode() != extprocv3.ProcessingMode_NONE {
								t.Fatal("body must be opt-in")
							}
							if j == 0 &&
								(cfg.GetMessageTimeout().AsDuration() != 350*time.Millisecond || !cfg.GetFailureModeAllow() || cfg.GetProcessingMode().GetResponseHeaderMode() != extprocv3.ProcessingMode_SEND) {
								t.Fatalf("provider options lost: %v", cfg)
							}
							if j == 1 &&
								cfg.GetProcessingMode().GetResponseHeaderMode() != extprocv3.ProcessingMode_SKIP {
								t.Fatal("response must default to SKIP")
							}
						}
					}
				}
			}
			if !disabled && found < 2 {
				t.Fatalf("missing HTTP/TLS-terminated chains: %d", found)
			}
			for _, provider := range inputs.AdditionalExtProcs {
				name := additionalExtProcName(provider, legacy)
				cluster := clusters[name]
				if disabled {
					if cluster != nil {
						t.Fatal("disabled chain retains additional cluster")
					}
					continue
				}
				if cluster == nil || cluster.GetLoadAssignment().GetClusterName() != name {
					t.Fatalf("missing named cluster %s", name)
				}
				address := cluster.GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()[0].GetEndpoint().
					GetAddress().
					GetSocketAddress()
				port := provider.Port
				if port == 0 {
					port = 9002
				}
				if address.GetAddress() != provider.Service || address.GetPortValue() != port {
					t.Fatalf("wrong endpoint: %v", address)
				}
			}
			if !disabled {
				inputs.AdditionalExtProcs = []*configv1.ExtProcProvider{second, first}
				reordered, err := Build(inputs)
				if err != nil {
					t.Fatal(err)
				}
				after := messagesOf(
					t,
					reordered,
					model.ClusterType,
					func() *clusterv3.Cluster { return &clusterv3.Cluster{} },
				)
				for name, before := range clusters {
					if !proto.Equal(before, after[name]) {
						t.Fatalf("reorder changed cluster %s", name)
					}
				}
			}
		}
	}
}
