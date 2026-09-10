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
	"testing"
	"time"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	httpupstreamv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"istio.io/istio/pkg/test"

	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func TestGatewayClustersUseConfiguredConnectTimeoutAndRootCA(t *testing.T) {
	const rootCAPath = "/etc/ssl/custom.pem"
	test.SetForTest(t, &features.GatewayConnectTimeout, 7*time.Second)
	test.SetForTest(t, &features.GatewayRootCAPath, rootCAPath)
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
		GlobalExtProc: &configv1.ExtProcProvider{
			Service: "epe.agentio-system.svc",
			Port:    9002,
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	for _, name := range []string{PassthroughCluster, HTTPDynamicForwardProxy, TLSConnectOriginate} {
		if got := clusters[name].GetConnectTimeout().AsDuration(); got != 7*time.Second {
			t.Errorf("cluster %s connect timeout = %s, want 7s", name, got)
		}
	}
	for _, name := range []string{MainInternal, MainForward, ExtProcCluster} {
		if got := clusters[name].GetConnectTimeout().AsDuration(); got != 10*time.Second {
			t.Errorf("cluster %s connect timeout = %s, want owned 10s", name, got)
		}
	}

	tlsContext := &tlsv3.UpstreamTlsContext{}
	if err := clusters[TLSConnectOriginate].GetTransportSocket().GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		t.Fatalf("unmarshal TLS origination context: %v", err)
	}
	if got := tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename(); got != rootCAPath {
		t.Fatalf("TLS origination root CA = %q, want %q", got, rootCAPath)
	}
}

func TestGatewayTLSOriginationDisablesSharedSessionCache(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local", Gateway: testGateway(nil),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	for _, name := range []string{TLSConnectOriginate, TLSProxyOriginate} {
		t.Run(name, func(t *testing.T) {
			cluster := clusters[name]
			context := &tlsv3.UpstreamTlsContext{}
			if err := cluster.GetTransportSocket().GetTypedConfig().UnmarshalTo(context); err != nil {
				t.Fatalf("decode TLS context: %v", err)
			}
			// An absent wrapper enables Envoy's default session cache.
			if keys := context.GetMaxSessionKeys(); keys == nil || keys.GetValue() != 0 {
				t.Fatalf("max session keys = %v, want explicit zero to prevent cross-SNI session reuse", keys)
			}
			if got := context.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename(); got != features.ResolveGatewayRootCAPath() {
				t.Fatalf("trusted CA = %q, want configured roots", got)
			}
			if name == TLSConnectOriginate {
				options := &httpupstreamv3.HttpProtocolOptions{}
				if err := cluster.GetTypedExtensionProtocolOptions()[httpProtocolOptionsType].UnmarshalTo(options); err != nil {
					t.Fatalf("decode HTTP options: %v", err)
				}
				if !options.GetUpstreamHttpProtocolOptions().GetAutoSni() || !options.GetUpstreamHttpProtocolOptions().GetAutoSanValidation() {
					t.Fatal("TLS origination must retain automatic SNI and SAN validation")
				}
			}
		})
	}
}

func TestGatewayClustersUseAgentioStatsAndCircuitBreakers(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
		GlobalExtProc: &configv1.ExtProcProvider{
			Service: "epe.agentio-system.svc",
			Port:    9002,
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	for _, name := range []string{
		MainInternal, MainForward, PassthroughCluster,
		HTTPDynamicForwardProxy, TLSConnectOriginate, TLSProxyOriginate, ExtProcCluster,
	} {
		cluster := clusters[name]
		if got, want := cluster.GetAltStatName(), name+";"; got != want {
			t.Errorf("cluster %s alt stat name = %q, want %q", name, got, want)
		}
		thresholds := cluster.GetCircuitBreakers().GetThresholds()
		if len(thresholds) != 1 {
			t.Errorf("cluster %s circuit breaker thresholds = %d, want 1", name, len(thresholds))
			continue
		}
		if thresholds[0].GetTrackRemaining() {
			t.Errorf("cluster %s enables track_remaining; Agentio does not", name)
		}
	}
}

func TestGatewayClustersUseAgentioDownstreamIdleTimeout(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	for _, name := range []string{MainInternal, MainForward, PassthroughCluster, TLSProxyOriginate, HTTPDynamicForwardProxy} {
		protocol := &httpupstreamv3.HttpProtocolOptions{}
		if err := clusters[name].GetTypedExtensionProtocolOptions()[httpProtocolOptionsType].UnmarshalTo(protocol); err != nil {
			t.Fatalf("unmarshal cluster %s HTTP protocol options: %v", name, err)
		}
		if got := protocol.GetCommonHttpProtocolOptions().GetIdleTimeout().AsDuration(); got != 5*time.Minute {
			t.Errorf("cluster %s downstream HTTP idle timeout = %s, want 5m", name, got)
		}
	}
}
