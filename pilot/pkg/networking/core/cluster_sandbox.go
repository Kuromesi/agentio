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

// Copyright Istio Authors
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

package core

import (
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	dfpcluster "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	dfpcommon "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	httpupstream "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pilot/pkg/util/protoconv"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/wellknown"
)

// GetMainForwardCluster returns the cluster routing into the main_forward internal listener.
// Sandbox-only: invoked from sandboxClusters.
// h2=true so the codec follows the downstream protocol; without it h2 requests get re-encoded
// as h1 to the cluster, causing UPE / stream reset. main_internal / encap already pass true.
var GetMainForwardCluster = func() *cluster.Cluster {
	return buildInternalUpstreamCluster(MainForwardName, MainForwardName, true)
}

// sandboxClusters returns the sandbox-egress-specific clusters appended to the
// waypoint cluster list.
func sandboxClusters(cb *ClusterBuilder) []*cluster.Cluster {
	return []*cluster.Cluster{
		buildSandboxPassthroughCluster(cb),
		buildDefaultTLSConnectOriginateCluster(cb),
		GetMainForwardCluster(),
	}
}

// buildSandboxPassthroughCluster builds a passthrough cluster for the sandbox catchall
// filter chains. Routes unmatched traffic to its original destination using ORIGINAL_DST.
// (Previously named buildWaypointPassthroughCluster — renamed because it is sandbox-only.)
func buildSandboxPassthroughCluster(cb *ClusterBuilder) *cluster.Cluster {
	c := &cluster.Cluster{
		Name:                 util.PassthroughCluster,
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_ORIGINAL_DST},
		ConnectTimeout:       cb.req.Push.Mesh.ConnectTimeout,
		LbPolicy:             cluster.Cluster_CLUSTER_PROVIDED,
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			v3.HttpProtocolOptionsType: passthroughHttpProtocolOptions,
		},
		CircuitBreakers: &cluster.CircuitBreakers{Thresholds: []*cluster.CircuitBreakers_Thresholds{getDefaultCircuitBreakerThresholds()}},
	}
	c.AltStatName = util.DelimitedStatsPrefix(util.PassthroughCluster)
	return c
}

// buildDefaultTLSConnectOriginateCluster builds a dynamic forward proxy cluster for
// the catchall-tls filter chain. Resolves SNI hostnames via DNS and originates TLS
// connections to upstream services.
func buildDefaultTLSConnectOriginateCluster(cb *ClusterBuilder) *cluster.Cluster {
	c := &cluster.Cluster{
		Name:            tlsOriginateCluster,
		LbPolicy:        cluster.Cluster_CLUSTER_PROVIDED,
		ConnectTimeout:  cb.req.Push.Mesh.ConnectTimeout,
		CircuitBreakers: &cluster.CircuitBreakers{Thresholds: []*cluster.CircuitBreakers_Thresholds{getDefaultCircuitBreakerThresholds()}},
		ClusterDiscoveryType: &cluster.Cluster_ClusterType{
			ClusterType: &cluster.Cluster_CustomClusterType{
				Name: "envoy.clusters.dynamic_forward_proxy",
				TypedConfig: protoconv.MessageToAny(&dfpcluster.ClusterConfig{
					ClusterImplementationSpecifier: &dfpcluster.ClusterConfig_DnsCacheConfig{
						DnsCacheConfig: &dfpcommon.DnsCacheConfig{
							Name:            agentioDFPCacheName,
							DnsLookupFamily: cluster.Cluster_AUTO,
						},
					},
				}),
			},
		},
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			v3.HttpProtocolOptionsType: protoconv.MessageToAny(&httpupstream.HttpProtocolOptions{
				CommonHttpProtocolOptions: &core.HttpProtocolOptions{
					IdleTimeout: durationpb.New(5 * time.Minute),
				},
				UpstreamHttpProtocolOptions: &core.UpstreamHttpProtocolOptions{
					AutoSni:           true,
					AutoSanValidation: true,
				},
				UpstreamProtocolOptions: &httpupstream.HttpProtocolOptions_AutoConfig{
					AutoConfig: &httpupstream.HttpProtocolOptions_AutoHttpConfig{
						HttpProtocolOptions:  &core.Http1ProtocolOptions{},
						Http2ProtocolOptions: http2ProtocolOptions(),
					},
				},
			}),
		},
		TransportSocket: &core.TransportSocket{
			Name: wellknown.TransportSocketTLS,
			ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&tlsv3.UpstreamTlsContext{
				CommonTlsContext: &tlsv3.CommonTlsContext{
					TlsParams: &tlsv3.TlsParameters{
						TlsMinimumProtocolVersion: tlsv3.TlsParameters_TLSv1_2,
					},
					ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{
						ValidationContext: &tlsv3.CertificateValidationContext{
							TrustedCa: &core.DataSource{
								Specifier: &core.DataSource_Filename{
									Filename: security.GetOSRootFilePath(),
								},
							},
						},
					},
					AlpnProtocols: util.ALPNHttp,
				},
			})},
		},
	}
	c.AltStatName = util.DelimitedStatsPrefix(tlsOriginateCluster)
	return c
}
