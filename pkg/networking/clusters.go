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
	"math"
	"time"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	dfpclusterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	dfpcommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	internalupstreamv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/internal_upstream/v3"
	rawbufferv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/raw_buffer/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	httpupstreamv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/features"
)

// TypedExtensionProtocolOptions is keyed by the fully qualified message name,
// not an Any type URL; Envoy rejects the wrong key form.
const httpProtocolOptionsType = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"

func buildClusters(config effectiveConfig) ([]*clusterv3.Cluster, error) {
	result := []*clusterv3.Cluster{
		buildInternalCluster(MainInternal),
		buildInternalCluster(MainForward),
		buildPassthroughCluster(),
		buildBlackHoleCluster(),
		buildDFPCluster(HTTPDynamicForwardProxy, true, false),
		buildDFPCluster(TLSConnectOriginate, false, true),
		buildTLSProxyOriginateCluster(),
	}
	if config.extProc != nil {
		result = append(result, buildExtProcCluster(config.extProc))
	}
	if config.telemetry != nil {
		names := sets.NewWithLength[string](len(result) + len(config.telemetry.Clusters))
		for _, cluster := range result {
			names.Insert(cluster.Name)
		}
		for _, cluster := range config.telemetry.Clusters {
			if names.Contains(cluster.Name) {
				return nil, fmt.Errorf("Telemetry cluster %q conflicts with an existing Gateway cluster", cluster.Name)
			}
			names.Insert(cluster.Name)
			result = append(result, proto.Clone(cluster).(*clusterv3.Cluster))
		}
	}
	return result, nil
}

func buildInternalCluster(name string) *clusterv3.Cluster {
	raw, _ := anypb.New(&rawbufferv3.RawBuffer{})
	internal, _ := anypb.New(&internalupstreamv3.InternalUpstreamTransport{
		TransportSocket: &corev3.TransportSocket{Name: "raw_buffer", ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: raw}},
	})
	return &clusterv3.Cluster{
		Name:                 name,
		AltStatName:          delimitedStatsPrefix(name),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
		ConnectTimeout:       durationpb.New(10 * time.Second),
		LbPolicy:             clusterv3.Cluster_ROUND_ROBIN,
		CircuitBreakers:      defaultCircuitBreakers(),
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*endpointv3.LocalityLbEndpoints{{
				LbEndpoints: []*endpointv3.LbEndpoint{{HostIdentifier: &endpointv3.LbEndpoint_Endpoint{Endpoint: &endpointv3.Endpoint{
					Address: internalAddress(name),
				}}}},
			}},
		},
		TransportSocket: &corev3.TransportSocket{
			Name:       "internal_upstream",
			ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: internal},
		},
		TypedExtensionProtocolOptions: map[string]*anypb.Any{httpProtocolOptionsType: downstreamHTTPOptions()},
	}
}

func buildPassthroughCluster() *clusterv3.Cluster {
	return &clusterv3.Cluster{
		Name:                 PassthroughCluster,
		AltStatName:          delimitedStatsPrefix(PassthroughCluster),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_ORIGINAL_DST},
		ConnectTimeout:       durationpb.New(features.GatewayConnectTimeout),
		LbPolicy:             clusterv3.Cluster_CLUSTER_PROVIDED,
		CircuitBreakers:      defaultCircuitBreakers(),
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			httpProtocolOptionsType: downstreamHTTPOptions(),
		},
	}
}

// buildTLSProxyOriginateCluster reconnects to the original HTTPS proxy while
// request-scoped filter state supplies the outer SNI and SAN. The inner CONNECT
// authority must never become the proxy certificate identity.
func buildTLSProxyOriginateCluster() *clusterv3.Cluster {
	cluster := buildPassthroughCluster()
	cluster.Name = TLSProxyOriginate
	cluster.AltStatName = delimitedStatsPrefix(TLSProxyOriginate)
	options, _ := anypb.New(&httpupstreamv3.HttpProtocolOptions{
		CommonHttpProtocolOptions: &corev3.HttpProtocolOptions{IdleTimeout: durationpb.New(5 * time.Minute)},
		UpstreamProtocolOptions: &httpupstreamv3.HttpProtocolOptions_AutoConfig{AutoConfig: &httpupstreamv3.HttpProtocolOptions_AutoHttpConfig{
			HttpProtocolOptions:  &corev3.Http1ProtocolOptions{},
			Http2ProtocolOptions: &corev3.Http2ProtocolOptions{},
		}},
	})
	cluster.TypedExtensionProtocolOptions = map[string]*anypb.Any{httpProtocolOptionsType: options}
	tlsConfig, _ := anypb.New(&tlsv3.UpstreamTlsContext{CommonTlsContext: &tlsv3.CommonTlsContext{
		TlsParams: &tlsv3.TlsParameters{TlsMinimumProtocolVersion: tlsv3.TlsParameters_TLSv1_2},
		ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{ValidationContext: &tlsv3.CertificateValidationContext{
			TrustedCa: &corev3.DataSource{Specifier: &corev3.DataSource_Filename{Filename: features.ResolveGatewayRootCAPath()}},
		}},
		AlpnProtocols: []string{"h2", "http/1.1"},
	}})
	cluster.TransportSocket = &corev3.TransportSocket{
		Name:       "envoy.transport_sockets.tls",
		ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: tlsConfig},
	}
	return cluster
}

func buildBlackHoleCluster() *clusterv3.Cluster {
	return &clusterv3.Cluster{
		Name:                 BlackHoleCluster,
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
		ConnectTimeout:       durationpb.New(time.Second),
		LbPolicy:             clusterv3.Cluster_ROUND_ROBIN,
		LoadAssignment:       &endpointv3.ClusterLoadAssignment{ClusterName: BlackHoleCluster},
	}
}

func buildDFPCluster(name string, allowInsecure, originateTLS bool) *clusterv3.Cluster {
	typed, _ := anypb.New(&dfpclusterv3.ClusterConfig{
		ClusterImplementationSpecifier: &dfpclusterv3.ClusterConfig_DnsCacheConfig{DnsCacheConfig: dnsCacheConfig()},
		AllowInsecureClusterOptions:    allowInsecure,
	})
	cluster := &clusterv3.Cluster{
		Name:            name,
		AltStatName:     delimitedStatsPrefix(name),
		ConnectTimeout:  durationpb.New(features.GatewayConnectTimeout),
		LbPolicy:        clusterv3.Cluster_CLUSTER_PROVIDED,
		CircuitBreakers: defaultCircuitBreakers(),
		ClusterDiscoveryType: &clusterv3.Cluster_ClusterType{ClusterType: &clusterv3.Cluster_CustomClusterType{
			Name:        "envoy.clusters.dynamic_forward_proxy",
			TypedConfig: typed,
		}},
	}
	if !originateTLS {
		cluster.TypedExtensionProtocolOptions = map[string]*anypb.Any{httpProtocolOptionsType: downstreamHTTPOptions()}
		return cluster
	}
	opts, _ := anypb.New(&httpupstreamv3.HttpProtocolOptions{
		CommonHttpProtocolOptions: &corev3.HttpProtocolOptions{IdleTimeout: durationpb.New(5 * time.Minute)},
		UpstreamHttpProtocolOptions: &corev3.UpstreamHttpProtocolOptions{
			AutoSni:           true,
			AutoSanValidation: true,
		},
		UpstreamProtocolOptions: &httpupstreamv3.HttpProtocolOptions_AutoConfig{AutoConfig: &httpupstreamv3.HttpProtocolOptions_AutoHttpConfig{
			HttpProtocolOptions:  &corev3.Http1ProtocolOptions{},
			Http2ProtocolOptions: &corev3.Http2ProtocolOptions{},
		}},
	})
	cluster.TypedExtensionProtocolOptions = map[string]*anypb.Any{httpProtocolOptionsType: opts}
	tlsConfig, _ := anypb.New(&tlsv3.UpstreamTlsContext{CommonTlsContext: &tlsv3.CommonTlsContext{
		TlsParams: &tlsv3.TlsParameters{TlsMinimumProtocolVersion: tlsv3.TlsParameters_TLSv1_2},
		ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{ValidationContext: &tlsv3.CertificateValidationContext{
			TrustedCa: &corev3.DataSource{Specifier: &corev3.DataSource_Filename{Filename: features.ResolveGatewayRootCAPath()}},
		}},
		AlpnProtocols: []string{"h2", "http/1.1"},
	}})
	cluster.TransportSocket = &corev3.TransportSocket{
		Name:       "envoy.transport_sockets.tls",
		ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: tlsConfig},
	}
	return cluster
}

func buildExtProcCluster(provider *configv1.ExtProcProvider) *clusterv3.Cluster {
	port := provider.GetPort()
	if port == 0 {
		port = 9002
	}
	httpSettings := provider.GetClusterSettings().GetHttp()
	http2 := &corev3.Http2ProtocolOptions{AllowConnect: true}
	if httpSettings.GetMaxConcurrentStreams() > 0 {
		http2.MaxConcurrentStreams = wrapperspb.UInt32(httpSettings.GetMaxConcurrentStreams())
	}
	protocol := &httpupstreamv3.HttpProtocolOptions{
		CommonHttpProtocolOptions: &corev3.HttpProtocolOptions{IdleTimeout: durationpb.New(5 * time.Minute)},
		UpstreamProtocolOptions: &httpupstreamv3.HttpProtocolOptions_ExplicitHttpConfig_{ExplicitHttpConfig: &httpupstreamv3.HttpProtocolOptions_ExplicitHttpConfig{
			ProtocolConfig: &httpupstreamv3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{Http2ProtocolOptions: http2},
		}},
	}
	if httpSettings.GetMaxRequestsPerConnection() > 0 {
		protocol.CommonHttpProtocolOptions.MaxRequestsPerConnection = wrapperspb.UInt32(httpSettings.GetMaxRequestsPerConnection())
	}
	protocolAny, _ := anypb.New(protocol)
	return &clusterv3.Cluster{
		Name:                 ExtProcCluster,
		AltStatName:          delimitedStatsPrefix(ExtProcCluster),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS},
		ConnectTimeout:       durationpb.New(10 * time.Second),
		LbPolicy:             clusterv3.Cluster_ROUND_ROBIN,
		CircuitBreakers:      defaultCircuitBreakers(),
		OutlierDetection: &clusterv3.OutlierDetection{
			ConsecutiveGatewayFailure:          wrapperspb.UInt32(20),
			EnforcingConsecutiveGatewayFailure: wrapperspb.UInt32(100),
			Interval:                           durationpb.New(10 * time.Second),
			BaseEjectionTime:                   durationpb.New(30 * time.Second),
			MaxEjectionPercent:                 wrapperspb.UInt32(34),
		},
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: ExtProcCluster,
			Endpoints: []*endpointv3.LocalityLbEndpoints{{
				LbEndpoints: []*endpointv3.LbEndpoint{{HostIdentifier: &endpointv3.LbEndpoint_Endpoint{Endpoint: &endpointv3.Endpoint{
					Address: socketAddress(provider.GetService(), port),
				}}}},
			}},
		},
		TypedExtensionProtocolOptions: map[string]*anypb.Any{httpProtocolOptionsType: protocolAny},
	}
}

func dnsCacheConfig() *dfpcommonv3.DnsCacheConfig {
	return &dfpcommonv3.DnsCacheConfig{Name: DNSCacheName, DnsLookupFamily: clusterv3.Cluster_V4_ONLY}
}

func defaultCircuitBreakers() *clusterv3.CircuitBreakers {
	max := wrapperspb.UInt32(math.MaxUint32)
	return &clusterv3.CircuitBreakers{Thresholds: []*clusterv3.CircuitBreakers_Thresholds{{
		MaxRetries:         max,
		MaxRequests:        wrapperspb.UInt32(math.MaxUint32),
		MaxConnections:     wrapperspb.UInt32(math.MaxUint32),
		MaxPendingRequests: wrapperspb.UInt32(math.MaxUint32),
	}}}
}

func downstreamHTTPOptions() *anypb.Any {
	value, _ := anypb.New(&httpupstreamv3.HttpProtocolOptions{
		CommonHttpProtocolOptions: &corev3.HttpProtocolOptions{IdleTimeout: durationpb.New(5 * time.Minute)},
		UpstreamProtocolOptions: &httpupstreamv3.HttpProtocolOptions_UseDownstreamProtocolConfig{
			UseDownstreamProtocolConfig: &httpupstreamv3.HttpProtocolOptions_UseDownstreamHttpConfig{
				HttpProtocolOptions:  &corev3.Http1ProtocolOptions{},
				Http2ProtocolOptions: &corev3.Http2ProtocolOptions{},
			},
		},
	})
	return value
}

func delimitedStatsPrefix(name string) string {
	return name + ";"
}

func internalAddress(name string) *corev3.Address {
	return &corev3.Address{Address: &corev3.Address_EnvoyInternalAddress{EnvoyInternalAddress: &corev3.EnvoyInternalAddress{
		AddressNameSpecifier: &corev3.EnvoyInternalAddress_ServerListenerName{ServerListenerName: name},
	}}}
}

func socketAddress(address string, port uint32) *corev3.Address {
	return &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
		Address:       address,
		Protocol:      corev3.SocketAddress_TCP,
		PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: port},
	}}}
}
