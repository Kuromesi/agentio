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

package agentio

import (
	"math"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	http "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pilot/pkg/util/protoconv"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/wellknown"
)

var SandboxExtProcName = env.Register("SANDBOX_EXT_PROC_NAME", "sandbox-ext-proc",
	"External processing cluster name for sandbox.").Get()

// resolveExtProc returns the effective ExtProcProvider for the given proxy.
// Gateway-level ext_proc takes precedence over the global AgentioConfig default.
func resolveExtProc(proxy *model.Proxy, config *model.AgentioConfig) *extensions.ExtProcProvider {
	if config == nil {
		return nil
	}
	if g := FindEgressGatewayForProxy(proxy, config.GetEgressGateways()); g != nil && g.ExtProc != nil {
		if g.ExtProc.Service == "" {
			return nil
		}
		return g.ExtProc
	}
	return config.GetSandboxExtProc()
}

// BuildExtProcClusters returns the STRICT_DNS cluster for the ext_proc gRPC upstream,
// or nil when the proxy is not a sandbox egress or no ext_proc provider is configured.
func BuildExtProcClusters(proxy *model.Proxy, config *model.AgentioConfig) []*cluster.Cluster {
	extProc := resolveExtProc(proxy, config)
	if !IsSandboxEgress(proxy) || extProc == nil {
		return nil
	}

	c := &cluster.Cluster{
		Name:                 SandboxExtProcName,
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
		// 10s matches Istio's default mesh ConnectTimeout. The previous 1s budget
		// was not enough for cross-namespace STRICT_DNS lookup + h2 + TLS cold
		// start (DNS TTL miss + handshake can each be several hundred ms), so
		// the first request after a long idle would fail with UF/connect-timeout.
		ConnectTimeout: durationpb.New(10 * time.Second),
		LbPolicy:       cluster.Cluster_ROUND_ROBIN,
		// Eject a bad endpoint instead of letting it drag every request through a
		// retry. STRICT_DNS may resolve several A records and previously a single
		// dead replica was hit on every round_robin tick. consecutive_gateway_failure
		// covers connect timeouts / 5xx from the upstream, which is what we expect
		// when a replica is unhealthy. base_ejection_time keeps the host out long
		// enough for k8s to drop it from the Endpoint slice. max_ejection_percent=100
		// is safe here because the ext_proc filter is configured with
		// failure_mode_allow so a fully-ejected cluster still lets traffic through.
		OutlierDetection: &cluster.OutlierDetection{
			ConsecutiveGatewayFailure:          &wrapperspb.UInt32Value{Value: 20},
			EnforcingConsecutiveGatewayFailure: &wrapperspb.UInt32Value{Value: 100},
			Interval:                           durationpb.New(10 * time.Second),
			BaseEjectionTime:                   durationpb.New(30 * time.Second),
			MaxEjectionPercent:                 &wrapperspb.UInt32Value{Value: 34},
		},
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: SandboxExtProcName,
			Endpoints: []*endpoint.LocalityLbEndpoints{{
				LbEndpoints: []*endpoint.LbEndpoint{{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{
						Endpoint: &endpoint.Endpoint{
							Address: &core.Address{
								Address: &core.Address_SocketAddress{
									SocketAddress: &core.SocketAddress{
										Address: extProc.Service,
										PortSpecifier: &core.SocketAddress_PortValue{
											PortValue: extProc.Port,
										},
									},
								},
							},
						},
					},
				}},
			}},
		},
		CircuitBreakers: &cluster.CircuitBreakers{
			Thresholds: []*cluster.CircuitBreakers_Thresholds{getDefaultCircuitBreakerThresholds()},
		},
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			v3.HttpProtocolOptionsType: protoconv.MessageToAny(buildExtProcHttpProtocolOptions(extProc)),
		},
		AltStatName: util.DelimitedStatsPrefix(SandboxExtProcName),
	}
	return []*cluster.Cluster{c}
}

func buildExtProcHttpProtocolOptions(extProc *extensions.ExtProcProvider) *http.HttpProtocolOptions {
	httpSettings := extProc.GetClusterSettings().GetHttp()

	http2Options := &core.Http2ProtocolOptions{
		AllowConnect: true,
	}
	if httpSettings.GetMaxConcurrentStreams() > 0 {
		http2Options.MaxConcurrentStreams = &wrapperspb.UInt32Value{Value: httpSettings.GetMaxConcurrentStreams()}
	}

	opts := &http.HttpProtocolOptions{
		CommonHttpProtocolOptions: &core.HttpProtocolOptions{
			IdleTimeout: durationpb.New(5 * time.Minute),
		},
		UpstreamProtocolOptions: &http.HttpProtocolOptions_ExplicitHttpConfig_{
			ExplicitHttpConfig: &http.HttpProtocolOptions_ExplicitHttpConfig{
				ProtocolConfig: &http.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
					Http2ProtocolOptions: http2Options,
				},
			},
		},
	}

	if httpSettings.GetMaxRequestsPerConnection() > 0 {
		opts.CommonHttpProtocolOptions.MaxRequestsPerConnection = &wrapperspb.UInt32Value{Value: httpSettings.GetMaxRequestsPerConnection()}
	}

	return opts
}

func toEnvoyHeaderSendMode(mode extensions.HeaderSendMode, defaultMode extproc.ProcessingMode_HeaderSendMode) extproc.ProcessingMode_HeaderSendMode {
	switch mode {
	case extensions.HeaderSendMode_SEND:
		return extproc.ProcessingMode_SEND
	case extensions.HeaderSendMode_SKIP:
		return extproc.ProcessingMode_SKIP
	default:
		return defaultMode
	}
}

// BuildExtProcFilter returns the ext_proc HTTP filter pointing at the cluster
// built by BuildExtProcClusters. Returns nil when the proxy is not a sandbox
// egress or no ext_proc provider is configured — the caller relies on this nil
// return to skip filter wiring entirely.
func BuildExtProcFilter(proxy *model.Proxy, config *model.AgentioConfig) []*hcm.HttpFilter {
	extProc := resolveExtProc(proxy, config)
	if !IsSandboxEgress(proxy) || extProc == nil {
		return nil
	}

	requestHeaderMode := extproc.ProcessingMode_SEND
	responseHeaderMode := extproc.ProcessingMode_SKIP

	var requestAttributes, responseAttributes []string
	if extProc.Request != nil {
		requestHeaderMode = toEnvoyHeaderSendMode(extProc.Request.HeaderMode, requestHeaderMode)
		requestAttributes = extProc.Request.Attributes
	}
	if extProc.Response != nil {
		responseHeaderMode = toEnvoyHeaderSendMode(extProc.Response.HeaderMode, responseHeaderMode)
		responseAttributes = extProc.Response.Attributes
	}

	filter := &extproc.ExternalProcessor{
		GrpcService: &core.GrpcService{
			TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
				EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
					ClusterName: SandboxExtProcName,
				},
			},
		},
		FailureModeAllow:  extProc.FailureModeAllow,
		AllowModeOverride: true,
		ProcessingMode: &extproc.ProcessingMode{
			RequestHeaderMode:  requestHeaderMode,
			ResponseHeaderMode: responseHeaderMode,
		},
		RequestAttributes:  requestAttributes,
		ResponseAttributes: responseAttributes,
		MessageTimeout:     parseMessageTimeout(extProc.MessageTimeout),
	}

	return []*hcm.HttpFilter{{
		Name:       wellknown.HTTPExternalProcessing,
		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: protoconv.MessageToAny(filter)},
	}}
}

func parseMessageTimeout(s string) *durationpb.Duration {
	if s == "" {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Warnf("invalid ext_proc message_timeout %q: %v, using default", s, err)
		return nil
	}
	return durationpb.New(d)
}

func getDefaultCircuitBreakerThresholds() *cluster.CircuitBreakers_Thresholds {
	return &cluster.CircuitBreakers_Thresholds{
		// DefaultMaxRetries specifies the default for the Envoy circuit breaker parameter max_retries. This
		// defines the maximum number of parallel retries a given Envoy will allow to the upstream cluster. Envoy defaults
		// this value to 3, however that has shown to be insufficient during periods of pod churn (e.g. rolling updates),
		// where multiple endpoints in a cluster are terminated. In these scenarios the circuit breaker can kick
		// in before Pilot is able to deliver an updated endpoint list to Envoy, leading to client-facing 503s.
		MaxRetries:         &wrapperspb.UInt32Value{Value: math.MaxUint32},
		MaxRequests:        &wrapperspb.UInt32Value{Value: math.MaxUint32},
		MaxConnections:     &wrapperspb.UInt32Value{Value: math.MaxUint32},
		MaxPendingRequests: &wrapperspb.UInt32Value{Value: math.MaxUint32},
		TrackRemaining:     !features.DisableTrackRemainingMetrics,
	}
}
