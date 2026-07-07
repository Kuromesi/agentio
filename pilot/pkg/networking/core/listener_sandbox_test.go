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

package core

import (
	"testing"
	"time"

	localratelimit "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/config/xds"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/pkg/test/util/assert"
)

func sandboxEgressNode() *model.Proxy {
	return &model.Proxy{
		Labels: map[string]string{
			agentio.LabelSandboxEgress: "true",
		},
		ID:              "egress-gw-0.istio-system",
		ConfigNamespace: "istio-system",
		Metadata: &model.NodeMetadata{
			Namespace: "istio-system",
		},
		VerifiedIdentity: &spiffe.Identity{
			ServiceAccount: "egress-gw",
			Namespace:      "istio-system",
		},
	}
}

func nonSandboxNode() *model.Proxy {
	return &model.Proxy{
		Labels:          map[string]string{},
		ID:              "sidecar-0.default",
		ConfigNamespace: "default",
		Metadata:        &model.NodeMetadata{Namespace: "default"},
	}
}

func makeConnPool(opts ...func(*extensions.ConnectionPoolSettings)) *extensions.ConnectionPoolSettings {
	cp := &extensions.ConnectionPoolSettings{}
	for _, o := range opts {
		o(cp)
	}
	return cp
}

func withStreamIdleTimeout(d time.Duration) func(*extensions.ConnectionPoolSettings) {
	return func(cp *extensions.ConnectionPoolSettings) {
		if cp.Http == nil {
			cp.Http = &extensions.ConnectionPoolHttpSettings{}
		}
		cp.Http.StreamIdleTimeout = durationpb.New(d)
	}
}

func withTCPIdleTimeout(d time.Duration) func(*extensions.ConnectionPoolSettings) {
	return func(cp *extensions.ConnectionPoolSettings) {
		if cp.Tcp == nil {
			cp.Tcp = &extensions.TcpSettings{}
		}
		cp.Tcp.IdleTimeout = durationpb.New(d)
	}
}

func withTCPMaxConnDuration(d time.Duration) func(*extensions.ConnectionPoolSettings) {
	return func(cp *extensions.ConnectionPoolSettings) {
		if cp.Tcp == nil {
			cp.Tcp = &extensions.TcpSettings{}
		}
		cp.Tcp.MaxConnectionDuration = durationpb.New(d)
	}
}

func withDefaultRoute(timeout time.Duration) func(*extensions.ConnectionPoolSettings) {
	return func(cp *extensions.ConnectionPoolSettings) {
		if cp.Http == nil {
			cp.Http = &extensions.ConnectionPoolHttpSettings{}
		}
		cp.Http.DefaultRoute = &extensions.HttpRouteSettings{
			Timeout: durationpb.New(timeout),
		}
	}
}

func withRouteOverride(hosts []string, timeout time.Duration) func(*extensions.ConnectionPoolSettings) {
	return func(cp *extensions.ConnectionPoolSettings) {
		if cp.Http == nil {
			cp.Http = &extensions.ConnectionPoolHttpSettings{}
		}
		cp.Http.RouteOverrides = append(cp.Http.RouteOverrides, &extensions.HttpRouteOverride{
			Hosts: hosts,
			Settings: &extensions.HttpRouteSettings{
				Timeout: durationpb.New(timeout),
			},
		})
	}
}

func testInboundChainConfig(clusterName string) inboundChainConfig {
	return inboundChainConfig{
		clusterName: clusterName,
		port: model.ServiceInstancePort{
			ServicePort: &model.Port{
				Name:     "http",
				Protocol: protocol.HTTP,
				Port:     8080,
			},
		},
	}
}

// --- buildSandboxHTTPRouteConfig ---

func TestBuildSandboxHTTPRouteConfig_NoOverrides(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")
	connPool := makeConnPool()

	rc := buildSandboxHTTPRouteConfig(lb, cc, connPool)

	assert.Equal(t, len(rc.VirtualHosts), 1)
	assert.Equal(t, rc.VirtualHosts[0].Domains, []string{"*"})
	assert.Equal(t, rc.VirtualHosts[0].Name, "sandbox|default|8080")
}

func TestBuildSandboxHTTPRouteConfig_WithOverrides(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")
	connPool := makeConnPool(
		withRouteOverride([]string{"api.example.com"}, 60*time.Second),
		withRouteOverride([]string{"*.internal.com", "db.local"}, 10*time.Second),
		withDefaultRoute(300*time.Second),
	)

	rc := buildSandboxHTTPRouteConfig(lb, cc, connPool)

	assert.Equal(t, len(rc.VirtualHosts), 3)

	assert.Equal(t, rc.VirtualHosts[0].Domains, []string{"api.example.com"})
	assert.Equal(t, rc.VirtualHosts[0].Routes[0].GetRoute().Timeout.AsDuration(), 60*time.Second)

	assert.Equal(t, rc.VirtualHosts[1].Domains, []string{"*.internal.com", "db.local"})
	assert.Equal(t, rc.VirtualHosts[1].Routes[0].GetRoute().Timeout.AsDuration(), 10*time.Second)

	assert.Equal(t, rc.VirtualHosts[2].Domains, []string{"*"})
	assert.Equal(t, rc.VirtualHosts[2].Routes[0].GetRoute().Timeout.AsDuration(), 300*time.Second)
}

func TestBuildSandboxHTTPRouteConfig_EmptyHostsSkipped(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")
	connPool := makeConnPool()
	connPool.Http = &extensions.ConnectionPoolHttpSettings{
		RouteOverrides: []*extensions.HttpRouteOverride{
			{Hosts: []string{}, Settings: &extensions.HttpRouteSettings{Timeout: durationpb.New(10 * time.Second)}},
			{Hosts: []string{"valid.com"}, Settings: &extensions.HttpRouteSettings{Timeout: durationpb.New(20 * time.Second)}},
		},
	}

	rc := buildSandboxHTTPRouteConfig(lb, cc, connPool)

	assert.Equal(t, len(rc.VirtualHosts), 2)
	assert.Equal(t, rc.VirtualHosts[0].Domains, []string{"valid.com"})
}

func TestBuildSandboxHTTPRouteConfig_AppliesInboundEnvoyFilterPatches(t *testing.T) {

	patchValue, err := xds.BuildXDSObjectFromStruct(
		networking.EnvoyFilter_ROUTE_CONFIGURATION,
		buildPatchStruct(`{"request_headers_to_remove":["x-sandbox-test"]}`),
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	lb := &ListenerBuilder{
		node: sandboxEgressNode(),
		push: &model.PushContext{},
		envoyFilterWrapper: &model.MergedEnvoyFilterWrapper{
			Patches: map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper{
				networking.EnvoyFilter_ROUTE_CONFIGURATION: {{
					Operation: networking.EnvoyFilter_Patch_MERGE,
					Match: &networking.EnvoyFilter_EnvoyConfigObjectMatch{
						Context: networking.EnvoyFilter_SIDECAR_INBOUND,
					},
					Value: patchValue,
				}},
			},
		},
	}
	cc := testInboundChainConfig("passthrough")
	connPool := makeConnPool()

	rc := buildSandboxHTTPRouteConfig(lb, cc, connPool)

	assert.Equal(t, rc.RequestHeadersToRemove, []string{"x-sandbox-test"})
}

// --- buildSandboxRoute ---

func TestBuildSandboxRoute_NilSettings(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")

	r := buildSandboxRoute(lb, cc, nil)

	assert.Equal(t, r.GetRoute().Timeout.AsDuration(), time.Duration(0))
}

func TestBuildSandboxRoute_WithTimeout(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")

	r := buildSandboxRoute(lb, cc, &extensions.HttpRouteSettings{
		Timeout: durationpb.New(30 * time.Second),
	})

	assert.Equal(t, r.GetRoute().Timeout.AsDuration(), 30*time.Second)
}

func TestBuildSandboxRoute_WithRetry(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")

	r := buildSandboxRoute(lb, cc, &extensions.HttpRouteSettings{
		Retries: &networking.HTTPRetry{
			Attempts:      3,
			PerTryTimeout: durationpb.New(5 * time.Second),
			RetryOn:       "connect-failure,refused-stream",
		},
	})

	rp := r.GetRoute().GetRetryPolicy()
	assert.Equal(t, rp.PerTryTimeout.AsDuration(), 5*time.Second)
	assert.Equal(t, rp.NumRetries.GetValue(), uint32(3))
	assert.Equal(t, rp.RetryOn, "connect-failure,refused-stream")
}

func TestBuildSandboxRoute_RouteMatch(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")

	r := buildSandboxRoute(lb, cc, nil)

	assert.Equal(t, r.GetMatch().GetPrefix(), "/")
	assert.Equal(t, r.Name, "default")
}

func TestBuildSandboxRoute_ClusterMatchesChainConfig(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("tls_connect_originate")

	r := buildSandboxRoute(lb, cc, &extensions.HttpRouteSettings{
		Timeout: durationpb.New(60 * time.Second),
	})

	assert.Equal(t, r.GetRoute().GetCluster(), "tls_connect_originate")
}

// --- applySandboxStreamIdleTimeout ---

func TestApplySandboxStreamIdleTimeout_Default(t *testing.T) {

	lb := &ListenerBuilder{
		node: sandboxEgressNode(),
		push: &model.PushContext{
			AgentioConfig: &model.AgentioConfig{
				AgentioConfig: &extensions.AgentioConfig{
					EgressGateways: []*extensions.EgressGateway{{
						Name:      "egress-gw",
						Namespace: "istio-system",
					}},
				},
			},
		},
	}
	h := &hcm.HttpConnectionManager{StreamIdleTimeout: durationpb.New(0)}

	applySandboxStreamIdleTimeout(lb, h)

	assert.Equal(t, h.StreamIdleTimeout.AsDuration(), 30*time.Minute)
}

func TestApplySandboxStreamIdleTimeout_Configured(t *testing.T) {

	lb := &ListenerBuilder{
		node: sandboxEgressNode(),
		push: &model.PushContext{
			AgentioConfig: &model.AgentioConfig{
				AgentioConfig: &extensions.AgentioConfig{
					EgressGateways: []*extensions.EgressGateway{{
						Name:      "egress-gw",
						Namespace: "istio-system",
						ConnectionPool: makeConnPool(
							withStreamIdleTimeout(10 * time.Minute),
						),
					}},
				},
			},
		},
	}
	h := &hcm.HttpConnectionManager{StreamIdleTimeout: durationpb.New(0)}

	applySandboxStreamIdleTimeout(lb, h)

	assert.Equal(t, h.StreamIdleTimeout.AsDuration(), 10*time.Minute)
}

func TestApplySandboxStreamIdleTimeout_NonSandboxNoop(t *testing.T) {

	lb := &ListenerBuilder{
		node: nonSandboxNode(),
		push: &model.PushContext{},
	}
	h := &hcm.HttpConnectionManager{StreamIdleTimeout: durationpb.New(0)}

	applySandboxStreamIdleTimeout(lb, h)

	assert.Equal(t, h.StreamIdleTimeout.AsDuration(), time.Duration(0))
}

// --- applySandboxTCPTimeouts ---

func TestApplySandboxTCPTimeouts_Defaults(t *testing.T) {
	tp := &tcp.TcpProxy{}

	applySandboxTCPTimeouts(nil, tp)

	assert.Equal(t, tp.IdleTimeout.AsDuration(), 1*time.Hour)
	assert.Equal(t, tp.MaxDownstreamConnectionDuration == nil, true)
}

func TestApplySandboxTCPTimeouts_Configured(t *testing.T) {
	tp := &tcp.TcpProxy{}
	connPool := makeConnPool(
		withTCPIdleTimeout(30*time.Minute),
		withTCPMaxConnDuration(24*time.Hour),
	)

	applySandboxTCPTimeouts(connPool, tp)

	assert.Equal(t, tp.IdleTimeout.AsDuration(), 30*time.Minute)
	assert.Equal(t, tp.MaxDownstreamConnectionDuration.AsDuration(), 24*time.Hour)
}

func TestApplySandboxTCPTimeouts_PartialConfig(t *testing.T) {
	tp := &tcp.TcpProxy{}
	connPool := makeConnPool(withTCPMaxConnDuration(2 * time.Hour))

	applySandboxTCPTimeouts(connPool, tp)

	assert.Equal(t, tp.IdleTimeout.AsDuration(), 1*time.Hour)
	assert.Equal(t, tp.MaxDownstreamConnectionDuration.AsDuration(), 2*time.Hour)
}

func TestApplySandboxTCPTimeouts_EmptyConnPool(t *testing.T) {
	tp := &tcp.TcpProxy{}
	connPool := makeConnPool()

	applySandboxTCPTimeouts(connPool, tp)

	assert.Equal(t, tp.IdleTimeout.AsDuration(), 1*time.Hour)
	assert.Equal(t, tp.MaxDownstreamConnectionDuration == nil, true)
}

// --- Error state / validation ---

func TestBuildSandboxRoute_DecoratorNonEmpty(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}

	for _, cluster := range []string{"passthrough", "encap", "tls_connect_originate"} {
		t.Run(cluster, func(t *testing.T) {
			cc := testInboundChainConfig(cluster)
			r := buildSandboxRoute(lb, cc, nil)
			op := r.GetDecorator().GetOperation()
			if op == "" {
				t.Fatalf("decorator operation must be non-empty (Envoy requires >= 1 char), got empty for cluster %q", cluster)
			}
		})
	}
}

func TestBuildSandboxRoute_DecoratorNonEmptyWithSettings(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("encap")

	r := buildSandboxRoute(lb, cc, &extensions.HttpRouteSettings{
		Timeout: durationpb.New(30 * time.Second),
	})

	if r.GetDecorator().GetOperation() == "" {
		t.Fatal("decorator operation must be non-empty with settings")
	}
}

func TestBuildSandboxHTTPRouteConfig_AllRoutesHaveValidDecorator(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("encap")
	connPool := makeConnPool(
		withRouteOverride([]string{"a.com"}, 10*time.Second),
		withDefaultRoute(60*time.Second),
	)

	rc := buildSandboxHTTPRouteConfig(lb, cc, connPool)

	for _, vh := range rc.VirtualHosts {
		for _, r := range vh.Routes {
			if r.GetDecorator().GetOperation() == "" {
				t.Fatalf("VirtualHost %q route has empty decorator operation", vh.Name)
			}
		}
	}
}

func TestBuildSandboxHTTPRouteConfig_ValidateClustersDisabled(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")

	rc := buildSandboxHTTPRouteConfig(lb, cc, makeConnPool())

	if rc.ValidateClusters == nil || rc.ValidateClusters.Value {
		t.Fatal("ValidateClusters must be false for sandbox DFP routes")
	}
}

func TestBuildSandboxHTTPRouteConfig_FallbackAlwaysPresent(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")

	cases := []struct {
		name     string
		connPool *extensions.ConnectionPoolSettings
	}{
		{"nil http", makeConnPool()},
		{"empty overrides", makeConnPool(withDefaultRoute(30 * time.Second))},
		{"only overrides", makeConnPool(withRouteOverride([]string{"a.com"}, 10*time.Second))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := buildSandboxHTTPRouteConfig(lb, cc, tc.connPool)
			last := rc.VirtualHosts[len(rc.VirtualHosts)-1]
			assert.Equal(t, last.Domains, []string{"*"})
		})
	}
}

func TestApplySandboxTCPTimeouts_NilConnPool_NeverPanics(t *testing.T) {
	tp := &tcp.TcpProxy{}
	applySandboxTCPTimeouts(nil, tp)
	if tp.IdleTimeout == nil {
		t.Fatal("IdleTimeout must be set to default even with nil connPool")
	}
}

// --- Full scenario ---

func sandboxLBWithRateLimit(rl *extensions.LocalRateLimitSettings) *ListenerBuilder {
	return &ListenerBuilder{
		node: sandboxEgressNode(),
		push: &model.PushContext{
			AgentioConfig: &model.AgentioConfig{
				AgentioConfig: &extensions.AgentioConfig{
					EgressGateways: []*extensions.EgressGateway{{
						Name:             "egress-gw",
						Namespace:        "istio-system",
						ConnectRateLimit: rl,
					}},
				},
			},
		},
	}
}

func parseRateLimitFilter(f *hcm.HttpFilter) *localratelimit.LocalRateLimit {
	if f == nil {
		return nil
	}
	cfg := &localratelimit.LocalRateLimit{}
	if err := proto.Unmarshal(f.GetTypedConfig().GetValue(), cfg); err != nil {
		return nil
	}
	return cfg
}

// --- buildSandboxConnectTerminateRateLimitFilter ---

func TestRateLimit_NilWhenNotConfigured(t *testing.T) {

	lb := sandboxLBWithRateLimit(nil)

	f := buildSandboxConnectTerminateRateLimitFilter(lb)

	assert.Equal(t, f == nil, true)
}

func TestRateLimit_NilForNonSandbox(t *testing.T) {

	lb := &ListenerBuilder{
		node: nonSandboxNode(),
		push: &model.PushContext{},
	}

	f := buildSandboxConnectTerminateRateLimitFilter(lb)

	assert.Equal(t, f == nil, true)
}

func TestRateLimit_GlobalBucketOnly(t *testing.T) {

	lb := sandboxLBWithRateLimit(&extensions.LocalRateLimitSettings{
		TokenBucket: &extensions.TokenBucket{
			MaxTokens:     100,
			TokensPerFill: 50,
			FillInterval:  durationpb.New(time.Second),
		},
	})

	f := buildSandboxConnectTerminateRateLimitFilter(lb)

	assert.Equal(t, f != nil, true)
	cfg := parseRateLimitFilter(f)
	assert.Equal(t, cfg.StatPrefix, "connect_rate_limit")
	assert.Equal(t, cfg.TokenBucket.MaxTokens, uint32(100))
	assert.Equal(t, cfg.TokenBucket.TokensPerFill.GetValue(), uint32(50))
	assert.Equal(t, cfg.TokenBucket.FillInterval.AsDuration(), time.Second)
	assert.Equal(t, cfg.FilterEnabled.DefaultValue.Numerator, uint32(100))
	assert.Equal(t, cfg.FilterEnforced.DefaultValue.Numerator, uint32(100))
	assert.Equal(t, len(cfg.Descriptors), 0)
	assert.Equal(t, len(cfg.RateLimits), 0)
}

func TestRateLimit_PerDownstreamConnection(t *testing.T) {

	lb := sandboxLBWithRateLimit(&extensions.LocalRateLimitSettings{
		TokenBucket: &extensions.TokenBucket{
			MaxTokens:     10,
			TokensPerFill: 10,
			FillInterval:  durationpb.New(time.Second),
		},
		PerDownstreamConnection: true,
	})

	cfg := parseRateLimitFilter(buildSandboxConnectTerminateRateLimitFilter(lb))

	assert.Equal(t, cfg.LocalRateLimitPerDownstreamConnection, true)
}

func TestRateLimit_WithDescriptors(t *testing.T) {

	lb := sandboxLBWithRateLimit(&extensions.LocalRateLimitSettings{
		TokenBucket: &extensions.TokenBucket{
			MaxTokens:     100,
			TokensPerFill: 100,
			FillInterval:  durationpb.New(time.Second),
		},
		Descriptors: []*extensions.RateLimitDescriptor{
			{
				Entries: []*extensions.RateLimitEntry{
					{Key: "client_ip", Cel: `source.address`},
				},
				TokenBucket: &extensions.TokenBucket{
					MaxTokens:     10,
					TokensPerFill: 10,
					FillInterval:  durationpb.New(time.Second),
				},
			},
		},
	})

	cfg := parseRateLimitFilter(buildSandboxConnectTerminateRateLimitFilter(lb))

	assert.Equal(t, len(cfg.Descriptors), 1)
	assert.Equal(t, cfg.Descriptors[0].Entries[0].Key, "client_ip")
	assert.Equal(t, cfg.Descriptors[0].TokenBucket.MaxTokens, uint32(10))

	assert.Equal(t, len(cfg.RateLimits), 1)
	assert.Equal(t, cfg.RateLimits[0].Actions[0].GetExtension() != nil, true)
}

func TestRateLimit_MultipleDescriptorKeys(t *testing.T) {

	lb := sandboxLBWithRateLimit(&extensions.LocalRateLimitSettings{
		Descriptors: []*extensions.RateLimitDescriptor{
			{
				Entries: []*extensions.RateLimitEntry{
					{Key: "peer_ns", Cel: `filter_state["downstream_peer"].namespace`},
					{Key: "peer_name", Cel: `filter_state["downstream_peer"].name`},
				},
				TokenBucket: &extensions.TokenBucket{
					MaxTokens: 5, TokensPerFill: 5,
					FillInterval: durationpb.New(time.Second),
				},
			},
		},
	})

	cfg := parseRateLimitFilter(buildSandboxConnectTerminateRateLimitFilter(lb))

	assert.Equal(t, len(cfg.Descriptors), 1)
	assert.Equal(t, len(cfg.Descriptors[0].Entries), 2)

	assert.Equal(t, len(cfg.RateLimits), 1)
	assert.Equal(t, len(cfg.RateLimits[0].Actions), 2)
}

func TestRateLimit_DescriptorWithoutCEL_NoAction(t *testing.T) {

	lb := sandboxLBWithRateLimit(&extensions.LocalRateLimitSettings{
		TokenBucket: &extensions.TokenBucket{
			MaxTokens: 100, TokensPerFill: 100,
			FillInterval: durationpb.New(time.Second),
		},
		Descriptors: []*extensions.RateLimitDescriptor{
			{
				Entries: []*extensions.RateLimitEntry{
					{Key: "static_key", Value: "static_value"},
				},
				TokenBucket: &extensions.TokenBucket{
					MaxTokens: 20, TokensPerFill: 20,
					FillInterval: durationpb.New(time.Second),
				},
			},
		},
	})

	cfg := parseRateLimitFilter(buildSandboxConnectTerminateRateLimitFilter(lb))

	assert.Equal(t, len(cfg.Descriptors), 1)
	assert.Equal(t, len(cfg.RateLimits), 0)
}

func TestRateLimit_CELExpression(t *testing.T) {

	lb := sandboxLBWithRateLimit(&extensions.LocalRateLimitSettings{
		Descriptors: []*extensions.RateLimitDescriptor{
			{
				Entries: []*extensions.RateLimitEntry{
					{
						Key: "downstream_name",
						Cel: `filter_state["downstream_peer"].name`,
					},
				},
				TokenBucket: &extensions.TokenBucket{
					MaxTokens: 5, TokensPerFill: 5,
					FillInterval: durationpb.New(time.Second),
				},
			},
		},
	})

	cfg := parseRateLimitFilter(buildSandboxConnectTerminateRateLimitFilter(lb))

	assert.Equal(t, len(cfg.Descriptors), 1)
	assert.Equal(t, cfg.Descriptors[0].Entries[0].Key, "downstream_name")

	action := cfg.RateLimits[0].Actions[0]
	assert.Equal(t, action.GetExtension() != nil, true)
	assert.Equal(t, action.GetExtension().Name, "envoy.rate_limit_descriptors.expr")
}

// --- toEnvoyTokenBucket ---

func TestToEnvoyTokenBucket_Nil(t *testing.T) {
	assert.Equal(t, toEnvoyTokenBucket(nil) == nil, true)
}

func TestToEnvoyTokenBucket_Full(t *testing.T) {
	tb := toEnvoyTokenBucket(&extensions.TokenBucket{
		MaxTokens:     200,
		TokensPerFill: 50,
		FillInterval:  durationpb.New(500 * time.Millisecond),
	})
	assert.Equal(t, tb.MaxTokens, uint32(200))
	assert.Equal(t, tb.TokensPerFill.GetValue(), uint32(50))
	assert.Equal(t, tb.FillInterval.AsDuration(), 500*time.Millisecond)
}

func TestToEnvoyTokenBucket_ZeroTokensPerFill(t *testing.T) {
	tb := toEnvoyTokenBucket(&extensions.TokenBucket{
		MaxTokens:    10,
		FillInterval: durationpb.New(time.Second),
	})
	assert.Equal(t, tb.TokensPerFill == nil, true)
}

// --- Full scenario ---

func TestBuildSandboxHTTPRouteConfig_FullScenario(t *testing.T) {

	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("tls_connect_originate")

	connPool := makeConnPool(
		withRouteOverride([]string{"ws.example.com"}, 0),
		withRouteOverride([]string{"api.example.com", "api2.example.com"}, 60*time.Second),
		withDefaultRoute(120*time.Second),
	)
	connPool.Http.RouteOverrides[1].Settings.Retries = &networking.HTTPRetry{
		Attempts:      3,
		PerTryTimeout: durationpb.New(10 * time.Second),
		RetryOn:       "connect-failure,refused-stream",
	}

	rc := buildSandboxHTTPRouteConfig(lb, cc, connPool)

	assert.Equal(t, rc.Name, "tls_connect_originate")
	assert.Equal(t, len(rc.VirtualHosts), 3)

	// ws.example.com: timeout=0 (disabled for websocket)
	wsVH := rc.VirtualHosts[0]
	assert.Equal(t, wsVH.Domains, []string{"ws.example.com"})
	assert.Equal(t, wsVH.Routes[0].GetRoute().Timeout.AsDuration(), time.Duration(0))

	// api: timeout=60s, per_try=10s, retries=3
	apiVH := rc.VirtualHosts[1]
	assert.Equal(t, apiVH.Domains, []string{"api.example.com", "api2.example.com"})
	assert.Equal(t, apiVH.Routes[0].GetRoute().Timeout.AsDuration(), 60*time.Second)
	assert.Equal(t, apiVH.Routes[0].GetRoute().GetRetryPolicy().PerTryTimeout.AsDuration(), 10*time.Second)
	assert.Equal(t, apiVH.Routes[0].GetRoute().GetRetryPolicy().NumRetries.GetValue(), uint32(3))
	assert.Equal(t, apiVH.Routes[0].GetRoute().GetRetryPolicy().RetryOn, "connect-failure,refused-stream")

	// fallback: timeout=120s
	fallbackVH := rc.VirtualHosts[2]
	assert.Equal(t, fallbackVH.Domains, []string{"*"})
	assert.Equal(t, fallbackVH.Routes[0].GetRoute().Timeout.AsDuration(), 120*time.Second)

	for _, vh := range rc.VirtualHosts {
		for _, r := range vh.Routes {
			assert.Equal(t, r.GetRoute().GetCluster(), "tls_connect_originate")
		}
	}
}
