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

	configv1 "github.com/openkruise/agentio/api/config/v1"

	xdsmatcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	celv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	dfpclusterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	dfpcommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	extensionmatchingv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	dfphttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	tlsinspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	previousprioritiesv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/retry/priority/previous_priorities/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	httpupstreamv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	networkingv1alpha3 "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pkg/test"

	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking/telemetry"
)

func testGateway(config *configv1.EgressGateway) model.Gateway {
	if config == nil {
		config = &configv1.EgressGateway{}
	}
	return model.Gateway{
		Namespace: "agentio-system",
		Name:      "egress",
		Config:    config,
	}
}

func TestBuildProducesProductionGatewayGraph(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	resources, err := Build(Inputs{
		Gateway: testGateway(&configv1.EgressGateway{
			ConnectionPool: &configv1.ConnectionPoolSettings{
				Tcp: &configv1.TcpSettings{IdleTimeout: durationpb.New(2 * time.Minute)},
				Http: &configv1.ConnectionPoolHttpSettings{StreamIdleTimeout: durationpb.New(3 * time.Minute),
					RouteOverrides: []*configv1.HttpRouteOverride{{Hosts: []string{"api.example.com"},
						Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(4 * time.Second)}}}},
			},
			ConnectRateLimit: &configv1.LocalRateLimitSettings{TokenBucket: &configv1.TokenBucket{
				MaxTokens: 20, TokensPerFill: 5, FillInterval: durationpb.New(time.Second),
			}},
		}),
		GlobalExtProc: &configv1.ExtProcProvider{
			Service:          "epe.agentio-system.svc",
			Port:             9002,
			MessageTimeout:   "350ms",
			FailureModeAllow: true,
		},
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	for _, name := range []string{MainInternal, MainForward, PassthroughCluster, BlackHoleCluster,
		HTTPDynamicForwardProxy, TLSConnectOriginate, ExtProcCluster} {
		cluster := clusters[name]
		if cluster == nil {
			t.Errorf("cluster %q not found", name)
			continue
		}
		if err := cluster.ValidateAll(); err != nil {
			t.Errorf("cluster %q invalid: %v", name, err)
		}
	}
	httpDFP := &dfpclusterv3.ClusterConfig{}
	if err := clusters[HTTPDynamicForwardProxy].GetClusterType().GetTypedConfig().UnmarshalTo(httpDFP); err != nil {
		t.Fatalf("unmarshal HTTP DFP cluster: %v", err)
	}
	if httpDFP.GetDnsCacheConfig().GetName() != DNSCacheName {
		t.Fatalf("HTTP DFP cache = %q", httpDFP.GetDnsCacheConfig().GetName())
	}
	for name, cluster := range clusters {
		if _, found := cluster.GetTypedExtensionProtocolOptions()["type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions"]; found {
			t.Fatalf("cluster %s uses an Any type URL as protocol-options map key", name)
		}
	}

	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })
	for _, name := range []string{ConnectTerminate, MainInternal, MainForward} {
		listener := listeners[name]
		if listener == nil {
			t.Errorf("listener %q not found", name)
			continue
		}
		if err := listener.ValidateAll(); err != nil {
			t.Errorf("listener %q invalid: %v", name, err)
		}
	}
	tlsChain := findFilterChain(t, listeners[MainInternal], tlsTerminateChain)
	if got, want := networkFilterNames(tlsChain), []string{
		"envoy.filters.network.set_filter_state",
		"connect_downstream_peer",
		"envoy.filters.network.tcp_proxy",
	}; !equalStrings(got, want) {
		t.Fatalf("TLS termination filter order = %v, want %v", got, want)
	}
	connectHCM := findHCM(t, listeners[ConnectTerminate])
	if connectHCM.GetRds().GetRouteConfigName() != ConnectTerminate {
		t.Fatalf("connect RDS name = %q", connectHCM.GetRds().GetRouteConfigName())
	}
	if got, want := httpFilterNames(connectHCM), []string{
		"waypoint_downstream_peer_metadata",
		"connect_authority",
		"envoy.filters.http.local_ratelimit",
		"envoy.filters.http.router",
	}; !equalStrings(got, want) {
		t.Fatalf("CONNECT filter order = %v, want %v", got, want)
	}
	if !hasHTTPFilter(connectHCM, "envoy.filters.http.local_ratelimit") {
		t.Error("CONNECT local rate-limit filter not found")
	}
	forwardHCM := findHCM(t, listeners[MainForward])
	if hasHTTPFilter(forwardHCM, staticEndpointFilterStateFilter) {
		t.Fatalf("main_forward without service entries gained static endpoint filter: %v", httpFilterNames(forwardHCM))
	}
	if !hasHTTPFilter(forwardHCM, "envoy.filters.http.rbac") ||
		!hasHTTPFilter(forwardHCM, "envoy.filters.http.ext_proc") ||
		!hasHTTPFilter(forwardHCM, "envoy.filters.http.dynamic_forward_proxy") {
		t.Fatalf("main_forward filters = %v", httpFilterNames(forwardHCM))
	}
	for _, filter := range forwardHCM.GetHttpFilters() {
		if filter.GetName() == "envoy.filters.http.ext_proc" {
			cfg := &extprocv3.ExternalProcessor{}
			if err := filter.GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.GetGrpcService().GetEnvoyGrpc().GetClusterName() != ExtProcCluster || cfg.GetMessageTimeout().AsDuration() != 350*time.Millisecond {
				t.Fatalf("ext_proc config = %+v", cfg)
			}
		}
		if filter.GetName() == "envoy.filters.http.dynamic_forward_proxy" {
			cfg := &dfphttpv3.FilterConfig{}
			if err := filter.GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.GetDnsCacheConfig().GetName() != DNSCacheName {
				t.Fatalf("HTTP filter DFP cache = %q", cfg.GetDnsCacheConfig().GetName())
			}
			if cfg.GetAllowDynamicHostFromFilterState() {
				t.Fatal("HTTP filter DFP unexpectedly accepts dynamic host state without static service entries")
			}
		}
	}

	routes := messagesOf(t, resources, model.RouteType, func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} })
	for _, name := range []string{ConnectTerminate, HTTPDynamicForwardProxy, TLSConnectOriginate} {
		if routes[name] == nil {
			t.Errorf("route %q not found", name)
			continue
		}
		if err := routes[name].ValidateAll(); err != nil {
			t.Errorf("route %q invalid: %v", name, err)
		}
	}
	tlsRoute := routes[TLSConnectOriginate]
	if len(tlsRoute.GetVirtualHosts()) != 2 || tlsRoute.GetVirtualHosts()[0].GetDomains()[0] != "api.example.com" {
		t.Fatalf("TLS route virtual hosts = %+v", tlsRoute.GetVirtualHosts())
	}
	if got := tlsRoute.GetVirtualHosts()[0].GetRoutes()[1].GetRoute().GetTimeout().AsDuration(); got != 4*time.Second {
		t.Fatalf("route override timeout = %s", got)
	}

	for _, resource := range resources {
		if resource.XDSName == "" {
			t.Errorf("resource %s has no wire name", resource.Key.Name)
		}
		if resource.Key.Name == resource.XDSName {
			t.Errorf("resource %s is not gateway-scoped internally", resource.Key.Name)
		}
		if resource.Facts.GatewayOwner != "agentio-system/egress" {
			t.Errorf("resource %s facts = %+v", resource.Key.Name, resource.Facts)
		}
	}
}

func TestBuildConnectTerminateRouteDisablesRequestTimeout(t *testing.T) {
	resources, err := Build(Inputs{
		Gateway:          testGateway(nil),
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	routes := messagesOf(t, resources, model.RouteType, func() *routev3.RouteConfiguration {
		return &routev3.RouteConfiguration{}
	})
	connect := routes[ConnectTerminate].GetVirtualHosts()[0].GetRoutes()[0].GetRoute()
	if connect.GetTimeout() == nil {
		t.Fatal("CONNECT termination route timeout is unset; Envoy's request timeout would cap the tunnel lifetime")
	}
	if got := connect.GetTimeout().AsDuration(); got != 0 {
		t.Fatalf("CONNECT termination route timeout = %s, want disabled", got)
	}
}

func TestBuildStaticEgressServiceEntriesPreserveDestinationPort(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local", Gateway: testGateway(&configv1.EgressGateway{
			ConnectionPool: &configv1.ConnectionPoolSettings{Http: &configv1.ConnectionPoolHttpSettings{
				RouteOverrides: []*configv1.HttpRouteOverride{{
					Hosts:    []string{"api.example.com", "other.example.com"},
					Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(17 * time.Second)},
				}},
			}},
			ServiceEntries: []*configv1.EgressServiceEntry{
				{
					Hosts: []string{"api.example.com"},
					Endpoints: []*configv1.EgressServiceEntryEndpoint{
						{Address: "10.10.20.30"},
						{Address: "10.10.20.31"},
					},
				},
				{
					Hosts:     []string{"single.example.com"},
					Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "10.10.20.40"}},
				},
			},
		})})
	if err != nil {
		t.Fatalf("Build(): %v", err)
	}

	routes := messagesOf(t, resources, model.RouteType, func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} })
	for _, routeName := range []string{HTTPDynamicForwardProxy, TLSConnectOriginate} {
		routeConfig := routes[routeName]
		if got, want := len(routeConfig.GetVirtualHosts()), 4; got != want {
			t.Fatalf("%s virtual hosts = %d, want two static services, remaining override, and fallback (%d)", routeName, got, want)
		}
		apiHost := routeConfig.GetVirtualHosts()[0]
		if got, want := apiHost.GetDomains(), []string{"api.example.com", "api.example.com:*"}; !slices.Equal(got, want) {
			t.Fatalf("%s static domains = %v, want %v", routeName, got, want)
		}
		apiRoute := apiHost.GetRoutes()[1]
		if got := apiRoute.GetRoute().GetTimeout().AsDuration(); got != 17*time.Second {
			t.Fatalf("%s static route timeout = %s, want matching override 17s", routeName, got)
		}
		weighted := apiRoute.GetRoute().GetWeightedClusters().GetClusters()
		if got, want := len(weighted), 2; got != want {
			t.Fatalf("%s static weighted endpoints = %d, want %d", routeName, got, want)
		}
		for index, wantAddress := range []string{"10.10.20.30", "10.10.20.31"} {
			entry := weighted[index]
			if entry.GetName() != routeName || entry.GetWeight().GetValue() != 1 {
				t.Fatalf("%s weighted endpoint %d = name %q weight %d", routeName, index, entry.GetName(), entry.GetWeight().GetValue())
			}
			assertStaticEndpointState(t, entry.GetTypedPerFilterConfig(), wantAddress)
		}

		singleRoute := routeConfig.GetVirtualHosts()[1].GetRoutes()[1]
		if got := singleRoute.GetRoute().GetCluster(); got != routeName {
			t.Fatalf("%s single endpoint cluster = %q, want existing DFP cluster", routeName, got)
		}
		assertStaticEndpointState(t, singleRoute.GetTypedPerFilterConfig(), "10.10.20.40")

		remainingOverride := routeConfig.GetVirtualHosts()[2]
		if got, want := remainingOverride.GetDomains(), []string{"other.example.com"}; !slices.Equal(got, want) {
			t.Fatalf("%s remaining override domains = %v, want %v", routeName, got, want)
		}
		if config := remainingOverride.GetRoutes()[1].GetTypedPerFilterConfig(); len(config) != 0 {
			t.Fatalf("%s ordinary override gained static endpoint state: %v", routeName, config)
		}
		fallback := routeConfig.GetVirtualHosts()[3]
		if got := fallback.GetDomains(); !slices.Equal(got, []string{"*"}) {
			t.Fatalf("%s fallback domains = %v", routeName, got)
		}
	}

	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })
	for _, listenerName := range []string{MainInternal, MainForward} {
		hcm := findHCM(t, listeners[listenerName])
		filterNames := httpFilterNames(hcm)
		stateIndex := slices.Index(filterNames, "agentio.static_endpoint_filter_state")
		dfpIndex := slices.Index(filterNames, "envoy.filters.http.dynamic_forward_proxy")
		if stateIndex < 0 || dfpIndex != stateIndex+1 {
			t.Fatalf("%s HTTP filters = %v, want static endpoint state immediately before DFP", listenerName, filterNames)
		}
		stateConfig := &setstatehttpv3.Config{}
		if err := hcm.GetHttpFilters()[stateIndex].GetTypedConfig().UnmarshalTo(stateConfig); err != nil {
			t.Fatalf("decode %s listener set-filter-state: %v", listenerName, err)
		}
		if got := len(stateConfig.GetOnRequestHeaders()); got != 0 {
			t.Fatalf("%s listener static state values = %d, want route-only configuration", listenerName, got)
		}
		dfpConfig := &dfphttpv3.FilterConfig{}
		if err := hcm.GetHttpFilters()[dfpIndex].GetTypedConfig().UnmarshalTo(dfpConfig); err != nil {
			t.Fatalf("decode %s DFP filter: %v", listenerName, err)
		}
		if !dfpConfig.GetAllowDynamicHostFromFilterState() {
			t.Fatalf("%s DFP filter does not allow route-selected static endpoints", listenerName)
		}
	}
}

func assertStaticEndpointState(t *testing.T, typedConfig map[string]*anypb.Any, wantAddress string) {
	t.Helper()
	value := typedConfig["agentio.static_endpoint_filter_state"]
	if value == nil {
		t.Fatal("static endpoint set-filter-state config not found")
	}
	config := &setstatehttpv3.Config{}
	if err := value.UnmarshalTo(config); err != nil {
		t.Fatalf("decode static endpoint set-filter-state: %v", err)
	}
	values := config.GetOnRequestHeaders()
	if got, want := len(values), 2; got != want {
		t.Fatalf("static endpoint state values = %d, want %d", got, want)
	}
	if got := values[0].GetObjectKey(); got != "envoy.upstream.dynamic_host" {
		t.Fatalf("static host state key = %q", got)
	}
	if got := values[0].GetFormatString().GetTextFormatSource().GetInlineString(); got != wantAddress {
		t.Fatalf("static host state value = %q, want %q", got, wantAddress)
	}
	if !values[0].GetReadOnly() {
		t.Fatal("static host state must be read-only")
	}
	if got := values[1].GetObjectKey(); got != "envoy.upstream.dynamic_port" {
		t.Fatalf("static port state key = %q", got)
	}
	if got, want := values[1].GetFormatString().GetTextFormatSource().GetInlineString(),
		"%FILTER_STATE(envoy.filters.listener.original_dst.local_ip:FIELD:port)%"; got != want {
		t.Fatalf("static port state value = %q, want %q", got, want)
	}
	if !values[1].GetReadOnly() || !values[1].GetSkipIfEmpty() {
		t.Fatal("static port state must be read-only and skip empty values")
	}
}

func TestRouteSettingsForStaticHostUsesEnvoyDomainPrecedence(t *testing.T) {
	settings := &configv1.ConnectionPoolHttpSettings{
		DefaultRoute: &configv1.HttpRouteSettings{Timeout: durationpb.New(time.Second)},
		RouteOverrides: []*configv1.HttpRouteOverride{
			{Hosts: []string{"*"}, Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(2 * time.Second)}},
			{Hosts: []string{"api.*"}, Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(3 * time.Second)}},
			{Hosts: []string{"*.com"}, Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(4 * time.Second)}},
			{Hosts: []string{"*.example.com"}, Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(5 * time.Second)}},
			{Hosts: []string{"api.example.com"}, Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(6 * time.Second)}},
		},
	}
	tests := []struct {
		host string
		want time.Duration
	}{
		{host: "unmatched.org", want: 2 * time.Second},
		{host: "api.other.org", want: 3 * time.Second},
		{host: "www.example.com", want: 5 * time.Second},
		{host: "API.EXAMPLE.COM", want: 6 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			got := routeSettingsForHost(settings, test.host).GetTimeout().AsDuration()
			if got != test.want {
				t.Fatalf("route settings timeout = %s, want %s", got, test.want)
			}
		})
	}
}

func TestBuildInstallsTelemetryOnForwardAndConnectTerminationPaths(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	resources, err := Build(Inputs{
		DiscoveryAddress:       "agentiod.agentio-system.svc:15012",
		TrustDomain:            "cluster.local",
		Gateway:                testGateway(nil),
		TelemetryRootNamespace: "agentio-system",
	})
	if err != nil {
		t.Fatal(err)
	}
	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })

	connect := findHCM(t, listeners[ConnectTerminate])
	if slices.Contains(httpFilterNames(connect), "istio.stats") {
		t.Fatalf("CONNECT Telemetry filters = %v", httpFilterNames(connect))
	}
	// CONNECT termination mirrors release-0.1 setHboneTerminationAccessLog: a
	// single access log restricted to status >= 400 responses.
	connectLogs := connect.GetAccessLog()
	if len(connectLogs) != 1 {
		t.Fatalf("CONNECT Telemetry logs = %d, want 1", len(connectLogs))
	}
	statusFilter := connectLogs[0].GetFilter().GetStatusCodeFilter()
	if statusFilter.GetComparison().GetOp() != accesslogv3.ComparisonFilter_GE ||
		statusFilter.GetComparison().GetValue().GetDefaultValue() != 400 {
		t.Fatalf("CONNECT Telemetry log filter = %v, want status >= 400", connectLogs[0].GetFilter())
	}
	for _, listenerName := range []string{MainInternal, MainForward} {
		hcm := findHCM(t, listeners[listenerName])
		filters := httpFilterNames(hcm)
		statsIndex := slices.Index(filters, "istio.stats")
		routerIndex := slices.Index(filters, "envoy.filters.http.router")
		wantRouterOffset := 1
		if listenerName == MainForward {
			identityIndex := slices.Index(filters, connectProxyTLSIdentityFilter)
			if identityIndex != statsIndex+1 {
				t.Fatalf("%s CONNECT TLS identity filter order = %v", listenerName, filters)
			}
			wantRouterOffset = 2
		}
		if statsIndex < 0 || statsIndex != routerIndex-wantRouterOffset || len(hcm.GetAccessLog()) != 1 {
			t.Fatalf("%s application HTTP Telemetry = filters %v logs %d", listenerName, filters, len(hcm.GetAccessLog()))
		}
	}

	for _, listenerName := range []string{MainInternal, MainForward} {
		chain := findFilterChain(t, listeners[listenerName], forwardTCPChain)
		filters := networkFilterNames(chain)
		statsIndex := slices.Index(filters, "istio.stats")
		proxyIndex := slices.Index(filters, "envoy.filters.network.tcp_proxy")
		if statsIndex < 0 || statsIndex != proxyIndex-1 {
			t.Fatalf("%s application TCP filters = %v", listenerName, filters)
		}
		proxy := new(tcpproxyv3.TcpProxy)
		if err := chain.Filters[proxyIndex].GetTypedConfig().UnmarshalTo(proxy); err != nil {
			t.Fatal(err)
		}
		if len(proxy.GetAccessLog()) != 1 {
			t.Fatalf("%s TCP access logs = %d", listenerName, len(proxy.GetAccessLog()))
		}
	}

	tlsRelay := findFilterChain(t, listeners[MainInternal], tlsTerminateChain)
	if slices.Contains(networkFilterNames(tlsRelay), "istio.stats") {
		t.Fatalf("TLS relay filters = %v", networkFilterNames(tlsRelay))
	}
	proxy := new(tcpproxyv3.TcpProxy)
	last := tlsRelay.Filters[len(tlsRelay.Filters)-1]
	if err := last.GetTypedConfig().UnmarshalTo(proxy); err != nil {
		t.Fatal(err)
	}
	if len(proxy.GetAccessLog()) != 0 {
		t.Fatalf("TLS relay access logs = %d", len(proxy.GetAccessLog()))
	}
}

func TestBuildInstallsNoRouteListenerAccessLogs(t *testing.T) {
	filter := "response.code >= 500"
	policy, err := model.NewTelemetry(model.TelemetryMetadata{
		Namespace: "agentio-system", Name: "listener-logs", Source: "agentio-system/source",
	}, []string{"agentio-system/egress"}, nil, nil, []model.TelemetryAccessLogging{{
		Mode: model.TelemetryModeServer, Providers: []string{"envoy"}, Filter: &filter,
	}})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := Build(Inputs{
		DiscoveryAddress:       "agentiod.agentio-system.svc:15012",
		TrustDomain:            "cluster.local",
		Gateway:                testGateway(nil),
		TelemetryRootNamespace: "agentio-system",
		Telemetry:              []model.Telemetry{policy},
	})
	if err != nil {
		t.Fatal(err)
	}
	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })
	for _, name := range []string{ConnectTerminate, MainInternal, MainForward} {
		logs := listeners[name].GetAccessLog()
		if len(logs) != 1 {
			t.Errorf("listener %s access logs = %d, want 1", name, len(logs))
			continue
		}
		filters := logs[0].GetFilter().GetAndFilter().GetFilters()
		if len(filters) != 2 || !slices.Equal(filters[0].GetResponseFlagFilter().GetFlags(), []string{"NR"}) {
			t.Errorf("listener %s access-log filter = %v, want NR AND CEL", name, logs[0].GetFilter())
			continue
		}
		extension := filters[1].GetExtensionFilter()
		celFilter := new(celv3.ExpressionFilter)
		if extension.GetName() != "envoy.access_loggers.extension_filters.cel" ||
			extension.GetTypedConfig().UnmarshalTo(celFilter) != nil || celFilter.GetExpression() != filter {
			t.Errorf("listener %s CEL filter = %v, want %q", name, extension, filter)
		}
	}
}

func TestBuildAppliesEnvoyFilterAfterTelemetry(t *testing.T) {
	emptyAny, err := anypb.New(&emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	patch, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "agentio-system", Name: "telemetry-patch", Source: "agentio-system/config-source",
	}, 0, []string{"agentio-system/egress"}, []model.EnvoyPatch{{
		Operation: model.PatchInsertBefore,
		Target: model.HTTPFilterPatch{
			Match: &model.ListenerMatch{Name: MainForward, FilterChain: &model.FilterChainMatch{
				Filter: &model.FilterMatch{Name: "envoy.filters.network.http_connection_manager", SubFilter: &model.SubFilterMatch{Name: "istio.stats"}},
			}},
			Value: &hcmv3.HttpFilter{Name: "example.before-stats", ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: emptyAny}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil), GatewayPatches: []model.GatewayPatch{patch}, TelemetryRootNamespace: "agentio-system",
	})
	if err != nil {
		t.Fatal(err)
	}
	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })
	filters := httpFilterNames(findHCM(t, listeners[MainForward]))
	if before, stats := slices.Index(filters, "example.before-stats"), slices.Index(filters, "istio.stats"); before < 0 || before+1 != stats {
		t.Fatalf("patched Telemetry filter order = %v", filters)
	}
}

func TestBuildClustersRejectsTelemetryNameCollision(t *testing.T) {
	_, err := buildClusters(effectiveConfig{
		gateway:   &configv1.EgressGateway{},
		telemetry: &telemetry.Output{Clusters: []*clusterv3.Cluster{{Name: MainForward}}},
	})
	if err == nil {
		t.Fatal("expected Telemetry cluster collision failure")
	}
}

func TestBuildAppliesGatewayEnvoyFilterTransactionally(t *testing.T) {
	emptyAny, err := anypb.New(&emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	filter, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "agentio-system", Name: "egress-patches", Source: "agentio-system/config-sources",
	}, 0, []string{"agentio-system/egress"}, []model.EnvoyPatch{
		{
			Operation: model.PatchMerge,
			Target: model.ClusterPatch{
				Match: &model.ClusterMatch{Name: MainForward},
				Value: &clusterv3.Cluster{AltStatName: "envoy-filter-patched"},
			},
		},
		{
			Operation: model.PatchInsertBefore,
			Target: model.HTTPFilterPatch{
				Match: &model.ListenerMatch{Name: MainForward, FilterChain: &model.FilterChainMatch{
					Filter: &model.FilterMatch{Name: "envoy.filters.network.http_connection_manager",
						SubFilter: &model.SubFilterMatch{Name: "envoy.filters.http.router"}},
				}},
				Value: &hcmv3.HttpFilter{Name: "envoy.filters.http.gateway-patch",
					ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: emptyAny}},
			},
		},
		{
			Operation: model.PatchAdd,
			Target: model.ExtensionConfigurationPatch{Value: &corev3.TypedExtensionConfig{
				Name: "gateway-extension", TypedConfig: emptyAny,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local", Gateway: testGateway(nil), GatewayPatches: []model.GatewayPatch{filter}})
	if err != nil {
		t.Fatal(err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	if got := clusters[MainForward].GetAltStatName(); got != "envoy-filter-patched" {
		t.Fatalf("patched cluster alt stat name = %q", got)
	}
	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })
	if filters := httpFilterNames(findHCM(t, listeners[MainForward])); !slices.Contains(filters, "envoy.filters.http.gateway-patch") {
		t.Fatalf("patched HTTP filters = %v", filters)
	}
	extensions := messagesOf(t, resources, model.ExtensionConfigurationType, func() *corev3.TypedExtensionConfig { return &corev3.TypedExtensionConfig{} })
	if extensions["gateway-extension"] == nil {
		t.Fatalf("extension resources = %+v", extensions)
	}
	for _, resource := range resources {
		if resource.XDSName == "gateway-extension" && resource.Facts.GatewayOwner != "agentio-system/egress" {
			t.Fatalf("extension facts = %+v", resource.Facts)
		}
	}
}

func TestBuildSupportsDeployedIPv4DynamicForwardProxyPatches(t *testing.T) {
	cache := &dfpcommonv3.DnsCacheConfig{Name: "agentio_dns_cache", DnsLookupFamily: clusterv3.Cluster_V4_ONLY}
	clusterTyped, err := anypb.New(&dfpclusterv3.ClusterConfig{
		ClusterImplementationSpecifier: &dfpclusterv3.ClusterConfig_DnsCacheConfig{DnsCacheConfig: cache},
	})
	if err != nil {
		t.Fatal(err)
	}
	httpTyped, err := anypb.New(&dfphttpv3.FilterConfig{
		ImplementationSpecifier: &dfphttpv3.FilterConfig_DnsCacheConfig{DnsCacheConfig: cache},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "agentio-system", Name: "egress-gateway-dfp-ipv4-only", Source: "agentio-system/config-source",
	}, 0, []string{"agentio-system/egress"}, []model.EnvoyPatch{
		{
			Operation: model.PatchMerge,
			Target: model.ClusterPatch{
				Match: &model.ClusterMatch{Name: TLSConnectOriginate},
				Value: &clusterv3.Cluster{ClusterDiscoveryType: &clusterv3.Cluster_ClusterType{
					ClusterType: &clusterv3.Cluster_CustomClusterType{
						Name: "envoy.clusters.dynamic_forward_proxy", TypedConfig: clusterTyped,
					},
				}},
			},
		},
		{
			Operation: model.PatchMerge,
			Target: model.HTTPFilterPatch{
				Match: &model.ListenerMatch{FilterChain: &model.FilterChainMatch{Filter: &model.FilterMatch{
					Name:      "envoy.filters.network.http_connection_manager",
					SubFilter: &model.SubFilterMatch{Name: "envoy.filters.http.dynamic_forward_proxy"},
				}}},
				Value: &hcmv3.HttpFilter{Name: "envoy.filters.http.dynamic_forward_proxy",
					ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: httpTyped}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local", Gateway: testGateway(nil), GatewayPatches: []model.GatewayPatch{policy}})
	if err != nil {
		t.Fatal(err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	gotCluster := &dfpclusterv3.ClusterConfig{}
	if err := clusters[TLSConnectOriginate].GetClusterType().GetTypedConfig().UnmarshalTo(gotCluster); err != nil {
		t.Fatal(err)
	}
	if got := gotCluster.GetDnsCacheConfig(); got.GetName() != "agentio_dns_cache" || got.GetDnsLookupFamily() != clusterv3.Cluster_V4_ONLY {
		t.Fatalf("cluster DNS cache = %+v", got)
	}

	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })
	manager := findHCM(t, listeners[MainForward])
	var dynamicForwardProxy *hcmv3.HttpFilter
	for _, filter := range manager.GetHttpFilters() {
		if filter.GetName() == "envoy.filters.http.dynamic_forward_proxy" {
			dynamicForwardProxy = filter
			break
		}
	}
	if dynamicForwardProxy == nil {
		t.Fatal("dynamic forward proxy HTTP filter not found")
	}
	gotHTTP := &dfphttpv3.FilterConfig{}
	if err := dynamicForwardProxy.GetTypedConfig().UnmarshalTo(gotHTTP); err != nil {
		t.Fatal(err)
	}
	if got := gotHTTP.GetDnsCacheConfig(); got.GetName() != "agentio_dns_cache" || got.GetDnsLookupFamily() != clusterv3.Cluster_V4_ONLY {
		t.Fatalf("HTTP DNS cache = %+v", got)
	}
}

func TestBuildSupportsDeployedSandboxConnectPatch(t *testing.T) {
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "agentio-system", Name: "enable-sandbox-connect", Source: "agentio-system/config-source",
	}, 0, []string{"agentio-system/egress"}, []model.EnvoyPatch{{
		Operation: model.PatchInsertBefore,
		Target: model.HTTPRoutePatch{
			Match: &model.RouteConfigurationMatch{
				Name:        HTTPDynamicForwardProxy,
				VirtualHost: &model.VirtualHostMatch{Route: &model.RouteMatch{Name: "default"}},
			},
			Value: &routev3.Route{
				Name: "sandbox-connect",
				Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_ConnectMatcher_{
					ConnectMatcher: &routev3.RouteMatch_ConnectMatcher{},
				}},
				Action: &routev3.Route_Route{Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: PassthroughCluster},
					Timeout:          durationpb.New(0),
					UpgradeConfigs: []*routev3.RouteAction_UpgradeConfig{{
						UpgradeType: "CONNECT", ConnectConfig: &routev3.RouteAction_UpgradeConfig_ConnectConfig{},
					}},
				}},
			},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}

	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local", Gateway: testGateway(nil), GatewayPatches: []model.GatewayPatch{policy}})
	if err != nil {
		t.Fatal(err)
	}
	routes := messagesOf(t, resources, model.RouteType, func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} })
	got := routes[HTTPDynamicForwardProxy].GetVirtualHosts()[0].GetRoutes()
	if len(got) != 3 || got[0].GetName() != "sandbox-connect" || got[1].GetName() != "sandbox-connect" || got[2].GetName() != "default" {
		t.Fatalf("HTTP DFP routes = %+v", got)
	}
	if got[1].GetMatch().GetConnectMatcher() == nil || got[1].GetRoute().GetCluster() != PassthroughCluster ||
		got[1].GetRoute().GetTimeout().AsDuration() != 0 || len(got[1].GetRoute().GetUpgradeConfigs()) != 1 ||
		got[1].GetRoute().GetUpgradeConfigs()[0].GetUpgradeType() != "CONNECT" ||
		got[1].GetRoute().GetUpgradeConfigs()[0].GetConnectConfig() == nil {
		t.Fatalf("deployed sandbox CONNECT route = %+v", got[1])
	}
}

// Application CONNECT is proxied to the original explicit proxy; it is not the
// HBONE CONNECT terminator.
func TestGatewayForwardProxyConnectSemantics(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local", Gateway: testGateway(nil)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	proxyTLS := clusters["tls_proxy_originate"]
	if proxyTLS == nil {
		t.Fatal("TLS proxy origination cluster not found")
	}
	if proxyTLS.GetType() != clusterv3.Cluster_ORIGINAL_DST || proxyTLS.GetLbPolicy() != clusterv3.Cluster_CLUSTER_PROVIDED {
		t.Fatalf("TLS proxy cluster type/lb = %v/%v, want ORIGINAL_DST/CLUSTER_PROVIDED", proxyTLS.GetType(), proxyTLS.GetLbPolicy())
	}
	protocol := &httpupstreamv3.HttpProtocolOptions{}
	if err := proxyTLS.GetTypedExtensionProtocolOptions()[httpProtocolOptionsType].UnmarshalTo(protocol); err != nil {
		t.Fatalf("decode TLS proxy HTTP options: %v", err)
	}
	if protocol.GetAutoConfig() == nil || protocol.GetUpstreamHttpProtocolOptions().GetAutoSni() ||
		protocol.GetUpstreamHttpProtocolOptions().GetAutoSanValidation() {
		t.Fatalf("TLS proxy HTTP options = %+v", protocol)
	}
	tlsContext := &tlsv3.UpstreamTlsContext{}
	if err := proxyTLS.GetTransportSocket().GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		t.Fatalf("decode TLS proxy transport socket: %v", err)
	}
	if tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename() != features.ResolveGatewayRootCAPath() {
		t.Fatalf("TLS proxy trusted CA = %+v", tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa())
	}

	routes := messagesOf(t, resources, model.RouteType, func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} })
	for routeName, clusterName := range map[string]string{
		HTTPDynamicForwardProxy: PassthroughCluster,
		TLSConnectOriginate:     "tls_proxy_originate",
	} {
		for _, virtualHost := range routes[routeName].GetVirtualHosts() {
			got := virtualHost.GetRoutes()
			if len(got) != 2 || got[0].GetName() != "sandbox-connect" || got[1].GetName() != "default" {
				t.Fatalf("route %s virtual host %s routes = %+v", routeName, virtualHost.GetName(), got)
			}
			connect := got[0]
			if connect.GetMatch().GetConnectMatcher() == nil || connect.GetRoute().GetCluster() != clusterName ||
				connect.GetRoute().GetTimeout().AsDuration() != 0 || len(connect.GetRoute().GetUpgradeConfigs()) != 1 ||
				connect.GetRoute().GetUpgradeConfigs()[0].GetUpgradeType() != "CONNECT" ||
				connect.GetRoute().GetUpgradeConfigs()[0].GetConnectConfig() != nil {
				t.Fatalf("route %s CONNECT = %+v", routeName, connect)
			}
		}
	}

	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })
	clearHCM := findHCM(t, listeners[MainInternal])
	tlsHCM := findHCM(t, listeners[MainForward])
	if !clearHCM.GetHttp2ProtocolOptions().GetAllowConnect() || !tlsHCM.GetHttp2ProtocolOptions().GetAllowConnect() {
		t.Fatal("both forward HCMs must allow HTTP/2 CONNECT")
	}
	if hasHTTPFilter(clearHCM, "connect-proxy-tls-identity") {
		t.Fatal("clear HTTP proxy gained TLS identity filter")
	}
	var identity *hcmv3.HttpFilter
	for _, filter := range tlsHCM.GetHttpFilters() {
		if filter.GetName() == "connect-proxy-tls-identity" {
			identity = filter
			break
		}
	}
	if identity == nil {
		t.Fatal("HTTPS proxy TLS identity filter not found")
	}
	wrapper := &extensionmatchingv3.ExtensionWithMatcher{}
	if err := identity.GetTypedConfig().UnmarshalTo(wrapper); err != nil {
		t.Fatalf("decode TLS identity wrapper: %v", err)
	}
	if err := wrapper.ValidateAll(); err != nil {
		t.Fatalf("validate TLS identity wrapper: %v", err)
	}
	matchers := wrapper.GetXdsMatcher().GetMatcherList().GetMatchers()
	if len(matchers) != 1 {
		t.Fatalf("TLS identity matcher count = %d", len(matchers))
	}
	notConnect := matchers[0].GetPredicate().GetNotMatcher().GetSinglePredicate()
	method := &matcherv3.HttpRequestHeaderMatchInput{}
	if notConnect == nil || notConnect.GetInput().GetTypedConfig().UnmarshalTo(method) != nil ||
		method.GetHeaderName() != ":method" || notConnect.GetValueMatch().GetExact() != "CONNECT" {
		t.Fatalf("TLS identity method matcher = %+v", notConnect)
	}
	setState := &setstatehttpv3.Config{}
	if err := wrapper.GetExtensionConfig().GetTypedConfig().UnmarshalTo(setState); err != nil {
		t.Fatalf("decode TLS identity set-filter-state: %v", err)
	}
	values := setState.GetOnRequestHeaders()
	if len(values) != 2 || values[0].GetObjectKey() != "envoy.network.upstream_server_name" ||
		values[1].GetObjectKey() != "envoy.network.upstream_subject_alt_names" {
		t.Fatalf("TLS identity values = %+v", values)
	}
}

func TestSNIHostMismatchConditionUsesProxyAuthorityForConnect(t *testing.T) {
	environment, err := cel.NewEnv(
		cel.Variable("request", cel.DynType),
		cel.Variable("filter_state", cel.MapType(cel.StringType, cel.BytesType)),
		ext.Strings(),
	)
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := environment.Compile(sniHostMismatchExprText)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("compile SNI mismatch expression: %v", issues.Err())
	}
	program, err := environment.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, method, host string
		want               bool
	}{
		{name: "ordinary mismatch denied", method: "GET", host: "target.example:443", want: true},
		{name: "CONNECT target differs from proxy SNI", method: "CONNECT", host: "target.example:443", want: false},
		{name: "ordinary match allowed", method: "GET", host: "proxy.example:8443", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, _, err := program.Eval(map[string]any{
				"request":      map[string]any{"method": test.method, "host": test.host},
				"filter_state": map[string][]byte{outerSNIKey: []byte("proxy.example")},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := result.Value().(bool); !ok || got != test.want {
				t.Fatalf("condition = %v (%T), want %v", result.Value(), result.Value(), test.want)
			}
		})
	}
}

func TestGatewayExtProcOverridesGlobalFallback(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway: testGateway(&configv1.EgressGateway{
			ExtProc: &configv1.ExtProcProvider{
				Service: "gateway-ext-proc.agentio-system.svc",
				Port:    9003,
			},
		}),
		GlobalExtProc: &configv1.ExtProcProvider{
			Service: "global-ext-proc.agentio-system.svc",
			Port:    9002,
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	cluster := messagesOf(t, resources, model.ClusterType,
		func() *clusterv3.Cluster { return &clusterv3.Cluster{} })[ExtProcCluster]
	socket := cluster.GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()[0].
		GetEndpoint().GetAddress().GetSocketAddress()
	if socket.GetAddress() != "gateway-ext-proc.agentio-system.svc" || socket.GetPortValue() != 9003 {
		t.Fatalf("gateway ext_proc endpoint = %s:%d", socket.GetAddress(), socket.GetPortValue())
	}
}

func TestBuildRejectsConflictingGateway(t *testing.T) {
	gateway := testGateway(nil)
	gateway.Source = model.GatewaySourceConflict
	_, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local", Gateway: gateway})
	if err == nil || err.Error() != "gateway agentio-system/egress has conflicting declarations" {
		t.Fatalf("Build() error = %v", err)
	}
}

func TestBuildWithoutSNITrafficPolicyUsesProtocolMatcher(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
		GlobalExtProc: &configv1.ExtProcProvider{
			Service: "ext-proc.agentio-system.svc.cluster.local",
			Port:    9002,
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })
	internal := listeners[MainInternal]
	gotChains := make([]string, 0, len(internal.GetFilterChains()))
	for _, chain := range internal.GetFilterChains() {
		gotChains = append(gotChains, chain.GetName())
	}
	if want := []string{forwardHTTPChain, forwardTCPChain}; !equalStrings(gotChains, want) {
		t.Fatalf("MainInternal filter chains = %v, want %v without SNI policy runtime", gotChains, want)
	}
	tls := internal.GetFilterChainMatcher().GetMatcherTree().GetExactMatchMap().GetMap()["tls"]
	if got := tls.GetAction().GetName(); got != forwardTCPChain {
		t.Fatalf("TLS fallback chain = %q, want %q without SNI policy runtime", got, forwardTCPChain)
	}
}

func TestBuildStaticSNIMatcherOmitsEmptyHostGroups(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway: testGateway(&configv1.EgressGateway{
			TlsTermination: &configv1.TlsTerminationConfig{
				IncludeHosts: []string{"*.example.com"},
			},
		}),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })
	domains := &xdsmatcherv3.ServerNameMatcher{}
	if err := listeners[MainInternal].GetFilterChainMatcher().GetMatcherTree().GetCustomMatch().GetTypedConfig().UnmarshalTo(domains); err != nil {
		t.Fatalf("unmarshal static SNI matcher: %v", err)
	}
	for _, domain := range domains.GetDomainMatchers() {
		if len(domain.GetDomains()) == 0 {
			t.Fatalf("static SNI matcher contains an empty domain group: %+v", domains)
		}
	}
}

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

func TestBuildRejectsRelativeGatewayRootCAPath(t *testing.T) {
	test.SetForTest(t, &features.GatewayRootCAPath, "certs/root.pem")
	_, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
	})
	if err == nil || err.Error() != "gateway root CA path must be absolute" {
		t.Fatalf("Build() error = %v, want gateway root CA path must be absolute", err)
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

func TestGatewayListenersUseSupportedAgentioSemantics(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })

	for _, name := range []string{MainInternal, MainForward} {
		listener := listeners[name]
		if listener.GetListenerFiltersTimeout() != nil || listener.GetContinueOnListenerFiltersTimeout() {
			t.Errorf("listener %s does not use Envoy's fail-closed listener-filter defaults", name)
		}
	}
	for name, want := range map[string][]string{
		MainInternal: {"envoy.filters.listener.original_dst", "envoy.filters.listener.http_inspector", "envoy.filters.listener.tls_inspector"},
		MainForward:  {"envoy.filters.listener.original_dst", "envoy.filters.listener.tls_inspector", "envoy.filters.listener.http_inspector"},
	} {
		listener := listeners[name]
		got := make([]string, 0, len(listener.GetListenerFilters()))
		for _, filter := range listener.GetListenerFilters() {
			got = append(got, filter.GetName())
			if filter.GetName() == "envoy.filters.listener.tls_inspector" {
				config := &tlsinspectorv3.TlsInspector{}
				if err := filter.GetTypedConfig().UnmarshalTo(config); err != nil {
					t.Fatalf("unmarshal %s TLS inspector: %v", name, err)
				}
				if config.GetInitialReadBufferSize().GetValue() != 16*1024 {
					t.Errorf("listener %s TLS inspector initial read buffer = %d, want 16384", name, config.GetInitialReadBufferSize().GetValue())
				}
			}
		}
		if !equalStrings(got, want) {
			t.Errorf("listener %s filters = %v, want %v", name, got, want)
		}
	}

	tlsChain := findFilterChain(t, listeners[MainInternal], tlsTerminateChain)
	if got := tlsChain.GetTransportSocketConnectTimeout().AsDuration(); got != 15*time.Second {
		t.Errorf("TLS termination transport-socket connect timeout = %s, want 15s", got)
	}

	connectHCM := findHCM(t, listeners[ConnectTerminate])
	keepalive := connectHCM.GetHttp2ProtocolOptions().GetConnectionKeepalive()
	if got := keepalive.GetInterval().AsDuration(); got != 10*time.Second {
		t.Errorf("CONNECT keepalive interval = %s, want 10s", got)
	}
	if got := keepalive.GetTimeout().AsDuration(); got != 20*time.Second {
		t.Errorf("CONNECT keepalive timeout = %s, want 20s", got)
	}
	if connectHCM.GetForwardClientCertDetails() != hcmv3.HttpConnectionManager_SANITIZE || connectHCM.GetSetCurrentClientCertDetails() != nil {
		t.Error("CONNECT must not propagate caller-controlled XFCC state")
	}

	for _, name := range []string{MainInternal, MainForward} {
		hcm := findHCM(t, listeners[name])
		if hcm.GetServerName() != "istio-envoy" || !hcm.Proxy_100Continue {
			t.Errorf("listener %s HCM server_name/proxy_100_continue = %q/%v", name, hcm.GetServerName(), hcm.Proxy_100Continue)
		}
		if len(hcm.GetUpgradeConfigs()) != 1 || hcm.GetUpgradeConfigs()[0].GetUpgradeType() != "websocket" {
			t.Errorf("listener %s HCM websocket upgrades = %+v", name, hcm.GetUpgradeConfigs())
		}
	}
}

func TestGatewayRoutesUseSupportedAgentioRetries(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway: testGateway(&configv1.EgressGateway{
			ConnectionPool: &configv1.ConnectionPoolSettings{Http: &configv1.ConnectionPoolHttpSettings{
				DefaultRoute: &configv1.HttpRouteSettings{Timeout: durationpb.New(12 * time.Second)},
				RouteOverrides: []*configv1.HttpRouteOverride{{Hosts: []string{"api.example.com"}, Settings: &configv1.HttpRouteSettings{
					Retries: &networkingv1alpha3.HTTPRetry{Attempts: 3, RetryOn: "connect-failure,refused-stream"},
				}}},
			}},
		}),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	routes := messagesOf(t, resources, model.RouteType, func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} })
	for _, name := range []string{HTTPDynamicForwardProxy, TLSConnectOriginate} {
		config := routes[name]
		configured := config.GetVirtualHosts()[0].GetRoutes()[1]
		retry := configured.GetRoute().GetRetryPolicy()
		if retry.GetHostSelectionRetryMaxAttempts() != 5 || len(retry.GetRetryHostPredicate()) != 1 ||
			retry.GetRetryHostPredicate()[0].GetName() != "envoy.retry_host_predicates.previous_hosts" {
			t.Errorf("route %s configured retry host selection = %+v", name, retry)
		}
		fallback := config.GetVirtualHosts()[1].GetRoutes()[1]
		if retry := fallback.GetRoute().GetRetryPolicy(); retry.GetRetryOn() != "reset-before-request" || retry.GetNumRetries().GetValue() != 2 {
			t.Errorf("route %s default retry = %+v", name, retry)
		}
	}
}

func TestForwardRouteConvertsSupportedAgentioRetryFields(t *testing.T) {
	tests := []struct {
		name              string
		retries           *networkingv1alpha3.HTTPRetry
		wantNil           bool
		wantRetryOn       string
		wantCodes         []uint32
		wantPreviousHosts bool
		wantRemote        bool
	}{
		{
			name: "numeric status and spaces",
			retries: &networkingv1alpha3.HTTPRetry{Attempts: 2,
				RetryOn: " 5xx, 404, , 503,connect-failure "},
			wantRetryOn: "5xx,connect-failure,retriable-status-codes", wantCodes: []uint32{404, 503}, wantPreviousHosts: true,
		},
		{
			name: "remote localities", retries: &networkingv1alpha3.HTTPRetry{Attempts: 2, RetryRemoteLocalities: wrapperspb.Bool(true)},
			wantRetryOn: "connect-failure,refused-stream,unavailable,cancelled,retriable-status-codes", wantPreviousHosts: true, wantRemote: true,
		},
		{name: "attempts disabled", retries: &networkingv1alpha3.HTTPRetry{Attempts: 0}, wantNil: true},
		{
			name: "ignore previous hosts enabled", retries: &networkingv1alpha3.HTTPRetry{Attempts: 2, RetryIgnorePreviousHosts: wrapperspb.Bool(true)},
			wantRetryOn: "connect-failure,refused-stream,unavailable,cancelled,retriable-status-codes", wantPreviousHosts: true,
		},
		{
			name: "ignore previous hosts disabled", retries: &networkingv1alpha3.HTTPRetry{Attempts: 2, RetryIgnorePreviousHosts: wrapperspb.Bool(false)},
			wantRetryOn: "connect-failure,refused-stream,unavailable,cancelled,retriable-status-codes",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := forwardRoute("test", &configv1.HttpRouteSettings{Retries: test.retries}).GetRoute().GetRetryPolicy()
			if test.wantNil {
				if policy != nil {
					t.Fatalf("retry policy = %+v, want nil", policy)
				}
				return
			}
			if policy.GetRetryOn() != test.wantRetryOn || !slices.Equal(policy.GetRetriableStatusCodes(), test.wantCodes) {
				t.Errorf("retry-on/codes = %q/%v, want %q/%v", policy.GetRetryOn(), policy.GetRetriableStatusCodes(), test.wantRetryOn, test.wantCodes)
			}
			if got := len(policy.GetRetryHostPredicate()) == 1; got != test.wantPreviousHosts {
				t.Errorf("previous-host predicate = %v, want %v", got, test.wantPreviousHosts)
			}
			if test.wantRemote {
				config := &previousprioritiesv3.PreviousPrioritiesConfig{}
				if policy.GetRetryPriority().GetName() != "envoy.retry_priorities.previous_priorities" {
					t.Fatalf("retry priority = %+v", policy.GetRetryPriority())
				}
				if err := policy.GetRetryPriority().GetTypedConfig().UnmarshalTo(config); err != nil {
					t.Fatalf("decode retry priority: %v", err)
				}
				if config.GetUpdateFrequency() != 2 {
					t.Errorf("retry priority update frequency = %d, want 2", config.GetUpdateFrequency())
				}
			} else if policy.GetRetryPriority() != nil {
				t.Errorf("retry priority = %+v, want nil", policy.GetRetryPriority())
			}
		})
	}
}

func messagesOf[T proto.Message](t *testing.T, resources []model.Resource, typeURL string, newMessage func() T) map[string]T {
	t.Helper()
	result := map[string]T{}
	for _, resource := range resources {
		if resource.Key.TypeURL != typeURL {
			continue
		}
		message := newMessage()
		if err := resource.Value.UnmarshalTo(message); err != nil {
			t.Fatalf("unmarshal %s: %v", resource.Key.Name, err)
		}
		result[resource.XDSName] = message
	}
	return result
}

func findHCM(t *testing.T, listener *listenerv3.Listener) *hcmv3.HttpConnectionManager {
	t.Helper()
	for _, chain := range listener.GetFilterChains() {
		for _, filter := range chain.GetFilters() {
			if filter.GetName() != "envoy.filters.network.http_connection_manager" {
				continue
			}
			cfg := &hcmv3.HttpConnectionManager{}
			if err := filter.GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatalf("unmarshal HCM: %v", err)
			}
			return cfg
		}
	}
	t.Fatal("HCM not found")
	return nil
}

func findFilterChain(t *testing.T, listener *listenerv3.Listener, name string) *listenerv3.FilterChain {
	t.Helper()
	for _, chain := range listener.GetFilterChains() {
		if chain.GetName() == name {
			return chain
		}
	}
	t.Fatalf("filter chain %q not found", name)
	return nil
}

func networkFilterNames(chain *listenerv3.FilterChain) []string {
	result := make([]string, 0, len(chain.GetFilters()))
	for _, filter := range chain.GetFilters() {
		result = append(result, filter.GetName())
	}
	return result
}

func hasHTTPFilter(hcm *hcmv3.HttpConnectionManager, name string) bool {
	for _, filter := range hcm.GetHttpFilters() {
		if filter.GetName() == name {
			return true
		}
	}
	return false
}

func httpFilterNames(hcm *hcmv3.HttpConnectionManager) []string {
	result := make([]string, 0, len(hcm.GetHttpFilters()))
	for _, filter := range hcm.GetHttpFilters() {
		result = append(result, filter.GetName())
	}
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
