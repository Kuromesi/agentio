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

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"

	xdsmatcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	setstatecommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	matchinginputv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func connectAuthorityStates(t *testing.T, listener *listenerv3.Listener) map[string]*setstatecommonv3.FilterStateValue {
	t.Helper()
	states := map[string]*setstatecommonv3.FilterStateValue{}
	for _, filter := range findHCM(t, listener).GetHttpFilters() {
		if filter.GetName() != "connect_authority" && filter.GetName() != "connect_tls_action" {
			continue
		}
		config := &setstatehttpv3.Config{}
		if err := filter.GetTypedConfig().UnmarshalTo(config); err != nil {
			t.Fatal(err)
		}
		for _, state := range config.GetOnRequestHeaders() {
			states[state.GetObjectKey()] = state
		}
	}
	return states
}

func TestTLSActionMetadataSelectsChainBeforeGatewayPolicy(t *testing.T) {
	listeners := messagesOf(
		t,
		buildCompleteGatewayGraph(t),
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	state := connectAuthorityStates(t, listeners[ConnectTerminate])[tlsActionKey]
	if state.GetFactoryKey() != "istio.hashable_string" || !state.GetReadOnly() || !state.GetSkipIfEmpty() ||
		state.GetSharedWithUpstream() != setstatecommonv3.FilterStateValue_ONCE ||
		state.GetFormatString().GetTextFormatSource().GetInlineString() != tlsActionMetadataFormat {
		t.Fatalf("CONNECT state %s = %v", tlsActionKey, state)
	}

	root := listeners[MainInternal].GetFilterChainMatcher()
	exclusions := root.GetMatcherTree().GetExactMatchMap().GetMap()["tls"].GetMatcher()
	domains := &xdsmatcherv3.ServerNameMatcher{}
	if err := exclusions.GetMatcherTree().GetCustomMatch().GetTypedConfig().UnmarshalTo(domains); err != nil {
		t.Fatalf("gateway exclusions must precede the CONNECT action: %v", err)
	}
	if len(domains.GetDomainMatchers()) == 0 {
		t.Fatal("expected gateway exclusions before the CONNECT action")
	}
	for _, match := range domains.GetDomainMatchers() {
		if got := match.GetOnMatch().GetAction().GetName(); got != forwardTCPChain {
			t.Fatalf("excluded SNI selects %q, want passthrough regardless of CONNECT action", got)
		}
	}
	action := exclusions.GetOnNoMatch().GetMatcher()
	input := &matchinginputv3.FilterStateInput{}
	if err := action.GetMatcherTree().GetInput().GetTypedConfig().UnmarshalTo(input); err != nil {
		t.Fatal(err)
	}
	if input.GetKey() != tlsActionKey {
		t.Fatalf("TLS decision input = %q, want the CONNECT action", input.GetKey())
	}
	actions := action.GetMatcherTree().GetExactMatchMap().GetMap()
	for value, chain := range map[string]string{"terminate": tlsTerminateChain, "passthrough": forwardTCPChain, "deny": sniDenyChain} {
		if got := actions[value].GetAction().GetName(); got != chain {
			t.Errorf("action %q selects %q, want %q", value, got, chain)
		}
	}
	if len(actions) != 3 {
		t.Errorf("unexpected actions: %v", actions)
	}
	if action.GetOnNoMatch().GetMatcher() == nil {
		t.Fatal("connections without a CONNECT action must fall back to gateway policy")
	}
}

func TestTLSActionWithoutGatewayExclusions(t *testing.T) {
	b := &resourceBuilder{}
	matcher := b.sniTrafficPolicyMatcher(nil)
	input := &matchinginputv3.FilterStateInput{}
	if err := matcher.GetMatcherTree().GetInput().GetTypedConfig().UnmarshalTo(input); err != nil {
		t.Fatal(err)
	}
	if input.GetKey() != tlsActionKey || matcher.GetOnNoMatch().GetMatcher() == nil {
		t.Fatal("without exclusions, consult CONNECT action with gateway policy fallback")
	}
}

func TestConnectExtProcEnablement(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, sni := range []bool{false, true} {
			for _, provider := range []*configv1.ExtProcProvider{nil, {Service: "custom.demo.svc", Port: 9002, FailureModeAllow: true}} {
				test.SetForTest(t, &features.EnablePorter, enabled)
				test.SetForTest(t, &features.EnableSNITrafficPolicy, sni)
				resources, err := Build(
					Inputs{
						DiscoveryAddress: "agentiod.agentio-system.svc:15012",
						TrustDomain:      "cluster.local",
						Gateway:          testGateway(nil),
						GlobalExtProc:    provider,
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
				connect := findHCM(t, listeners[ConnectTerminate])
				if got := hasHTTPFilter(connect, "envoy.filters.http.ext_proc"); got != enabled {
					t.Fatalf("CONNECT present=%v, enabled=%v, HTTP provider=%v", got, enabled, provider)
				}
				if got := hasHTTPFilter(connect, "connect_tls_action"); got != (enabled && sni) {
					t.Fatalf("TLS capture=%v", got)
				}
				if got := hasHTTPFilter(
					findHCM(t, listeners[MainInternal]),
					"envoy.filters.http.ext_proc",
				); got != (provider != nil) {
					t.Fatalf("HTTP provider affected by CONNECT setting: %v", got)
				}
			}
		}
	}
}

func TestConnectExtProcConfiguration(t *testing.T) {
	listeners := messagesOf(
		t,
		buildCompleteGatewayGraph(t),
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	hcm := findHCM(t, listeners[ConnectTerminate])
	names := httpFilterNames(hcm)
	authority := slices.Index(names, "connect_authority")
	ext := slices.Index(names, "envoy.filters.http.ext_proc")
	action := slices.Index(names, "connect_tls_action")
	if authority < 0 || ext <= authority || action != ext+1 || action >= len(names)-1 {
		t.Fatalf("incorrect CONNECT filter order: %v", names)
	}
	cfg := &extprocv3.ExternalProcessor{}
	if err := hcm.HttpFilters[ext].GetTypedConfig().UnmarshalTo(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ValidateAll(); err != nil {
		t.Fatal(err)
	}
	md := cfg.GetGrpcService().GetInitialMetadata()
	if len(md) != 0 || cfg.GetGrpcService().GetEnvoyGrpc().GetClusterName() != PorterCluster {
		t.Fatalf("CONNECT must use its own endpoint without a phase marker: %v", md)
	}
	mode := cfg.GetProcessingMode()
	if mode.GetRequestHeaderMode() != extprocv3.ProcessingMode_SEND ||
		mode.GetResponseHeaderMode() != extprocv3.ProcessingMode_SKIP ||
		mode.GetRequestBodyMode() != extprocv3.ProcessingMode_NONE ||
		mode.GetResponseBodyMode() != extprocv3.ProcessingMode_NONE ||
		mode.GetRequestTrailerMode() != extprocv3.ProcessingMode_SKIP ||
		mode.GetResponseTrailerMode() != extprocv3.ProcessingMode_SKIP || cfg.GetAllowModeOverride() {
		t.Fatalf("tunnel must only process request headers: %v", cfg)
	}
	if cfg.GetMessageTimeout().AsDuration() != 5*time.Second {
		t.Fatalf("tunnel timeout = %v", cfg.GetMessageTimeout())
	}
	if !slices.Equal(cfg.GetMetadataOptions().GetReceivingNamespaces().GetUntyped(), []string{"agentio"}) {
		t.Fatal("CONNECT metadata not accepted")
	}
	for _, attr := range []string{"filter_state['agentio.workload.name']", "filter_state['agentio.workload.namespace']", "filter_state['sandbox.id']"} {
		if !slices.Contains(cfg.GetRequestAttributes(), attr) {
			t.Fatalf("missing identity attribute %s", attr)
		}
	}
}

func TestConnectExtProcFailsClosed(t *testing.T) {
	b := &resourceBuilder{}
	cfg := &extprocv3.ExternalProcessor{}
	if err := b.connectExtProcFilter().GetTypedConfig().UnmarshalTo(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.GetFailureModeAllow() {
		t.Fatal("CONNECT must fail closed independently of HTTP provider settings")
	}
}
