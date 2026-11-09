// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0
package networking

import (
	"testing"

	xdsmatcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	common "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	state "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	networkstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	snidfpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
	tcpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	inputv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"

	"github.com/openkruise/agentio/pkg/model"
)

func tcpAllowedChain(t *testing.T, match *xdsmatcherv3.Matcher_OnMatch) string {
	t.Helper()
	if match.GetAction() != nil {
		return match.GetAction().GetName()
	}
	gate := match.GetMatcher()
	input := new(inputv3.FilterStateInput)
	if err := gate.GetMatcherTree().GetInput().GetTypedConfig().UnmarshalTo(input); err != nil {
		t.Fatal(err)
	}
	if input.Key != model.FilterStateTCPDecision {
		t.Fatalf("unexpected TCP decision input: %s", input.Key)
	}
	values := gate.GetMatcherTree().GetExactMatchMap().GetMap()
	if len(values) != 1 || gate.GetOnNoMatch().GetAction().GetName() != tcpDenyChain {
		t.Fatal("missing, invalid and deny decisions must close before dialing")
	}
	return values["allow"].GetAction().GetName()
}

func TestTCPDecisionAndExplicitSNIPassthrough(t *testing.T) {
	resources := buildCompleteGatewayGraph(t)
	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	for _, name := range []string{MainInternal, MainForward} {
		for _, chain := range listeners[name].FilterChains {
			if chain.Name == tlsTerminateChain {
				for _, filter := range chain.Filters {
					if filter.Name == "agentio.local_tcp_decision" {
						t.Fatal("TLS termination must preserve the decision for MainForward")
					}
				}
				continue
			}
			if chain.Name != forwardHTTPChain && chain.Name != forwardTCPChain && chain.Name != tlsPassthroughChain {
				continue
			}
			filter := chain.Filters[len(chain.Filters)-2]
			cfg := new(networkstate.Config)
			if err := filter.GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatal(err)
			}
			values := cfg.GetOnNewConnection()
			if len(values) != 1 || values[0].GetObjectKey() != model.FilterStateTCPDecision ||
				values[0].GetFactoryKey() != "envoy.string" ||
				values[0].GetSharedWithUpstream() != common.FilterStateValue_NONE {
				t.Fatalf("%s/%s must stop sharing the consumed decision", name, chain.Name)
			}
		}
		chain := findFilterChain(t, listeners[name], tcpDenyChain)
		proxy := new(tcpv3.TcpProxy)
		if err := chain.Filters[len(chain.Filters)-1].GetTypedConfig().UnmarshalTo(proxy); err != nil {
			t.Fatal(err)
		}
		if proxy.GetCluster() != BlackHoleCluster {
			t.Fatal("TCP deny must not dial the original destination")
		}
	}
	chain := findFilterChain(t, listeners[MainInternal], tlsPassthroughChain)
	if len(chain.Filters) != 4 {
		t.Fatal(chain)
	}
	dfp := new(snidfpv3.FilterConfig)
	if err := chain.Filters[1].GetTypedConfig().UnmarshalTo(dfp); err != nil {
		t.Fatal(err)
	}
	if dfp.DnsCacheConfig == nil {
		t.Fatal("explicit domain allow must resolve SNI")
	}
	proxy := new(tcpv3.TcpProxy)
	if err := chain.Filters[len(chain.Filters)-1].GetTypedConfig().UnmarshalTo(proxy); err != nil {
		t.Fatal(err)
	}
	if proxy.GetCluster() != HTTPDynamicForwardProxy {
		t.Fatal("passthrough must route encrypted bytes to the SNI destination without originating another TLS layer")
	}
	cfg := new(state.Config)
	if err := connectTCPDecisionFilter().GetTypedConfig().UnmarshalTo(cfg); err != nil {
		t.Fatal(err)
	}
	values := cfg.GetOnRequestHeaders()
	if len(values) != 1 || values[0].GetObjectKey() != model.FilterStateTCPDecision || !values[0].ReadOnly ||
		values[0].SharedWithUpstream != common.FilterStateValue_TRANSITIVE {
		t.Fatal("decision must reach both internal listener hops before it stops sharing")
	}
	if got := values[0].GetFormatString().
		GetTextFormatSource().
		GetInlineString(); got != "%DYNAMIC_METADATA(agentio:tcp:original_destination_decision)%" {
		t.Fatalf("decision must come from Porter: %s", got)
	}
}
