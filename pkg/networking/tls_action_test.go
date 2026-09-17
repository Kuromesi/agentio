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

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	setstatecommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	matchinginputv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	"istio.io/istio/pkg/test"

	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func connectAuthorityStates(t *testing.T, listener *listenerv3.Listener) map[string]*setstatecommonv3.FilterStateValue {
	t.Helper()
	states := map[string]*setstatecommonv3.FilterStateValue{}
	for _, filter := range findHCM(t, listener).GetHttpFilters() {
		if filter.GetName() != "connect_authority" {
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

func TestTLSActionHeaderSelectsChainBeforeGatewayPolicy(t *testing.T) {
	listeners := messagesOf(
		t,
		buildCompleteGatewayGraph(t),
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	state := connectAuthorityStates(t, listeners[ConnectTerminate])[tlsActionKey]
	if state.GetFactoryKey() != "istio.hashable_string" || !state.GetReadOnly() || !state.GetSkipIfEmpty() ||
		state.GetSharedWithUpstream() != setstatecommonv3.FilterStateValue_ONCE ||
		state.GetFormatString().GetTextFormatSource().GetInlineString() != "%REQ(X-AGENTIO-SNI-ACTION)%" {
		t.Fatalf("CONNECT state %s = %v", tlsActionKey, state)
	}

	root := listeners[MainInternal].GetFilterChainMatcher()
	action := root.GetMatcherTree().GetExactMatchMap().GetMap()["tls"].GetMatcher()
	input := &matchinginputv3.FilterStateInput{}
	if err := action.GetMatcherTree().GetInput().GetTypedConfig().UnmarshalTo(input); err != nil {
		t.Fatal(err)
	}
	if input.GetKey() != tlsActionKey {
		t.Fatalf("TLS decision input = %q, want the ztunnel action", input.GetKey())
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
		t.Fatal("connections without a ztunnel action must fall back to gateway policy")
	}
}

func TestTLSActionIgnoredWithoutSNITrafficPolicy(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, false)
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	if _, found := connectAuthorityStates(t, listeners[ConnectTerminate])[tlsActionKey]; found {
		t.Fatalf("CONNECT captures %s with SNI policy disabled", tlsActionKey)
	}
}
