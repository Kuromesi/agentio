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

package policy

import (
	"net/netip"
	"testing"

	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
)

func TestCompileEgressPoliciesResolvesHostsAndFailsClosed(t *testing.T) {
	config := &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{
		{Namespaces: []string{"demo"}, MatchHosts: []string{"api.example.com"}, Policy: extensionsv1.EgressPolicyAction_DENY},
		{MatchHosts: []string{"missing.example.com"}, Policy: extensionsv1.EgressPolicyAction_DENY},
	}}
	original := proto.Clone(config).(*configv1.AgentioConfig)
	compiled, err := CompileEgressPolicies(krt.TestingDummyContext{}, config, func(_ krt.HandlerContext, host string) []netip.Addr {
		if host == "api.example.com" {
			return []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7")}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("CompileEgressPolicies: %v", err)
	}
	if got := compiled.GetEgressPolicies()[0].GetMatchCidrs(); len(got) != 2 || got[0] != "203.0.113.7/32" || got[1] != "2001:db8::7/128" {
		t.Fatalf("resolved CIDRs = %v", got)
	}
	if got := compiled.GetEgressPolicies()[1].GetMatchCidrs(); len(got) != 1 || got[0] != "192.0.0.8/32" {
		t.Fatalf("failed resolution CIDRs = %v", got)
	}
	for _, value := range compiled.GetEgressPolicies() {
		if len(value.GetMatchHosts()) != 0 {
			t.Fatalf("uncompiled hostnames = %v", value.GetMatchHosts())
		}
	}
	if !proto.Equal(config, original) {
		t.Fatal("source config was mutated")
	}
}

func TestCompileEgressPoliciesRejectsInvalidGateway(t *testing.T) {
	_, err := CompileEgressPolicies(krt.TestingDummyContext{}, &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{{
		Policy: extensionsv1.EgressPolicyAction_GATEWAY,
	}}}, nil)
	if err == nil {
		t.Fatal("invalid gateway policy accepted")
	}
}

func TestCompileEgressPoliciesPreservesAgentioImplicitGatewayPort(t *testing.T) {
	compiled, err := CompileEgressPolicies(krt.TestingDummyContext{}, &configv1.AgentioConfig{
		EgressPolicies: []*extensionsv1.EgressPolicy{{
			Policy: extensionsv1.EgressPolicyAction_GATEWAY,
			Gateway: &extensionsv1.GatewayAddress{
				Service: "egress-gateway.agentio-system.svc.cluster.local",
			},
		}},
	}, nil)
	if err != nil {
		t.Fatalf("CompileEgressPolicies: %v", err)
	}
	gateway := compiled.GetEgressPolicies()[0].GetGateway()
	if gateway.GetService() != "egress-gateway.agentio-system.svc.cluster.local" || gateway.GetPort() != 0 {
		t.Fatalf("compiled gateway = %+v, want Agentio service with implicit port", gateway)
	}
}
