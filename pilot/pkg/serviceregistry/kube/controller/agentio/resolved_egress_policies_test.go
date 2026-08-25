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
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/retry"
)

func TestResolveEgressPolicies(t *testing.T) {
	source := []*extensions.EgressPolicy{
		{
			Namespaces: []string{"team-a"},
			MatchCidrs: []string{"10.0.0.0/8"},
			MatchHosts: []string{"one.example.com", "missing.example.com"},
			MatchPorts: []string{"443"},
			Policy:     extensions.EgressPolicyAction_GATEWAY,
			Gateway:    &extensions.GatewayAddress{Service: "egress.team-a.svc.cluster.local", Port: 15008},
		},
		{
			MatchHosts: []string{"missing.example.com"},
			Policy:     extensions.EgressPolicyAction_DENY,
		},
		{
			MatchCidrs: []string{"192.168.0.0/16"},
			MatchHosts: []string{"missing.example.com"},
			Policy:     extensions.EgressPolicyAction_PASSTHROUGH,
		},
		{
			MatchCidrs: []string{"172.16.0.0/12"},
			Policy:     extensions.EgressPolicyAction_DENY,
		},
	}
	original := proto.Clone(&extensions.EgressPolicies{EgressPolicies: source}).(*extensions.EgressPolicies)

	got := resolveEgressPolicies(krt.TestingDummyContext{}, source, func(_ krt.HandlerContext, hostname string) []string {
		if hostname == "one.example.com" {
			return []string{"203.0.113.7", "203.0.113.8"}
		}
		return nil
	})

	want := &extensions.EgressPolicies{EgressPolicies: []*extensions.EgressPolicy{
		{
			Namespaces: []string{"team-a"},
			MatchCidrs: []string{"10.0.0.0/8", "203.0.113.7/32", "203.0.113.8/32"},
			MatchPorts: []string{"443"},
			Policy:     extensions.EgressPolicyAction_GATEWAY,
			Gateway:    &extensions.GatewayAddress{Service: "egress.team-a.svc.cluster.local", Port: 15008},
		},
		{
			MatchCidrs: []string{unreachableCIDR},
			Policy:     extensions.EgressPolicyAction_DENY,
		},
		{
			MatchCidrs: []string{"192.168.0.0/16"},
			Policy:     extensions.EgressPolicyAction_PASSTHROUGH,
		},
		{
			MatchCidrs: []string{"172.16.0.0/12"},
			Policy:     extensions.EgressPolicyAction_DENY,
		},
	}}
	if !proto.Equal(&extensions.EgressPolicies{EgressPolicies: got}, want) {
		t.Fatalf("resolved policies mismatch:\n got: %v\nwant: %v", got, want.GetEgressPolicies())
	}
	if !proto.Equal(&extensions.EgressPolicies{EgressPolicies: source}, original) {
		t.Fatalf("source policies were mutated:\n got: %v\nwant: %v", source, original.GetEgressPolicies())
	}
}

func TestResolveEgressPoliciesEmpty(t *testing.T) {
	if got := resolveEgressPolicies(krt.TestingDummyContext{}, nil, func(krt.HandlerContext, string) []string {
		return []string{"203.0.113.9"}
	}); len(got) != 0 {
		t.Fatalf("expected no policies, got %v", got)
	}
}

func TestResolvedEgressPoliciesTracksConfigAndResolution(t *testing.T) {
	stop := test.NewStop(t)
	opts := krt.NewOptionsBuilder(stop, "resolved-egress-policies-test", krt.GlobalDebugHandler)
	policy := &extensions.EgressPolicy{
		MatchHosts: []string{"api.example.com"},
		Policy:     extensions.EgressPolicyAction_DENY,
	}
	config := krt.NewStatic(&model.AgentioConfig{AgentioConfig: &extensions.AgentioConfig{
		EgressPolicies: []*extensions.EgressPolicy{policy},
	}}, true, opts.WithName("AgentioConfig")...)
	address := "203.0.113.10"
	addresses := krt.NewStatic(&address, true, opts.WithName("ResolvedAddresses")...)
	resolved := newResolvedEgressPolicies(config, func(ctx krt.HandlerContext, _ string) []string {
		if current := krt.FetchOne(ctx, addresses.AsCollection()); current != nil {
			return []string{*current}
		}
		return nil
	}, opts)
	if !resolved.AsCollection().WaitUntilSynced(stop) {
		t.Fatal("resolved egress policies did not sync")
	}

	assertCIDR := func(want string) error {
		got := resolved.Get()
		if got == nil || len(got.GetEgressPolicies()) != 1 {
			return fmt.Errorf("resolved policies = %v, want one policy", got)
		}
		cidrs := got.GetEgressPolicies()[0].GetMatchCidrs()
		if len(cidrs) != 1 || cidrs[0] != want {
			return fmt.Errorf("resolved CIDRs = %v, want [%s]", cidrs, want)
		}
		return nil
	}
	if err := assertCIDR("203.0.113.10/32"); err != nil {
		t.Fatal(err)
	}

	updatedAddress := "203.0.113.11"
	addresses.Set(&updatedAddress)
	retry.UntilSuccessOrFail(t, func() error {
		return assertCIDR("203.0.113.11/32")
	}, retry.Timeout(5*time.Second))
}
