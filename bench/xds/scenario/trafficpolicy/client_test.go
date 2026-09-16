// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package trafficpolicy

import (
	"encoding/json"
	ads "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sandbox "github.com/openkruise/agentio/api/sandbox/v1"
	"google.golang.org/protobuf/types/known/anypb"
	"testing"

	security "github.com/openkruise/agentio/api/security/v1"
	"google.golang.org/protobuf/proto"
)

func TestPolicyValidatorChecksEveryRule(t *testing.T) {
	r := Round{Marker: 10001, Action: 1, RuleCount: 3, Ports: 2}
	p := &security.TrafficPolicy{Egress: &security.TrafficPolicy_RuleSet{}}
	for i := 0; i < 2; i++ {
		rule := &security.TrafficPolicy_Rule{Action: security.TrafficPolicy_DENY, Match: &security.TrafficPolicy_Match{}}
		for j := 0; j < 2; j++ {
			port := uint32(12000 + i*2 + j)
			if i == 0 && j == 0 {
				port = r.Marker
			}
			rule.Match.Ports = append(rule.Match.Ports, &security.TrafficPolicy_PortMatch{Protocol: security.TrafficPolicy_UDP, Port: &port})
		}
		p.Egress.Rules = append(p.Egress.Rules, rule)
	}
	p.Egress.Rules = append(p.Egress.Rules, &security.TrafficPolicy_Rule{Action: security.TrafficPolicy_DENY})
	if err := checkPolicy(p, r); err != nil {
		t.Fatal(err)
	}
	bad := proto.Clone(p).(*security.TrafficPolicy)
	bad.Egress.Rules[1].Match.Ports[1].Protocol = security.TrafficPolicy_TCP
	if err := checkPolicy(bad, r); err == nil {
		t.Fatal("corruption outside marker rule was not detected")
	}
}

func TestClientRoundMatchesMarkerAndSandboxReference(t *testing.T) {
	f, err := New(json.RawMessage(`{"policy_name":"trafficPolicies/test","sandbox_id":"local"}`))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := f.PrepareRound(json.RawMessage(`{"marker":10001,"action":1,"rule_count":2,"ports":1}`))
	if err != nil {
		t.Fatal(err)
	}
	c := f.New()
	sb, err := anypb.New(&sandbox.Sandbox{Uid: "local", PolicyRefs: map[string]*sandbox.PolicyReference{PolicyType: {ResourceNames: []string{"trafficPolicies/test"}}}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Observe(&ads.DeltaDiscoveryResponse{TypeUrl: SandboxType, Resources: []*ads.Resource{{Resource: sb}}}, nil)
	if err != nil || got.Ready {
		t.Fatalf("ready without policy: %+v %v", got, err)
	}
	for _, marker := range []uint32{10000, 10001} {
		p := &security.TrafficPolicy{Egress: &security.TrafficPolicy_RuleSet{Rules: []*security.TrafficPolicy_Rule{
			{Action: security.TrafficPolicy_DENY, Match: &security.TrafficPolicy_Match{Ports: []*security.TrafficPolicy_PortMatch{{Protocol: security.TrafficPolicy_UDP, Port: &marker}}}},
			{Action: security.TrafficPolicy_DENY},
		}}}
		body, err := anypb.New(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err = c.Observe(&ads.DeltaDiscoveryResponse{TypeUrl: PolicyType, Resources: []*ads.Resource{{Name: "trafficPolicies/test", Version: "v1", Resource: body}}}, expected)
		if err != nil || !got.Ready {
			t.Fatalf("observation: %+v %v", got, err)
		}
		if (got.Sample != nil) != (marker == 10001) {
			t.Fatalf("incorrect round sample for marker %d: %+v", marker, got)
		}
	}
}
