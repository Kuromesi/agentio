// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0
package securityprofile

import (
	"net/netip"
	"testing"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/policy"
)

func TestFromXDSTCPPolicy(t *testing.T) {
	value := &securityv1.SecurityProfile{
		Name:       "policy",
		Namespace:  "ns",
		Uid:        "uid",
		PolicyJson: []byte(`{"rules":[]}`),
		TcpPolicy: &securityv1.TCPPolicy{Rules: []*securityv1.TCPRule{{
			Name:   "private",
			Action: securityv1.TCPAction_TCP_ACTION_DENY,
			Match:  []*securityv1.TCPMatch{{Cidrs: []string{"10.1.2.3/8"}, Ports: []uint32{443}}},
		}}},
	}
	profile, err := FromXDS(value, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, _ := policy.MatchTCPRules(profile.TCPPolicy.Rules, netip.MustParseAddrPort("10.2.3.4:443")); allowed {
		t.Fatal("typed TCP deny was lost")
	}
	if value.TcpPolicy.Rules[0].Match[0].Cidrs[0] != "10.1.2.3/8" {
		t.Fatal("wire policy was mutated")
	}
	value.TcpPolicy.Rules[0].Match[0].Cidrs[0] = "invalid"
	if _, err := FromXDS(value, "", nil); err == nil {
		t.Fatal("invalid wire TCP policy accepted")
	}
}
