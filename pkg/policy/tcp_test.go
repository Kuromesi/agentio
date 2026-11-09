// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"net/netip"
	"testing"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
)

func TestTCPRulesOrderedDestinationMatching(t *testing.T) {
	rules := []agents.TCPRule{
		{
			Name:   "exception",
			Action: "allow",
			Match:  []agents.TCPMatch{{CIDRs: []string{"10.1.0.1/16"}, Ports: []int32{443}}},
		},
		{Name: "private", Action: "deny", Match: []agents.TCPMatch{{CIDRs: []string{"10.0.0.0/8", "fc00::/7"}}}},
	}
	compiled, err := CompileTCPRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		target string
		allow  bool
		index  int
	}{
		{"10.1.0.2:443", true, 0}, {"10.1.0.2:80", false, 1}, {"[fd00::1]:443", false, 1}, {"192.0.2.1:443", true, -1}, {"[::ffff:10.1.0.2]:443", true, 0},
	} {
		allow, index := MatchTCPRules(compiled.Rules, netip.MustParseAddrPort(tc.target))
		if allow != tc.allow || index != tc.index {
			t.Errorf("%s: %v/%d", tc.target, allow, index)
		}
	}
	for _, rule := range []agents.TCPRule{
		{Name: "bad", Action: "deny"},
		{Name: "bad", Action: "invalid", Match: []agents.TCPMatch{{}}},
		{Name: "bad", Action: "deny", Match: []agents.TCPMatch{{CIDRs: []string{"::ffff:10.0.0.0/120"}}}},
		{Name: "bad", Action: "deny", Match: []agents.TCPMatch{{Ports: []int32{65536}}}},
	} {
		if _, err := CompileTCPRules([]agents.TCPRule{rule}); err == nil {
			t.Fatalf("invalid rule accepted: %+v", rule)
		}
	}
	empty, err := CompileTCPRules(nil)
	if err != nil || empty == nil {
		t.Fatalf("empty policy: %v %v", empty, err)
	}
	if allow, _ := MatchTCPRules(empty.Rules, netip.MustParseAddrPort("192.0.2.1:443")); !allow {
		t.Fatal("empty policy must allow")
	}
}
