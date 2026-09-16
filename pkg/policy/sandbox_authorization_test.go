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
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
)

func TestSandboxAuthorizationDecisions(t *testing.T) {
	allow := &securityv1.TrafficPolicy_Rule{Match: &securityv1.TrafficPolicy_Match{}}
	deny := &securityv1.TrafficPolicy_Rule{Action: securityv1.TrafficPolicy_DENY, Match: &securityv1.TrafficPolicy_Match{}}
	ipAllow := &securityv1.TrafficPolicy_Rule{Match: &securityv1.TrafficPolicy_Match{DestinationIps: []*securityv1.TrafficPolicy_Address{{Address: []byte{192, 0, 2, 0}, Length: 24}}}}
	onPort := func(protocol securityv1.TrafficPolicy_Protocol, start, end uint32) *securityv1.TrafficPolicy_Rule {
		p := &securityv1.TrafficPolicy_PortMatch{Protocol: protocol}
		if start != 0 {
			p.Port = &start
		}
		if end != 0 {
			p.EndPort = &end
		}
		return &securityv1.TrafficPolicy_Rule{Match: &securityv1.TrafficPolicy_Match{Ports: []*securityv1.TrafficPolicy_PortMatch{p}}}
	}
	wildcardPort := onPort(securityv1.TrafficPolicy_TCP, 443, 0)
	wildcardPort.Match.Ports = append(wildcardPort.Match.Ports, &securityv1.TrafficPolicy_PortMatch{})
	p := func(rules ...*securityv1.TrafficPolicy_Rule) *securityv1.TrafficPolicy {
		return &securityv1.TrafficPolicy{Egress: &securityv1.TrafficPolicy_RuleSet{Rules: rules}}
	}
	for _, tc := range []struct {
		name     string
		chain    []*securityv1.TrafficPolicy
		ip       string
		protocol securityv1.Protocol
		port     uint32
		allow    bool
	}{
		{
			name:     "absent direction allows",
			chain:    nil,
			ip:       "192.0.2.1",
			protocol: securityv1.Protocol_TCP,
			port:     80,
			allow:    true,
		},
		{
			name:     "empty direction denies",
			chain:    []*securityv1.TrafficPolicy{p()},
			ip:       "192.0.2.1",
			protocol: securityv1.Protocol_TCP,
			port:     80,
			allow:    false,
		},
		{
			name:     "dedicated wins over shared deny",
			chain:    []*securityv1.TrafficPolicy{p(ipAllow), p(deny)},
			ip:       "192.0.2.1",
			protocol: securityv1.Protocol_TCP,
			port:     80,
			allow:    true,
		},
		{
			name:     "miss continues to shared deny",
			chain:    []*securityv1.TrafficPolicy{p(ipAllow), p(deny)},
			ip:       "203.0.113.1",
			protocol: securityv1.Protocol_TCP,
			port:     80,
			allow:    false,
		},
		{
			name:     "empty policy continues",
			chain:    []*securityv1.TrafficPolicy{p(), p(allow)},
			ip:       "203.0.113.1",
			protocol: securityv1.Protocol_TCP,
			port:     80,
			allow:    true,
		},
		{
			name:     "unmatched chain denies",
			chain:    []*securityv1.TrafficPolicy{p(ipAllow)},
			ip:       "203.0.113.1",
			protocol: securityv1.Protocol_TCP,
			port:     80,
			allow:    false,
		},
		{
			name:     "IPv6 wildcard allow",
			chain:    []*securityv1.TrafficPolicy{p(allow)},
			ip:       "2001:db8::1",
			protocol: securityv1.Protocol_UDP,
			port:     53,
			allow:    true,
		},
		{
			name:     "IPv6 wildcard deny",
			chain:    []*securityv1.TrafficPolicy{p(deny), p(allow)},
			ip:       "2001:db8::1",
			protocol: securityv1.Protocol_TCP,
			port:     80,
			allow:    false,
		},
		{
			name:     "missing reference denies",
			chain:    []*securityv1.TrafficPolicy{nil, p(allow)},
			ip:       "192.0.2.1",
			protocol: securityv1.Protocol_TCP,
			port:     80,
			allow:    false,
		},
		{
			name:     "earlier allow survives missing reference",
			chain:    []*securityv1.TrafficPolicy{p(allow), nil},
			ip:       "192.0.2.1",
			protocol: securityv1.Protocol_TCP,
			port:     80,
			allow:    true,
		},
		{
			name:     "port range inclusive",
			chain:    []*securityv1.TrafficPolicy{p(onPort(securityv1.TrafficPolicy_TCP, 80, 90))},
			ip:       "192.0.2.1",
			protocol: securityv1.Protocol_TCP,
			port:     90,
			allow:    true,
		},
		{
			name:     "port range miss",
			chain:    []*securityv1.TrafficPolicy{p(onPort(securityv1.TrafficPolicy_TCP, 80, 90))},
			ip:       "192.0.2.1",
			protocol: securityv1.Protocol_TCP,
			port:     91,
			allow:    false,
		},
		{
			name:     "protocol mismatch",
			chain:    []*securityv1.TrafficPolicy{p(onPort(securityv1.TrafficPolicy_UDP, 53, 0))},
			ip:       "192.0.2.1",
			protocol: securityv1.Protocol_TCP,
			port:     53,
			allow:    false,
		},
		{
			name:     "ICMP protocol only",
			chain:    []*securityv1.TrafficPolicy{p(onPort(securityv1.TrafficPolicy_ICMP, 0, 0))},
			ip:       "192.0.2.1",
			protocol: securityv1.Protocol_ICMP,
			port:     0,
			allow:    true,
		},
		{
			name:     "unconstrained port alternative",
			chain:    []*securityv1.TrafficPolicy{p(wildcardPort)},
			ip:       "192.0.2.1",
			protocol: securityv1.Protocol_UDP,
			port:     53,
			allow:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := make([]*securityv1.TrafficPolicy, len(tc.chain))
			for i, p := range tc.chain {
				if p != nil {
					before[i] = proto.Clone(p).(*securityv1.TrafficPolicy)
				}
			}
			converted, err := SandboxAsAuthorizations("test", "demo", tc.chain)
			if err != nil {
				t.Fatal(err)
			}
			if got := legacySandboxDecision(converted[0].Policy, netip.MustParseAddr(tc.ip), tc.protocol, tc.port); got != tc.allow {
				t.Fatalf("legacy allow=%v, expected %v; policy=%v", got, tc.allow, converted[0].Policy)
			}
			// No source configured ingress: the compatibility output preserves
			// native Sandbox's allow behavior, even if legacy global rules exist.
			if got := legacySandboxDecision(converted[1].Policy, netip.MustParseAddr(tc.ip), tc.protocol, tc.port); got != !slices.Contains(tc.chain, nil) {
				t.Fatal("egress rules affected ingress")
			}
			for i, p := range tc.chain {
				if !proto.Equal(p, before[i]) {
					t.Fatal("projection mutated shared compiled policy")
				}
			}
		})
	}
}

// Evaluate the legacy wire subset emitted above: OR of groups, AND of clauses,
// OR of matches, and negative fields encoding a terminal rejection. Explicit
// expectations above exercise behavior rather than copying the converter.
func legacySandboxDecision(p *securityv1.Authorization, dst netip.Addr, protocol securityv1.Protocol, port uint32) bool {
	for _, group := range p.Groups {
		negative := false
		for _, clause := range group.Rules {
			for _, m := range clause.Matches {
				negative = negative || len(m.NotDestinationIps) > 0 || len(m.NotDestinationPortRanges) > 0
			}
		}
		matched := true
		for _, clause := range group.Rules {
			clauseMatched := false
			for _, m := range clause.Matches {
				ips, ports := m.DestinationIps, m.DestinationPortRanges
				if negative {
					ips, ports = m.NotDestinationIps, m.NotDestinationPortRanges
				}
				ipMatched := len(ips) == 0
				for _, ip := range ips {
					addr, valid := netip.AddrFromSlice(ip.Address)
					ipMatched = ipMatched || (valid && netip.PrefixFrom(addr, int(ip.Length)).Contains(dst))
				}
				portMatched := len(ports) == 0
				for _, pr := range ports {
					portMatched = portMatched || ((pr.Protocol == securityv1.Protocol_ALL || pr.Protocol == protocol) && port >= pr.Start && port <= pr.End)
				}
				clauseMatched = clauseMatched || (ipMatched && portMatched)
			}
			matched = matched && clauseMatched
		}
		if matched {
			return !negative
		}
	}
	return false
}
