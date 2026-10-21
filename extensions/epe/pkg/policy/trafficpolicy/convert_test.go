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

package trafficpolicy

import (
	"net/netip"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	sec "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
)

func address(cidr string) *sec.TrafficPolicy_Address {
	p := netip.MustParsePrefix(cidr)
	return &sec.TrafficPolicy_Address{Address: p.Addr().AsSlice(), Length: uint32(p.Bits())}
}

func TestConvertOrderAndProtocol(t *testing.T) {
	deny := &sec.TrafficPolicy{
		Egress: &sec.TrafficPolicy_RuleSet{
			Rules: []*sec.TrafficPolicy_Rule{
				{
					Action: sec.TrafficPolicy_DENY,
					Match: &sec.TrafficPolicy_Match{
						DestinationIps: []*sec.TrafficPolicy_Address{address("10.0.0.0/8")},
						Ports: []*sec.TrafficPolicy_PortMatch{
							{Protocol: sec.TrafficPolicy_TCP, Port: proto.Uint32(80), EndPort: proto.Uint32(90)},
						},
					},
				},
			},
		},
	}
	allow := &sec.TrafficPolicy{
		Egress: &sec.TrafficPolicy_RuleSet{Rules: []*sec.TrafficPolicy_Rule{{Match: &sec.TrafficPolicy_Match{}}}},
	}
	cfg, err := Compile(
		[]NamedPolicy{{Name: "deny", Policy: deny}, {Name: "allow", Policy: allow}},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		dst  string
		want egressauthz.Action
	}{{"10.1.1.1:80", egressauthz.Deny}, {"10.1.1.1:443", egressauthz.Allow}, {"1.1.1.1:80", egressauthz.Allow}} {
		if got := cfg.Evaluate(netip.MustParseAddrPort(tc.dst)).Action; got != tc.want {
			t.Errorf("%s: %s, want %s", tc.dst, got, tc.want)
		}
	}
	source := &sec.TrafficPolicy{
		Egress: &sec.TrafficPolicy_RuleSet{
			Rules: []*sec.TrafficPolicy_Rule{
				{
					Match: &sec.TrafficPolicy_Match{
						SourceIps: []*sec.TrafficPolicy_Address{address("192.0.2.0/24")},
						Ports: []*sec.TrafficPolicy_PortMatch{
							{Protocol: sec.TrafficPolicy_UDP, Port: proto.Uint32(53)},
						},
					},
				},
			},
		},
	}
	cfg, err = Compile([]NamedPolicy{{Name: "source", Policy: source}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Evaluate(netip.MustParseAddrPort("1.1.1.1:53")).Action != egressauthz.Deny {
		t.Fatal("UDP policy allowed TCP")
	}
}

func TestPresenceAndMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *sec.TrafficPolicy
		want egressauthz.Action
	}{
		{"absent", &sec.TrafficPolicy{}, egressauthz.Deny},
		{"ingress only", &sec.TrafficPolicy{Ingress: &sec.TrafficPolicy_RuleSet{}}, egressauthz.Deny},
		{"empty", &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{}}, egressauthz.Deny},
	} {
		cfg, err := Compile([]NamedPolicy{{Name: tc.name, Policy: tc.p}})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Evaluate(netip.MustParseAddrPort("1.1.1.1:80")).Action != tc.want {
			t.Fatal(tc.name)
		}
	}
	for _, match := range []*sec.TrafficPolicy_Match{nil, {DestinationIps: []*sec.TrafficPolicy_Address{{Address: []byte{1}, Length: 32}}}, {Ports: []*sec.TrafficPolicy_PortMatch{{Port: proto.Uint32(65536)}}}} {
		_, err := Compile(
			[]NamedPolicy{
				{
					Name: "bad",
					Policy: &sec.TrafficPolicy{
						Egress: &sec.TrafficPolicy_RuleSet{Rules: []*sec.TrafficPolicy_Rule{{Match: match}}},
					},
				},
			},
		)
		if err == nil || !strings.Contains(err.Error(), `TrafficPolicy "bad" egress rule 0`) {
			t.Fatalf("malformed rule error lost policy or rule identity: %v", err)
		}
	}
}

func TestEgressIgnoresSourceAddresses(t *testing.T) {
	for _, source := range []*sec.TrafficPolicy_Address{
		address("192.0.2.0/24"),
		{Address: []byte{1}, Length: 999},
	} {
		policy := &sec.TrafficPolicy{
			Egress: &sec.TrafficPolicy_RuleSet{Rules: []*sec.TrafficPolicy_Rule{{Match: &sec.TrafficPolicy_Match{
				SourceIps:      []*sec.TrafficPolicy_Address{source},
				DestinationIps: []*sec.TrafficPolicy_Address{address("203.0.113.0/24")},
				Ports: []*sec.TrafficPolicy_PortMatch{
					{Protocol: sec.TrafficPolicy_TCP, Port: proto.Uint32(443)},
				},
			}}}},
		}
		cfg, err := Compile([]NamedPolicy{{Name: "destination-only", Policy: policy}})
		if err != nil {
			t.Fatal("ignored source affected compilation", err)
		}
		for _, tc := range []struct {
			address string
			want    egressauthz.Action
		}{
			{"203.0.113.7:443", egressauthz.Allow},
			{"203.0.113.7:80", egressauthz.Deny},
			{"192.0.2.1:443", egressauthz.Deny},
		} {
			if got := cfg.Evaluate(netip.MustParseAddrPort(tc.address)).Action; got != tc.want {
				t.Fatalf("%s: got %s, want %s", tc.address, got, tc.want)
			}
		}
	}
}

func TestDecisionPreservesSourceRuleIndex(t *testing.T) {
	cfg, err := Compile(
		[]NamedPolicy{
			{
				Name: "mixed",
				Policy: &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{Rules: []*sec.TrafficPolicy_Rule{
					{
						Match: &sec.TrafficPolicy_Match{
							Ports: []*sec.TrafficPolicy_PortMatch{{Protocol: sec.TrafficPolicy_UDP}},
						},
					},
					{Action: sec.TrafficPolicy_DENY, Match: &sec.TrafficPolicy_Match{}},
				}}},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Evaluate(netip.MustParseAddrPort("1.1.1.1:80"))
	if d.PolicyName != "mixed" || d.RuleIndex != 1 {
		t.Fatalf("decision: %+v", d)
	}
	cfg, err = Compile(nil)
	if err != nil {
		t.Fatal(err)
	}
	d = cfg.Evaluate(netip.MustParseAddrPort("1.1.1.1:80"))
	if d.Action != egressauthz.Allow || d.PolicyName != "" || d.RuleIndex != -1 {
		t.Fatalf("unexpected default decision: %+v", d)
	}
}

func TestPolicyChainDefaultDeny(t *testing.T) {
	absent := NamedPolicy{Name: "absent", Policy: &sec.TrafficPolicy{}}
	empty := NamedPolicy{Name: "empty", Policy: &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{}}}
	allow := NamedPolicy{Name: "allow", Policy: &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{
		Rules: []*sec.TrafficPolicy_Rule{{Action: sec.TrafficPolicy_ALLOW, Match: &sec.TrafficPolicy_Match{}}},
	}}}
	deny := NamedPolicy{Name: "deny", Policy: &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{
		Rules: []*sec.TrafficPolicy_Rule{{Action: sec.TrafficPolicy_DENY, Match: &sec.TrafficPolicy_Match{}}},
	}}}
	missing := NamedPolicy{Name: "missing"}
	for _, tc := range []struct {
		name      string
		policies  []NamedPolicy
		want      egressauthz.Action
		wantError bool
	}{
		{name: "no policies", want: egressauthz.Allow},
		{name: "absent direction", policies: []NamedPolicy{absent}, want: egressauthz.Deny},
		{name: "empty then allow", policies: []NamedPolicy{empty, allow}, want: egressauthz.Allow},
		{name: "allow then deny", policies: []NamedPolicy{allow, deny}, want: egressauthz.Allow},
		{name: "deny then allow", policies: []NamedPolicy{deny, allow}, want: egressauthz.Deny},
		{name: "empty then absent", policies: []NamedPolicy{empty, absent}, want: egressauthz.Deny},
		{name: "missing then allow", policies: []NamedPolicy{missing, allow}, wantError: true},
		{name: "allow then missing", policies: []NamedPolicy{allow, missing}, wantError: true},
		{name: "empty then missing", policies: []NamedPolicy{empty, missing}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Compile(tc.policies)
			if tc.wantError {
				if err == nil {
					t.Fatal("missing dependency accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Evaluate(netip.MustParseAddrPort("192.0.2.1:443")).Action; got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}
