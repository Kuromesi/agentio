// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package egressauthz

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/pkg/dns"
)

func TestGlobalDeniedCIDRs(t *testing.T) {
	global := Config{DeniedCIDRs: []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"),
	}}
	allowAll := Config{Policies: []Policy{{
		Name: "allow-all",
		Rules: []Rule{{
			Action: Allow,
			CIDRs:  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		}}}}}
	for _, tc := range []struct {
		name     string
		host     string
		ips      []netip.Addr
		upstream string
		original string
		want     string
	}{
		{name: "literal IPv4", host: "127.0.0.2"},
		{name: "literal IPv6", host: "::1"},
		{name: "mapped IPv4", host: "::ffff:127.0.0.1"},
		{name: "domain to loopback", host: "attacker.example", ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		{name: "explicit route", host: "allowed.example", upstream: "127.0.0.1:15000"},
		{name: "mixed DNS", host: "mixed.example", ips: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")}, want: "192.0.2.1:15000"},
		{name: "denied original cannot fall back", host: "mixed.example", ips: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")}, original: "127.0.0.1:15000"},
		{name: "unmatched IPv4", host: "192.0.2.1", want: "192.0.2.1:15000"},
		{name: "unmatched IPv6", host: "2001:db8::1", want: "[2001:db8::1]:15000"},
	} {
		for _, xds := range []bool{false, true} {
			name := tc.name + "/static"
			var policies ConfigResolver
			if xds {
				name = tc.name + "/xds-allow-all"
				policies = func(context.Context, *filter.Stream) (Config, error) { return allowAll, nil }
			}
			t.Run(name, func(t *testing.T) {
				lookups := 0
				client := dns.NewClient(lookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
					lookups++
					return dns.LookupResult{Addresses: tc.ips}, nil
				}), 0)
				stream := &filter.Stream{
					Request: httpreq.HTTPRequest{Host: tc.host, Port: 15000},
					Info:    filter.NewStreamInfo(),
				}
				if tc.upstream != "" {
					address := netip.MustParseAddrPort(tc.upstream)
					stream.Upstream = &filter.UpstreamTarget{Address: &address}
				}
				if tc.original != "" {
					stream.Request.OriginalDestination = netip.MustParseAddrPort(tc.original)
				}
				authorize := NewAuthorizer(client, func() Config { return global }, policies)
				target, reply, err := authorize(t.Context(), stream)
				if err != nil {
					t.Fatal(err)
				}
				if tc.want == "" {
					if target != nil || reply == nil || reply.Status != 403 {
						t.Fatalf("target=%v reply=%v", target, reply)
					}
					if stream.Info.Authorization.Policy != "EPEConfig/egressAuthorization" {
						t.Fatalf("audit=%+v", stream.Info.Authorization)
					}
				} else if reply != nil || target == nil || target.Address.String() != tc.want {
					t.Fatalf("target=%v reply=%v, want %s", target, reply, tc.want)
				}
				wantLookups := 0
				if tc.ips != nil {
					wantLookups = 1
				}
				if lookups != wantLookups {
					t.Fatalf("DNS lookups=%d, want %d", lookups, wantLookups)
				}
			})
		}
	}
}

func TestGlobalSnapshotAndWorkloadPolicies(t *testing.T) {
	denied := Config{DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	current := denied
	workload := Config{}
	var policyErr error
	authorize := NewAuthorizer(dns.NewClient(nil, 0), func() Config { return current },
		func(context.Context, *filter.Stream) (Config, error) {
			// An update during policy loading must affect only later requests.
			current = Config{}
			return workload, policyErr
		})
	request := func(host string) (*filter.UpstreamTarget, *filter.Reply, error) {
		return authorize(t.Context(), &filter.Stream{Request: httpreq.HTTPRequest{Host: host, Port: 443}})
	}
	if target, reply, err := request("127.0.0.1"); err != nil || reply == nil || target != nil {
		t.Fatalf("snapshot lost: %v %v %v", target, reply, err)
	}
	if target, reply, err := request("127.0.0.1"); err != nil || reply != nil || target == nil {
		t.Fatalf("update ignored: %v %v %v", target, reply, err)
	}
	current = denied
	workload.Policies = []Policy{{Name: "default-deny"}}
	if target, reply, err := request("192.0.2.1"); err != nil || reply == nil || target != nil {
		t.Fatalf("workload restriction bypassed: %v %v %v", target, reply, err)
	}
	policyErr = errors.New("xDS unavailable")
	if target, reply, err := request("192.0.2.1"); !errors.Is(err, policyErr) || reply != nil || target != nil {
		t.Fatalf("policy error ignored: %v %v %v", target, reply, err)
	}
}
