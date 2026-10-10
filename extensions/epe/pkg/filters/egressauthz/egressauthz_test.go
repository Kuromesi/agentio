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
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/pkg/dns"
)

func run(t *testing.T, f authorizeFunc, host string, port int32) *filter.RouteMutation {
	t.Helper()
	target, reply, err := f(context.Background(), &filter.Stream{
		Request: httpreq.HTTPRequest{Host: host, Port: port},
	})
	if err != nil {
		t.Fatal(err)
	}
	if reply != nil || target == nil {
		t.Fatalf("target=%v reply=%v", target, reply)
	}
	return &filter.RouteMutation{Upstream: target}
}

type lookupFunc func(context.Context, string, dns.Family) (dns.LookupResult, error)

func (f lookupFunc) Lookup(ctx context.Context, host string, family dns.Family) (dns.LookupResult, error) {
	return f(ctx, host, family)
}

func TestDNSUsesSharedCacheAndCustomRecords(t *testing.T) {
	calls := 0
	client := dns.NewClient(
		lookupFunc(func(_ context.Context, host string, family dns.Family) (dns.LookupResult, error) {
			calls++
			if host != "example.com" || family != dns.IPv4Only {
				t.Fatalf("lookup(%q, %v)", host, family)
			}
			return dns.LookupResult{
				Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
				TTL:       time.Minute,
			}, nil
		}),
		time.Second,
	)
	input := dnsAuthorizer(t, client, dns.IPv4Only)
	for range 2 {
		got := run(t, input, "example.com", 8443)
		if got.Upstream.Address.String() != "192.0.2.1:8443" || got.ClearCache {
			t.Fatalf("unexpected route: %+v", got)
		}
	}
	if calls != 1 {
		t.Fatalf("lookup calls = %d, want 1", calls)
	}
	if err := client.SetRecord("example.com", []netip.Addr{netip.MustParseAddr("192.0.2.3")}); err != nil {
		t.Fatal(err)
	}
	if got := run(t, input, "example.com", 443); got.Upstream.Address.String() != "192.0.2.3:443" {
		t.Fatal("custom record did not override cached DNS")
	}
	if err := client.DeleteRecord("example.com"); err != nil {
		t.Fatal(err)
	}
	if got := run(t, input, "example.com", 443); got.Upstream.Address.String() != "192.0.2.1:443" || calls != 2 {
		t.Fatal("removing custom record did not resume DNS")
	}
	got := run(t, dnsAuthorizer(t, client, dns.IPv6Only), "2001:db8::1", 443)
	if got.Upstream.Address.String() != "[2001:db8::1]:443" || got.ClearCache || calls != 2 {
		t.Fatal("literal IP route should skip DNS and preserve ClearCache=false")
	}
}

func TestInputFailuresDoNotProduceMutations(t *testing.T) {
	lookupErr := errors.New("lookup unavailable")
	client := dns.NewClient(lookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{}, lookupErr
	}), time.Second)
	for _, tc := range []struct {
		name  string
		input authorizeFunc
		host  string
		port  int32
		want  error
	}{
		{"lookup failure", dnsAuthorizer(t, client, dns.DualStack), "example.com", 443, lookupErr},
		{"missing client", dnsAuthorizer(t, nil, dns.DualStack), "example.com", 443, nil},
		{"invalid port", dnsAuthorizer(t, client, dns.DualStack), "example.com", 65536, nil},
		{"missing port", dnsAuthorizer(t, client, dns.DualStack), "example.com", 0, nil},
		{"family mismatch", dnsAuthorizer(t, client, dns.IPv4Only), "2001:db8::1", 443, dns.ErrNoAddresses},
		{"scoped IP", dnsAuthorizer(t, client, dns.DualStack), "fe80::1%eth0", 443, nil},
		{"invalid family", dnsAuthorizer(t, client, dns.Family(99)), "192.0.2.1", 443, dns.ErrInvalidFamily},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, _, err := tc.input(context.Background(), &filter.Stream{
				Request: httpreq.HTTPRequest{Host: tc.host, Port: tc.port},
			})
			if err == nil || target != nil {
				t.Fatalf("target=%+v, err=%v", target, err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
		})
	}
}

func dnsAuthorizer(t *testing.T, client *dns.Client, family dns.Family) authorizeFunc {
	t.Helper()
	return authorizer(Config{
		Family: family,
		Policies: []Policy{{Name: "test",
			Rules: []Rule{{
				Action: Allow,
				CIDRs:  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			}}}},
	}, client)
}

func TestAuthorizationSelectsAndPinsAllowedCandidate(t *testing.T) {
	client := dns.NewClient(nil, time.Second)
	if err := client.SetRecord("example.com", []netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"),
	}); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Policies: []Policy{{Name: "test",
		Rules: []Rule{
			{Action: Deny, CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}},
			{
				Action: Allow,
				CIDRs:  []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
				Ports:  []PortRange{{Start: 443}},
			},
		}}}}
	f := authorizer(cfg, client)
	if route := run(t, f, "example.com", 443); route.Upstream.Address.String() != "192.0.2.2:443" || route.ClearCache {
		t.Fatalf("unauthorized or changed target: %+v", route)
	}
	assertDenied(t, f, "example.com", 80)
	// An empty snapshot is an active deny-all policy, not a missing filter.
	empty := authorizer(Config{}, client)
	assertDenied(t, empty, "example.com", 443)
	assertDenied(t, empty, "192.0.2.1", 443)
}

func assertDenied(t *testing.T, f authorizeFunc, host string, port int32) {
	t.Helper()
	target, reply, err := f(context.Background(), &filter.Stream{
		Request: httpreq.HTTPRequest{Host: host, Port: port},
	})
	if err != nil || reply == nil || reply.Status != 403 || reply.Details != "epe_egress_denied" || target != nil {
		t.Fatalf("target=%v reply=%v err=%v", target, reply, err)
	}
}

type authorizeFunc func(context.Context, *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error)

func authorizer(cfg Config, client *dns.Client) authorizeFunc {
	return func(ctx context.Context, stream *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
		return Authorize(ctx, cfg, client, stream)
	}
}
