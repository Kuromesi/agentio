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

package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/openkruise/agentio/pkg/krt"
)

func TestResolverRefreshesWithoutBlockingCompile(t *testing.T) {
	ctx := t.Context()
	var calls atomic.Int32
	resolver, err := New(ctx, Options{RefreshInterval: 20 * time.Millisecond, LookupTimeout: time.Second, MaxConcurrent: 2},
		func(_ context.Context, _ string, queryType uint16) (LookupResult, error) {
			calls.Add(1)
			return LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.9")}, TTL: time.Minute}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if got := resolver.Resolve(krt.TestingDummyContext{}, "API.EXAMPLE.COM."); got != nil {
		t.Fatalf("cold resolve blocked or returned data: %v", got)
	}
	deadline := time.Now().Add(time.Second)
	for resolver.Results().GetKey("api.example.com") == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if resolver.Results().GetKey("api.example.com") == nil {
		t.Fatal("DNS result was not published to the collection")
	}
	got := resolver.Resolve(krt.TestingDummyContext{}, "api.example.com")
	if len(got) != 1 || got[0].String() != "203.0.113.9" {
		t.Fatalf("cached result = %v", got)
	}
	if calls.Load() == 0 {
		t.Fatal("lookup was not called")
	}
}

func TestResolverEvictsUnreferencedColdResultAtRefreshDeadline(t *testing.T) {
	host := "transient.example.com"
	address := netip.MustParseAddr("203.0.113.10")
	item := &entry{
		hostname:  host,
		next:      time.Now().Add(-time.Second),
		published: true,
		index:     -1,
	}
	resolver := &Resolver{
		entries: map[string]*entry{host: item},
		results: krt.NewStaticCollection[Result](nil, []Result{{
			Hostname:  host,
			Addresses: []netip.Addr{address},
		}}),
		jobs: make(chan lookupJob, 1),
	}
	item.families[0].queried = true
	item.families[1].queried = true
	resolver.scheduleLocked(item)

	resolver.dispatchDue()

	resolver.mu.RLock()
	_, retained := resolver.entries[host]
	resolver.mu.RUnlock()
	if retained {
		t.Fatal("unreferenced cold DNS entry remained resident after its TTL")
	}
	if got := resolver.Results().GetKey(host); got != nil {
		t.Fatalf("unreferenced cold DNS result remained published after its TTL: %+v", got)
	}
}

func TestResolverDropsUnreferencedColdEntryAfterLookupFailure(t *testing.T) {
	host := "unavailable.example.com"
	item := &entry{hostname: host, index: -1}
	resolver := &Resolver{
		ctx:     t.Context(),
		options: Options{RefreshInterval: time.Hour, LookupTimeout: time.Second},
		lookup: func(_ context.Context, _ string, queryType uint16) (LookupResult, error) {
			return LookupResult{}, fmt.Errorf("DNS unavailable")
		},
		entries: map[string]*entry{host: item},
		results: krt.NewStaticCollection[Result](nil, nil),
		wake:    make(chan struct{}, 1),
	}

	resolver.refresh(lookupJob{item, 0})
	resolver.refresh(lookupJob{item, 1})

	resolver.mu.RLock()
	_, retained := resolver.entries[host]
	resolver.mu.RUnlock()
	if retained {
		t.Fatal("failed unreferenced cold DNS entry remained scheduled for retry")
	}
}

func TestRefreshDelayHonorsTTLWithStableJitter(t *testing.T) {
	first := refreshDelay("api.example.com", 30*time.Second, time.Minute)
	second := refreshDelay("api.example.com", 30*time.Second, time.Minute)
	if first != second {
		t.Fatalf("stable jitter changed for the same hostname: %v != %v", first, second)
	}
	if first < 25*time.Second || first >= 28*time.Second {
		t.Fatalf("30s TTL refresh delay = %v, want [25s, 28s)", first)
	}

	short := refreshDelay("short.example.com", time.Second, time.Minute)
	if short < 800*time.Millisecond || short >= 960*time.Millisecond {
		t.Fatalf("short TTL refresh delay = %v, want [800ms, 960ms)", short)
	}

	fallback := refreshDelay("fallback.example.com", 0, 40*time.Second)
	if fallback < 35*time.Second || fallback >= 38*time.Second {
		t.Fatalf("fallback refresh delay = %v, want [35s, 38s)", fallback)
	}
}

func TestProtocolLookupKeepsFamilyTTLs(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{
		PacketConn: packet,
		Handler: mdns.HandlerFunc(func(response mdns.ResponseWriter, request *mdns.Msg) {
			message := new(mdns.Msg)
			message.SetReply(request)
			name := request.Question[0].Name
			switch request.Question[0].Qtype {
			case mdns.TypeA:
				message.Answer = append(message.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 45},
					A:   net.ParseIP("192.0.2.10"),
				})
			case mdns.TypeAAAA:
				message.Answer = append(message.Answer, &mdns.AAAA{
					Hdr:  mdns.RR_Header{Name: name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 20},
					AAAA: net.ParseIP("2001:db8::10"),
				})
			}
			if err := response.WriteMsg(message); err != nil {
				t.Errorf("write DNS response: %v", err)
			}
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	lookup := newProtocolLookup([]string{packet.LocalAddr().String()}, time.Second)
	for queryType, want := range map[uint16]struct {
		address string
		ttl     time.Duration
	}{
		mdns.TypeA:    {"192.0.2.10", 45 * time.Second},
		mdns.TypeAAAA: {"2001:db8::10", 20 * time.Second},
	} {
		result, err := lookup(t.Context(), "api.example.com", queryType)
		if err != nil || result.TTL != want.ttl || len(result.Addresses) != 1 || result.Addresses[0].String() != want.address {
			t.Fatalf("type=%d result=%+v err=%v, want %+v", queryType, result, err, want)
		}
	}
}

func TestProtocolLookupTreatsNXDOMAINAsAuthoritativeEmpty(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{
		PacketConn: packet,
		Handler: mdns.HandlerFunc(func(response mdns.ResponseWriter, request *mdns.Msg) {
			message := new(mdns.Msg)
			message.SetRcode(request, mdns.RcodeNameError)
			message.Ns = append(message.Ns, &mdns.SOA{
				Hdr:     mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: 30},
				Ns:      "ns.example.com.",
				Mbox:    "hostmaster.example.com.",
				Minttl:  12,
				Refresh: 60,
				Retry:   60,
				Expire:  300,
			})
			if err := response.WriteMsg(message); err != nil {
				t.Errorf("write DNS response: %v", err)
			}
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	lookup := newProtocolLookup([]string{packet.LocalAddr().String()}, time.Second)
	result, err := lookup(t.Context(), "gone.example.com", mdns.TypeA)
	if err != nil {
		t.Fatalf("NXDOMAIN returned a transient error: %v", err)
	}
	if len(result.Addresses) != 0 || !result.NameError {
		t.Fatalf("NXDOMAIN addresses = %v, want empty", result.Addresses)
	}
	if result.TTL != 12*time.Second {
		t.Fatalf("negative TTL = %v, want 12s", result.TTL)
	}
}

func TestResolverSchedulesFromAnswerTTLAndPreservesOnFailure(t *testing.T) {
	ctx := t.Context()
	var phase atomic.Int32
	resolver, err := New(ctx, Options{RefreshInterval: time.Hour, LookupTimeout: time.Second, MaxConcurrent: 1},
		func(_ context.Context, _ string, queryType uint16) (LookupResult, error) {
			if phase.Load() == 0 {
				return LookupResult{
					Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.20")},
					TTL:       30 * time.Second,
				}, nil
			}
			return LookupResult{}, fmt.Errorf("temporary DNS failure")
		})
	if err != nil {
		t.Fatal(err)
	}
	resolver.HandleAdd("api.example.com")
	eventuallyDNS(t, func() bool {
		result := resolver.Results().GetKey("api.example.com")
		return result != nil && len(result.Addresses) == 1
	}, "initial DNS result published")

	resolver.mu.RLock()
	next := resolver.entries["api.example.com"].next
	resolver.mu.RUnlock()
	delay := time.Until(next)
	if delay < 24*time.Second || delay >= 28*time.Second {
		t.Fatalf("next refresh delay = %v, want answer TTL based [24s, 28s)", delay)
	}

	phase.Store(1)
	resolver.mu.RLock()
	item := resolver.entries["api.example.com"]
	resolver.mu.RUnlock()
	resolver.refresh(lookupJob{item, 0})
	resolver.refresh(lookupJob{item, 1})
	result := resolver.Results().GetKey("api.example.com")
	if result == nil || len(result.Addresses) != 1 || result.Addresses[0].String() != "203.0.113.20" {
		t.Fatalf("temporary failure discarded last-known-good result: %+v", result)
	}
}

func TestNewUsesConfiguredDNSServers(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{
		PacketConn: packet,
		Handler: mdns.HandlerFunc(func(response mdns.ResponseWriter, request *mdns.Msg) {
			message := new(mdns.Msg)
			message.SetReply(request)
			name := request.Question[0].Name
			if request.Question[0].Qtype == mdns.TypeA {
				message.Answer = append(message.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.0.2.30"),
				})
			}
			if err := response.WriteMsg(message); err != nil {
				t.Errorf("write DNS response: %v", err)
			}
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	ctx := t.Context()
	resolver, err := New(ctx, Options{
		RefreshInterval: time.Hour,
		LookupTimeout:   time.Second,
		MaxConcurrent:   1,
		DNSServers:      []string{packet.LocalAddr().String()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolver.Resolve(krt.TestingDummyContext{}, "api.example.com"); got != nil {
		t.Fatalf("cold resolve returned synchronously: %v", got)
	}
	eventuallyDNS(t, func() bool {
		result := resolver.Results().GetKey("api.example.com")
		return result != nil && len(result.Addresses) == 1 && result.Addresses[0].String() == "192.0.2.30"
	}, "configured DNS server result published")
}

func TestResolverWakesForAnswerTTLBeforeFallbackInterval(t *testing.T) {
	ctx := t.Context()
	var calls atomic.Int32
	resolver, err := New(ctx, Options{RefreshInterval: time.Hour, LookupTimeout: time.Second, MaxConcurrent: 1},
		func(_ context.Context, _ string, queryType uint16) (LookupResult, error) {
			if queryType == mdns.TypeAAAA {
				return LookupResult{TTL: time.Hour}, nil
			}
			call := calls.Add(1)
			return LookupResult{
				Addresses: []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, byte(call)})},
				TTL:       10 * time.Second,
			}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	resolver.HandleAdd("ttl.example.com")
	eventuallyDNS(t, func() bool {
		result := resolver.Results().GetKey("ttl.example.com")
		return result != nil && len(result.Addresses) == 1 && result.Addresses[0].String() == "192.0.2.1"
	}, "initial TTL result published")

	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		result := resolver.Results().GetKey("ttl.example.com")
		if result != nil && len(result.Addresses) == 1 && result.Addresses[0].String() == "192.0.2.2" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("TTL refresh did not run before fallback interval; calls=%d", calls.Load())
}

func TestResolverDiscardsLookupForRemovedEntry(t *testing.T) {
	for _, recreate := range []bool{false, true} {
		t.Run(map[bool]string{false: "deleted", true: "recreated"}[recreate], func(t *testing.T) {
			started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			old := &entry{hostname: "example.com", refs: 1, index: -1}
			resolver := &Resolver{ctx: t.Context(), options: Options{LookupTimeout: time.Second}, entries: map[string]*entry{"example.com": old}, results: krt.NewStaticCollection[Result](nil, nil), wake: make(chan struct{}, 1)}
			resolver.lookup = func(ctx context.Context, _ string, queryType uint16) (LookupResult, error) {
				if queryType == mdns.TypeAAAA {
					return LookupResult{TTL: time.Hour}, nil
				}
				close(started)
				select {
				case <-release:
				case <-ctx.Done():
					return LookupResult{}, ctx.Err()
				}
				return LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTL: time.Minute}, nil
			}
			go func() { resolver.refresh(lookupJob{old, 0}); close(done) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("lookup did not start")
			}
			resolver.HandleDelete("example.com")
			if recreate {
				resolver.HandleAdd("example.com")
			}
			close(release)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("lookup did not finish")
			}
			if result := resolver.Results().GetKey("example.com"); result != nil {
				t.Fatalf("old lookup published: %+v", result)
			}
			if recreate && resolver.entries["example.com"].published {
				t.Fatal("old lookup changed recreated entry")
			}
		})
	}
}

func TestResolverPartialDNSResponses(t *testing.T) {
	const success, noData, servfail, timeout, nameError = 0, 1, 2, 3, 4
	for _, tc := range []struct {
		name    string
		a, aaaa int
		want    []string
	}{
		{"both_success", success, success, []string{"192.0.2.7", "2001:db8::7"}},
		{"aaaa_nodata", success, noData, []string{"192.0.2.7"}},
		{"aaaa_servfail", success, servfail, []string{"192.0.2.7"}},
		{"a_servfail", servfail, success, []string{"2001:db8::7"}},
		{"aaaa_timeout", success, timeout, []string{"192.0.2.7"}},
		{"a_timeout", timeout, success, []string{"2001:db8::7"}},
		{"both_failed", servfail, servfail, nil},
		{"both_nodata", noData, noData, nil},
		{"nxdomain", nameError, nameError, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
				query := request.Question[0]
				mode := tc.a
				if query.Qtype == mdns.TypeAAAA {
					mode = tc.aaaa
				}
				if mode == timeout {
					return
				}
				response := new(mdns.Msg)
				response.SetReply(request)
				switch mode {
				case success:
					if query.Qtype == mdns.TypeA {
						response.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: query.Name, Rrtype: query.Qtype, Class: mdns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.7")}}
					} else {
						response.Answer = []mdns.RR{&mdns.AAAA{Hdr: mdns.RR_Header{Name: query.Name, Rrtype: query.Qtype, Class: mdns.ClassINET, Ttl: 20}, AAAA: net.ParseIP("2001:db8::7")}}
					}
				case servfail:
					response.Rcode = mdns.RcodeServerFailure
				case nameError:
					response.Rcode = mdns.RcodeNameError
				}
				if err := w.WriteMsg(response); err != nil {
					t.Errorf("write DNS response: %v", err)
				}
			})}
			go func() { _ = server.ActivateAndServe() }()
			t.Cleanup(func() { _ = server.Shutdown() })
			resolver, err := New(t.Context(), Options{DNSServers: []string{packet.LocalAddr().String()}, LookupTimeout: 200 * time.Millisecond}, nil)
			if err != nil {
				t.Fatal(err)
			}
			resolver.HandleAdd("example.com")
			eventuallyDNS(t, func() bool {
				resolver.mu.RLock()
				defer resolver.mu.RUnlock()
				item := resolver.entries["example.com"]
				return item.published && item.families[0].queried && item.families[1].queried && !item.families[0].resolving && !item.families[1].resolving
			}, "both family queries completed")
			result := resolver.Results().GetKey("example.com")
			var got []string
			for _, address := range result.Addresses {
				got = append(got, address.String())
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("addresses=%v, want %v", got, tc.want)
			}
			if (result.IPv4Error != "") != (tc.a == servfail || tc.a == timeout) ||
				(result.IPv6Error != "") != (tc.aaaa == servfail || tc.aaaa == timeout) {
				t.Fatalf("wrong failure status: %+v", result)
			}
			if result.IPv4NameError != (tc.a == nameError) || result.IPv6NameError != (tc.aaaa == nameError) {
				t.Fatalf("NXDOMAIN and NODATA were conflated: %+v", result)
			}
		})
	}
}

func TestResolverPublishesBeforeOtherFamilyCompletes(t *testing.T) {
	for _, slowType := range queryTypes {
		t.Run(mdns.TypeToString[slowType], func(t *testing.T) {
			release := make(chan struct{})
			var fastCalls atomic.Int32
			resolver, err := New(t.Context(), Options{LookupTimeout: 5 * time.Second}, func(ctx context.Context, _ string, queryType uint16) (LookupResult, error) {
				if queryType == slowType {
					select {
					case <-release:
					case <-ctx.Done():
					}
					return LookupResult{}, fmt.Errorf("temporary failure")
				}
				address := "192.0.2.7"
				if queryType == mdns.TypeAAAA {
					address = "2001:db8::7"
				}
				fastCalls.Add(1)
				return LookupResult{Addresses: []netip.Addr{netip.MustParseAddr(address)}, TTL: time.Second}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			resolver.HandleAdd("example.com")
			eventuallyDNS(t, func() bool {
				result := resolver.Results().GetKey("example.com")
				return result != nil && len(result.Addresses) == 1
			}, "fast family published while slow family is blocked")
			deadline := time.Now().Add(2 * time.Second)
			for fastCalls.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if fastCalls.Load() < 2 {
				t.Fatal("slow family blocked short-TTL refresh of the successful family")
			}
			close(release)
			eventuallyDNS(t, func() bool {
				result := resolver.Results().GetKey("example.com")
				return len(result.Addresses) == 1 && (result.IPv4Error != "" || result.IPv6Error != "")
			}, "failure recorded without losing fast family")
		})
	}
}

func TestResolverFamilyCacheRefreshExpiryAndRecovery(t *testing.T) {
	host := "example.com"
	item := &entry{hostname: host, refs: 1, index: -1}
	resolver := &Resolver{
		options: Options{RefreshInterval: time.Minute},
		entries: map[string]*entry{host: item},
		results: krt.NewStaticCollection[Result](nil, nil),
		wake:    make(chan struct{}, 1), jobs: make(chan lookupJob, 1),
	}
	answer := func(ip string) LookupResult {
		return LookupResult{Addresses: []netip.Addr{netip.MustParseAddr(ip)}, TTL: time.Hour}
	}
	check := func(want ...string) {
		t.Helper()
		var got []string
		for _, address := range resolver.Results().GetKey(host).Addresses {
			got = append(got, address.String())
		}
		if !slices.Equal(got, want) {
			t.Fatalf("addresses=%v, want %v", got, want)
		}
	}
	resolver.applyAnswer(item, 0, answer("192.0.2.1"), nil, time.Now())
	resolver.applyAnswer(item, 1, answer("2001:db8::1"), nil, time.Now())
	v6Expiry := item.families[1].expires
	resolver.applyAnswer(item, 0, answer("192.0.2.2"), nil, time.Now())
	resolver.applyAnswer(item, 1, LookupResult{}, fmt.Errorf("SERVFAIL"), time.Now())
	check("192.0.2.2", "2001:db8::1")
	if !item.families[1].expires.Equal(v6Expiry) {
		t.Fatal("partial refresh extended IPv6 lifetime")
	}

	// Expiry must be published even with the refresh worker queued or blocked.
	item.families[1].resolving = true
	item.families[1].expires = time.Now().Add(-time.Second)
	resolver.scheduleLocked(item)
	resolver.dispatchDue()
	check("192.0.2.2")
	resolver.applyAnswer(item, 1, LookupResult{}, fmt.Errorf("SERVFAIL"), time.Now())
	check("192.0.2.2")
	if !item.families[1].expires.IsZero() {
		t.Fatal("failure renewed expired cache")
	}

	resolver.applyAnswer(item, 1, answer("2001:db8::2"), nil, time.Now())
	check("192.0.2.2", "2001:db8::2")
	if resolver.Results().GetKey(host).IPv6Error != "" {
		t.Fatal("recovery retained error state")
	}
	resolver.applyAnswer(item, 1, LookupResult{TTL: time.Minute}, nil, time.Now())
	check("192.0.2.2") // NODATA immediately replaces the old IPv6 RRset.
	resolver.applyAnswer(item, 0, LookupResult{TTL: time.Minute, NameError: true}, nil, time.Now())
	check()
	if !resolver.Results().GetKey(host).IPv4NameError {
		t.Fatal("NXDOMAIN status missing")
	}

	zeroTTL := answer("192.0.2.3")
	zeroTTL.TTL = 0
	resolver.applyAnswer(item, 0, zeroTTL, nil, time.Now())
	check() // Zero-TTL data must not become a persistent allow rule.
}
