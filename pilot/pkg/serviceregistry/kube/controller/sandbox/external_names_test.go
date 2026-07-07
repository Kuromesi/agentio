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

package sandbox

import (
	"container/heap"
	"testing"
	"time"
)

func newTestExternalNamesController() *externalNamesController {
	// Use a single fake DNS server so the controller doesn't try to read
	// /etc/resolv.conf in environments where it may not exist.
	return newExternalServiceController(externalNamesControllerOptions{
		dnsServers: []string{"127.0.0.1:65535"},
	})
}

func TestStableJitter_ZeroMax(t *testing.T) {
	if got := stableJitter("foo", 0); got != 0 {
		t.Errorf("expected 0 jitter when max=0, got %v", got)
	}
	if got := stableJitter("foo", -time.Second); got != 0 {
		t.Errorf("expected 0 jitter when max<0, got %v", got)
	}
}

func TestStableJitter_Deterministic(t *testing.T) {
	a := stableJitter("example.com", time.Second)
	b := stableJitter("example.com", time.Second)
	if a != b {
		t.Errorf("expected deterministic jitter for same key, got %v vs %v", a, b)
	}
	// Different keys should typically differ; if not, the sha256-based jitter
	// is degenerate. Pick keys known to produce different sums.
	c := stableJitter("other.com", time.Second)
	if a == c {
		t.Errorf("expected different jitter for different keys (degenerate hash?), got %v == %v", a, c)
	}
}

func TestStableJitter_WithinBound(t *testing.T) {
	max := 500 * time.Millisecond
	for _, k := range []string{"a", "b", "c", "long.host.example.com"} {
		got := stableJitter(k, max)
		if got < 0 || got >= max {
			t.Errorf("jitter for %q out of [0, %v): %v", k, max, got)
		}
	}
}

func TestRefreshInterval(t *testing.T) {
	cases := []struct {
		ttl  uint32
		want time.Duration
	}{
		// Below 10s floor: floored to 10s then trimmed by 5s.
		{ttl: 0, want: 5 * time.Second},
		{ttl: 5, want: 5 * time.Second},
		// 10s: floored to 10s, minus 5s.
		{ttl: 10, want: 5 * time.Second},
		// > 10s: minus 5s.
		{ttl: 60, want: 55 * time.Second},
		{ttl: 3600, want: 3595 * time.Second},
	}
	for _, tc := range cases {
		if got := refreshInterval(tc.ttl); got != tc.want {
			t.Errorf("refreshInterval(%d): expected %v, got %v", tc.ttl, tc.want, got)
		}
	}
}

func TestComputeNextRefresh_DeterministicPerHostname(t *testing.T) {
	// Same hostname/ttl → same jitter → same delta from now (modulo the clock
	// shift between the two calls, which we bound).
	t1 := computeNextRefresh("example.com", 60)
	t2 := computeNextRefresh("example.com", 60)
	delta := t2.Sub(t1)
	if delta > 50*time.Millisecond || delta < -50*time.Millisecond {
		t.Errorf("expected ~equal refresh times for same hostname, got delta=%v", delta)
	}
}

func TestEntryHeap_OrderingByNextRefresh(t *testing.T) {
	now := time.Now()
	a := &entry{index: -1, resolveResult: resolveResult{hostname: "a"}, nextRefresh: now.Add(2 * time.Second)}
	b := &entry{index: -1, resolveResult: resolveResult{hostname: "b"}, nextRefresh: now.Add(1 * time.Second)}
	c := &entry{index: -1, resolveResult: resolveResult{hostname: "c"}, nextRefresh: now.Add(3 * time.Second)}

	h := entryHeap{}
	heap.Init(&h)
	heap.Push(&h, a)
	heap.Push(&h, b)
	heap.Push(&h, c)

	wantOrder := []string{"b", "a", "c"}
	for i := 0; h.Len() > 0; i++ {
		top := heap.Pop(&h).(*entry)
		if top.hostname != wantOrder[i] {
			t.Errorf("at pop %d: expected %s, got %s", i, wantOrder[i], top.hostname)
		}
	}
}

func TestOnAddOnDelete_RefCounting(t *testing.T) {
	c := newTestExternalNamesController()

	c.onAdd("example.com")
	if e, ok := c.records["example.com"]; !ok || e.refs != 1 {
		t.Fatalf("expected refs=1 after first add, got %+v", e)
	}
	if !c.records["example.com"].inHeap {
		t.Error("expected entry to be pushed onto heap after add")
	}

	c.onAdd("example.com")
	if c.records["example.com"].refs != 2 {
		t.Errorf("expected refs=2 after second add, got %d", c.records["example.com"].refs)
	}

	// First delete only decrements; entry must remain.
	c.onDelete("example.com")
	if e, ok := c.records["example.com"]; !ok || e.refs != 1 {
		t.Errorf("expected entry to remain with refs=1 after first delete, got %+v", e)
	}

	// Second delete drops it.
	c.onDelete("example.com")
	if _, ok := c.records["example.com"]; ok {
		t.Errorf("expected entry to be removed after refs reach zero")
	}
}

func TestOnDelete_NonExistentIsNoop(t *testing.T) {
	c := newTestExternalNamesController()
	// Should not panic.
	c.onDelete("never-added.example")
	if len(c.records) != 0 {
		t.Errorf("expected empty records, got %d", len(c.records))
	}
}

func TestDispatchDueEntries_ReturnsWaitForFutureTop(t *testing.T) {
	c := newTestExternalNamesController()

	// Add an entry then push it back so nextRefresh is far in the future.
	c.onAdd("future.example")
	e := c.records["future.example"]
	heap.Remove(&c.heap, e.index)
	e.nextRefresh = time.Now().Add(time.Hour)
	c.pushOrFix(e)

	wait := c.dispatchDueEntries()
	// Wait should be roughly an hour (within 10s).
	if wait < 50*time.Minute || wait > 65*time.Minute {
		t.Errorf("expected ~1h wait, got %v", wait)
	}
}

func TestDispatchDueEntries_EmptyHeapReturnsHour(t *testing.T) {
	c := newTestExternalNamesController()
	if got := c.dispatchDueEntries(); got != time.Hour {
		t.Errorf("expected 1h fallback when heap empty, got %v", got)
	}
}

func TestOnResolveDone_UpdatesAddressesAndReschedules(t *testing.T) {
	c := newTestExternalNamesController()
	c.onAdd("example.com")
	e := c.records["example.com"]
	e.resolving = true // simulate worker dispatched

	before := e.nextRefresh
	c.onResolveDone(resolveResult{
		hostname:  "example.com",
		addresses: []string{"203.0.113.1"},
		ttl:       60,
	})
	if e.resolving {
		t.Error("resolving flag should be cleared after onResolveDone")
	}
	if len(e.addresses) != 1 || e.addresses[0] != "203.0.113.1" {
		t.Errorf("expected addresses=[203.0.113.1], got %+v", e.addresses)
	}
	if !e.nextRefresh.After(before) {
		t.Errorf("expected nextRefresh advanced, before=%v after=%v", before, e.nextRefresh)
	}
}

func TestOnResolveDone_FailedKeepsPreviousAddresses(t *testing.T) {
	c := newTestExternalNamesController()
	c.onAdd("example.com")
	e := c.records["example.com"]
	e.resolving = true
	e.addresses = []string{"203.0.113.99"} // previously known

	c.onResolveDone(resolveResult{
		hostname: "example.com",
		ttl:      60,
		failed:   true,
	})
	if len(e.addresses) != 1 || e.addresses[0] != "203.0.113.99" {
		t.Errorf("failed resolution must preserve previous addresses, got %+v", e.addresses)
	}
}

func TestOnResolveDone_UnknownHostnameIsNoop(t *testing.T) {
	c := newTestExternalNamesController()
	// Should not panic when the hostname is not registered.
	c.onResolveDone(resolveResult{hostname: "stale.example", addresses: []string{"1.2.3.4"}, ttl: 60})
}

func TestExternalName_ResourceName(t *testing.T) {
	e := ExternalName{Hostname: "example.com"}
	if e.ResourceName() != "example.com" {
		t.Errorf("expected ResourceName()=example.com, got %s", e.ResourceName())
	}
}
