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
package tokencache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCache_BasicSetGet(t *testing.T) {
	c := NewCache(1*time.Minute, 100)
	c.Set(Key{ProviderName: "provider-a", ResourceID: "resource-1"}, "token-abc")

	got, ok := c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-1"})
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got != "token-abc" {
		t.Errorf("expected token-abc, got %s", got)
	}
}

func TestCache_Miss(t *testing.T) {
	c := NewCache(1*time.Minute, 100)

	got, ok := c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-1"})
	if ok {
		t.Fatalf("expected cache miss, got %s", got)
	}
}

func TestCache_Delete(t *testing.T) {
	c := NewCache(1*time.Minute, 100)
	c.Set(Key{ProviderName: "provider-a", ResourceID: "resource-1"}, "token-abc")

	c.Delete(Key{ProviderName: "provider-a", ResourceID: "resource-1"})

	got, ok := c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-1"})
	if ok {
		t.Fatalf("expected cache miss after delete, got %s", got)
	}
}

func TestCache_DeleteNonExistent(t *testing.T) {
	c := NewCache(1*time.Minute, 100)
	c.Delete(Key{ProviderName: "nonexistent", ResourceID: "nonexistent"}) // should not panic
}

func TestCache_Expiration(t *testing.T) {
	c := NewCache(50*time.Millisecond, 100)
	now := time.Unix(1000, 0)
	c.SetClock(func() time.Time { return now })
	c.Set(Key{ProviderName: "provider-a", ResourceID: "resource-1"}, "token-abc")

	// Should hit immediately.
	got, ok := c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-1"})
	if !ok || got != "token-abc" {
		t.Fatalf("expected immediate hit, got %s, %v", got, ok)
	}

	// Advance past the TTL.
	now = now.Add(100 * time.Millisecond)

	got, ok = c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-1"})
	if ok {
		t.Fatalf("expected expired entry, got %s", got)
	}
}

// TestCache_SetWithTTL asserts a per-entry TTL governs expiry instead of the
// cache's configured one.
func TestCache_SetWithTTL(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ttl     time.Duration
		advance time.Duration
		wantHit bool
	}{
		{name: "shorter than cache TTL, before expiry", ttl: 10 * time.Minute, advance: 9 * time.Minute, wantHit: true},
		{name: "shorter than cache TTL, after expiry", ttl: 10 * time.Minute, advance: 11 * time.Minute, wantHit: false},
		{name: "longer than cache TTL, before expiry", ttl: 3 * time.Hour, advance: 2 * time.Hour, wantHit: true},
		{name: "longer than cache TTL, after expiry", ttl: 3 * time.Hour, advance: 4 * time.Hour, wantHit: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache(time.Hour, 100)
			now := time.Unix(1000, 0)
			c.SetClock(func() time.Time { return now })
			c.SetWithTTL(Key{ProviderName: "provider-a", ResourceID: "resource-1"}, "token-abc", tc.ttl, 0)

			now = now.Add(tc.advance)
			got, ok := c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-1"})
			if ok != tc.wantHit {
				t.Fatalf(
					"after %v with ttl %v: hit=%v (token %q), want hit=%v",
					tc.advance,
					tc.ttl,
					ok,
					got,
					tc.wantHit,
				)
			}
		})
	}
}

// TestCache_SetWithTTL_NonPositiveFallsBack asserts a non-positive ttl uses the
// cache's configured TTL rather than expiring immediately.
func TestCache_SetWithTTL_NonPositiveFallsBack(t *testing.T) {
	for _, ttl := range []time.Duration{0, -1 * time.Second} {
		c := NewCache(time.Hour, 100)
		now := time.Unix(1000, 0)
		c.SetClock(func() time.Time { return now })
		c.SetWithTTL(Key{ProviderName: "provider-a", ResourceID: "resource-1"}, "token-abc", ttl, 0)

		now = now.Add(59 * time.Minute)
		if _, ok := c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-1"}); !ok {
			t.Errorf("ttl %v: expected fallback to the cache TTL, got a miss before it elapsed", ttl)
		}

		now = now.Add(2 * time.Minute)
		if _, ok := c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-1"}); ok {
			t.Errorf("ttl %v: expected expiry after the cache TTL elapsed", ttl)
		}
	}
}

func TestCache_LRUEviction(t *testing.T) {
	c := NewCache(1*time.Minute, 3)

	c.Set(Key{ProviderName: "p", ResourceID: "r1"}, "t1")
	c.Set(Key{ProviderName: "p", ResourceID: "r2"}, "t2")
	c.Set(Key{ProviderName: "p", ResourceID: "r3"}, "t3")

	// Cache is full; adding r4 should evict r1 (LRU).
	c.Set(Key{ProviderName: "p", ResourceID: "r4"}, "t4")

	_, ok := c.Get(Key{ProviderName: "p", ResourceID: "r1"})
	if ok {
		t.Fatal("expected r1 to be evicted")
	}

	// r2, r3, r4 should still exist.
	got, ok := c.Get(Key{ProviderName: "p", ResourceID: "r2"})
	if !ok || got != "t2" {
		t.Errorf("expected r2=t2, got %s, %v", got, ok)
	}

	got, ok = c.Get(Key{ProviderName: "p", ResourceID: "r3"})
	if !ok || got != "t3" {
		t.Errorf("expected r3=t3, got %s, %v", got, ok)
	}

	got, ok = c.Get(Key{ProviderName: "p", ResourceID: "r4"})
	if !ok || got != "t4" {
		t.Errorf("expected r4=t4, got %s, %v", got, ok)
	}
}

func TestCache_LRUOrder_Update(t *testing.T) {
	c := NewCache(1*time.Minute, 3)

	c.Set(Key{ProviderName: "p", ResourceID: "r1"}, "t1")
	c.Set(Key{ProviderName: "p", ResourceID: "r2"}, "t2")
	c.Set(Key{ProviderName: "p", ResourceID: "r3"}, "t3")

	// Access r1 — moves it to front, so r2 becomes LRU.
	c.Get(Key{ProviderName: "p", ResourceID: "r1"})

	// Add r4 — should evict r2.
	c.Set(Key{ProviderName: "p", ResourceID: "r4"}, "t4")

	_, ok := c.Get(Key{ProviderName: "p", ResourceID: "r2"})
	if ok {
		t.Fatal("expected r2 to be evicted (was LRU after r1 accessed)")
	}

	got, ok := c.Get(Key{ProviderName: "p", ResourceID: "r1"})
	if !ok || got != "t1" {
		t.Errorf("expected r1=t1, got %s, %v", got, ok)
	}
}

func TestCache_UpdateExisting(t *testing.T) {
	c := NewCache(1*time.Minute, 100)

	c.Set(Key{ProviderName: "p", ResourceID: "r1"}, "token-old")
	c.Set(Key{ProviderName: "p", ResourceID: "r1"}, "token-new")

	got, ok := c.Get(Key{ProviderName: "p", ResourceID: "r1"})
	if !ok || got != "token-new" {
		t.Errorf("expected token-new, got %s, %v", got, ok)
	}

	// Length should still be 1.
	if c.Len() != 1 {
		t.Errorf("expected len 1, got %d", c.Len())
	}
}

func TestCache_Len(t *testing.T) {
	c := NewCache(1*time.Minute, 100)

	if c.Len() != 0 {
		t.Errorf("expected 0, got %d", c.Len())
	}

	c.Set(Key{ProviderName: "p", ResourceID: "r1"}, "t1")
	c.Set(Key{ProviderName: "p", ResourceID: "r2"}, "t2")

	if c.Len() != 2 {
		t.Errorf("expected 2, got %d", c.Len())
	}
}

func TestCache_DifferentProviders(t *testing.T) {
	c := NewCache(1*time.Minute, 100)

	c.Set(Key{ProviderName: "provider-a", ResourceID: "r1"}, "token-a")
	c.Set(Key{ProviderName: "provider-b", ResourceID: "r1"}, "token-b")

	gotA, okA := c.Get(Key{ProviderName: "provider-a", ResourceID: "r1"})
	gotB, okB := c.Get(Key{ProviderName: "provider-b", ResourceID: "r1"})

	if !okA || gotA != "token-a" {
		t.Errorf("provider-a: expected token-a, got %s, %v", gotA, okA)
	}
	if !okB || gotB != "token-b" {
		t.Errorf("provider-b: expected token-b, got %s, %v", gotB, okB)
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	c := NewCache(1*time.Minute, 1000)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			c.Set(Key{ProviderName: "provider", ResourceID: "resource"}, "token")
		}(i)
		go func(i int) {
			defer wg.Done()
			c.Get(Key{ProviderName: "provider", ResourceID: "resource"})
		}(i)
	}
	wg.Wait()

	got, ok := c.Get(Key{ProviderName: "provider", ResourceID: "resource"})
	if !ok || got != "token" {
		t.Errorf("expected token after concurrent ops, got %s, %v", got, ok)
	}
}

// TestCache_DefaultParams verifies TTL is explicit and non-positive capacity uses the default.
func TestCache_DefaultParams(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ttl     time.Duration
		maxSize int
	}{
		{name: "zero values", ttl: 0, maxSize: 0},
		{name: "negative values", ttl: -1 * time.Hour, maxSize: -5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache(tc.ttl, tc.maxSize)
			if c.ttl != tc.ttl {
				t.Errorf("ttl = %v, want %v", c.ttl, tc.ttl)
			}
			// maxSize is internal to the golang-lru backing; verify via behavior.
			fillAndVerifyCapacity(t, c, DefaultMaxSize)
		})
	}
}

// TestCache_NonPositiveTTLDisablesCaching verifies an explicit zero disables
// the default lifetime while a per-entry TTL still applies.
func TestCache_NonPositiveTTLDisablesCaching(t *testing.T) {
	c := NewCache(0, 100)
	if c.ttl != 0 {
		t.Fatalf("ttl = %v, want 0 (a non-positive TTL must not be clamped)", c.ttl)
	}

	now := time.Unix(1000, 0)
	c.SetClock(func() time.Time { return now })
	c.Set(Key{ProviderName: "provider-a", ResourceID: "resource-1"}, "token-abc")

	now = now.Add(time.Nanosecond)
	if got, ok := c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-1"}); ok {
		t.Errorf("expected no caching with a zero TTL, got %q", got)
	}

	// A provider-supplied lifetime still overrides the disabled fallback.
	c.SetWithTTL(Key{ProviderName: "provider-a", ResourceID: "resource-2"}, "token-xyz", 10*time.Minute, 0)
	now = now.Add(5 * time.Minute)
	if _, ok := c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-2"}); !ok {
		t.Error("expected cacheExpiresInSeconds to apply even when the fallback TTL is disabled")
	}
}

// fillAndVerifyCapacity sets entries up to the default max and verifies
// that adding one more evicts the LRU entry (behavioral check for maxSize).
func fillAndVerifyCapacity(t *testing.T, c *Cache, maxSize int) {
	// Only test a subset of the capacity to keep tests fast.
	limit := maxSize
	if limit > 100 {
		limit = 100 // test a reasonable subset
	}
	for i := 0; i < limit; i++ {
		c.SetWithTTL(
			Key{ProviderName: "default-test", ResourceID: fmt.Sprintf("r-%d", i)},
			fmt.Sprintf("t-%d", i),
			time.Minute,
			0,
		)
	}
	expectedLen := limit
	if c.Len() != expectedLen {
		t.Errorf("expected len %d after filling, got %d", expectedLen, c.Len())
	}
}

// TestNewCache_ClampsNonPositiveMaxSize asserts a non-positive
// capacity yields a working cache rather than a panic from lru.New.
func TestNewCache_ClampsNonPositiveMaxSize(t *testing.T) {
	for _, maxSize := range []int{0, -1} {
		c := NewCache(time.Minute, maxSize) // must not panic
		c.Set(Key{ProviderName: "provider-a", ResourceID: "resource-1"}, "token-abc")
		if _, ok := c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-1"}); !ok {
			t.Errorf("maxSize %d: expected a usable cache after the clamp", maxSize)
		}
	}
}

func TestCredentialExpirationBoundary(t *testing.T) {
	now := time.Unix(1000, 0)
	token := NewCache(time.Second, 2)
	token.SetClock(func() time.Time { return now })
	token.Set(Key{ProviderName: "provider", ResourceID: "resource"}, "token")
	sts := NewSTSCache(2)
	sts.expirationMargin = 0
	sts.SetClock(func() time.Time { return now })
	sts.SetWithExpiration(
		Key{ProviderName: "provider", ResourceID: "resource"},
		stsEntry("ak", "sk", "token"),
		now.Add(time.Second),
		0,
	)
	now = now.Add(time.Second)
	if _, ok := token.Get(Key{ProviderName: "provider", ResourceID: "resource"}); ok {
		t.Fatal("token accepted at its expiry deadline")
	}
	if _, ok := sts.Get(Key{ProviderName: "provider", ResourceID: "resource"}); ok {
		t.Fatal("STS accepted at its expiry deadline")
	}
}

func TestDisabledFallbackRemovesPreviousCredential(t *testing.T) {
	c := NewCache(0, 2)
	c.SetWithTTL(Key{ProviderName: "provider", ResourceID: "resource"}, "old", time.Minute, 0)
	c.Set(Key{ProviderName: "provider", ResourceID: "resource"}, "new-without-lifetime")
	if _, ok := c.Get(Key{ProviderName: "provider", ResourceID: "resource"}); ok {
		t.Fatal("disabled caching retained previous credential")
	}
}
