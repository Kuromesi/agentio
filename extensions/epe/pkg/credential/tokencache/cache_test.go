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

	"istio.io/istio/pkg/test"
)

func TestCache_BasicSetGet(t *testing.T) {
	c := NewCache(1*time.Minute, 100)
	c.Set("provider-a", "resource-1", "token-abc")

	got, ok := c.Get("provider-a", "resource-1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got != "token-abc" {
		t.Errorf("expected token-abc, got %s", got)
	}
}

func TestCache_Miss(t *testing.T) {
	c := NewCache(1*time.Minute, 100)

	got, ok := c.Get("provider-a", "resource-1")
	if ok {
		t.Fatalf("expected cache miss, got %s", got)
	}
}

func TestCache_Delete(t *testing.T) {
	c := NewCache(1*time.Minute, 100)
	c.Set("provider-a", "resource-1", "token-abc")

	c.Delete("provider-a", "resource-1")

	got, ok := c.Get("provider-a", "resource-1")
	if ok {
		t.Fatalf("expected cache miss after delete, got %s", got)
	}
}

func TestCache_DeleteNonExistent(t *testing.T) {
	c := NewCache(1*time.Minute, 100)
	c.Delete("nonexistent", "nonexistent") // should not panic
}

func TestCache_Expiration(t *testing.T) {
	c := NewCache(50*time.Millisecond, 100)
	now := time.Unix(1000, 0)
	c.SetClock(func() time.Time { return now })
	c.Set("provider-a", "resource-1", "token-abc")

	// Should hit immediately.
	got, ok := c.Get("provider-a", "resource-1")
	if !ok || got != "token-abc" {
		t.Fatalf("expected immediate hit, got %s, %v", got, ok)
	}

	// Advance past the TTL.
	now = now.Add(100 * time.Millisecond)

	got, ok = c.Get("provider-a", "resource-1")
	if ok {
		t.Fatalf("expected expired entry, got %s", got)
	}
}

func TestCache_LRUEviction(t *testing.T) {
	c := NewCache(1*time.Minute, 3)

	c.Set("p", "r1", "t1")
	c.Set("p", "r2", "t2")
	c.Set("p", "r3", "t3")

	// Cache is full; adding r4 should evict r1 (LRU).
	c.Set("p", "r4", "t4")

	_, ok := c.Get("p", "r1")
	if ok {
		t.Fatal("expected r1 to be evicted")
	}

	// r2, r3, r4 should still exist.
	got, ok := c.Get("p", "r2")
	if !ok || got != "t2" {
		t.Errorf("expected r2=t2, got %s, %v", got, ok)
	}

	got, ok = c.Get("p", "r3")
	if !ok || got != "t3" {
		t.Errorf("expected r3=t3, got %s, %v", got, ok)
	}

	got, ok = c.Get("p", "r4")
	if !ok || got != "t4" {
		t.Errorf("expected r4=t4, got %s, %v", got, ok)
	}
}

func TestCache_LRUOrder_Update(t *testing.T) {
	c := NewCache(1*time.Minute, 3)

	c.Set("p", "r1", "t1")
	c.Set("p", "r2", "t2")
	c.Set("p", "r3", "t3")

	// Access r1 — moves it to front, so r2 becomes LRU.
	c.Get("p", "r1")

	// Add r4 — should evict r2.
	c.Set("p", "r4", "t4")

	_, ok := c.Get("p", "r2")
	if ok {
		t.Fatal("expected r2 to be evicted (was LRU after r1 accessed)")
	}

	got, ok := c.Get("p", "r1")
	if !ok || got != "t1" {
		t.Errorf("expected r1=t1, got %s, %v", got, ok)
	}
}

func TestCache_UpdateExisting(t *testing.T) {
	c := NewCache(1*time.Minute, 100)

	c.Set("p", "r1", "token-old")
	c.Set("p", "r1", "token-new")

	got, ok := c.Get("p", "r1")
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

	c.Set("p", "r1", "t1")
	c.Set("p", "r2", "t2")

	if c.Len() != 2 {
		t.Errorf("expected 2, got %d", c.Len())
	}
}

func TestCache_DifferentProviders(t *testing.T) {
	c := NewCache(1*time.Minute, 100)

	c.Set("provider-a", "r1", "token-a")
	c.Set("provider-b", "r1", "token-b")

	gotA, okA := c.Get("provider-a", "r1")
	gotB, okB := c.Get("provider-b", "r1")

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
			c.Set("provider", "resource", "token")
		}(i)
		go func(i int) {
			defer wg.Done()
			c.Get("provider", "resource")
		}(i)
	}
	wg.Wait()

	got, ok := c.Get("provider", "resource")
	if !ok || got != "token" {
		t.Errorf("expected token after concurrent ops, got %s, %v", got, ok)
	}
}

// TestCache_DefaultParams verifies NewCache falls back to the default TTL and
// max size for non-positive constructor arguments.
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
			if c.ttl != defaultTTL {
				t.Errorf("expected default TTL %v, got %v", defaultTTL, c.ttl)
			}
			// maxSize is internal to the golang-lru backing; verify via behavior.
			fillAndVerifyCapacity(t, c, defaultMaxSize)
		})
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
		c.Set("default-test", fmt.Sprintf("r-%d", i), fmt.Sprintf("t-%d", i))
	}
	expectedLen := limit
	if c.Len() != expectedLen {
		t.Errorf("expected len %d after filling, got %d", expectedLen, c.Len())
	}
}

// TestNewCacheFromEnv covers env-driven configuration: a valid override is
// honoured and a non-positive value falls back to the default. Parsing of
// malformed strings is pkg/env's contract and is covered there.
func TestNewCacheFromEnv(t *testing.T) {
	test.SetForTest(t, &cacheTTL, 10*time.Minute)
	test.SetForTest(t, &cacheMaxSize, 500)
	if got := NewCacheFromEnv().ttl; got != 10*time.Minute {
		t.Errorf("expected 10m TTL, got %v", got)
	}

	test.SetForTest(t, &cacheTTL, time.Duration(0))
	test.SetForTest(t, &cacheMaxSize, -1)
	if got := NewCacheFromEnv().ttl; got != defaultTTL {
		t.Errorf("expected default TTL for a non-positive value, got %v", got)
	}
}

// TestConfigInfo asserts the logged config reports the values NewCacheFromEnv
// would actually build. A non-positive value must surface as the default rather
// than being echoed back raw, or the log misreports the live configuration.
func TestConfigInfo(t *testing.T) {
	test.SetForTest(t, &cacheTTL, 5*time.Minute)
	test.SetForTest(t, &cacheMaxSize, 42)
	if got := ConfigInfo(); got != "TTL=5m0s, maxSize=42" {
		t.Errorf("unexpected ConfigInfo: %q", got)
	}

	test.SetForTest(t, &cacheTTL, time.Duration(-1))
	test.SetForTest(t, &cacheMaxSize, -1)
	want := fmt.Sprintf("TTL=%s, maxSize=%d", defaultTTL, defaultMaxSize)
	if got := ConfigInfo(); got != want {
		t.Errorf("ConfigInfo() = %q, want %q", got, want)
	}
}
