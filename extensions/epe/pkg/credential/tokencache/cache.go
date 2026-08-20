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
// Package tokencache provides a thread-safe LRU cache for tokens obtained
// from the credential provider. Tokens are cached by credentialProviderName +
// resourceId and expire after the TTL supplied per entry, or the cache's
// configured TTL when none is. The LRU backing uses
// github.com/hashicorp/golang-lru/v2.
package tokencache

import (
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"istio.io/istio/pkg/env"
)

const defaultMaxSize = 100000

// Environment variables for cache configuration. Resolved once at init, as
// everywhere else in the tree; tests override the values with test.SetForTest.
var (
	// A non-positive cacheTTL is used as-is and disables caching.
	cacheTTL = env.Register("TOKEN_CACHE_TTL", 15*time.Minute,
		"Fallback time-to-live for cached credential provider API keys, used when the provider's response omits "+
			"cacheExpiresInSeconds; a non-positive value disables caching").Get()
	cacheMaxSize = env.Register("TOKEN_CACHE_MAX_SIZE", defaultMaxSize,
		"Maximum number of cached credential provider API keys; a non-positive value falls back to the default").Get()
)

// cacheKey is the composite key for a cached token.
type cacheKey struct {
	credentialProviderName string
	resourceID             string
}

// cacheEntry holds a cached token with metadata.
type cacheEntry struct {
	token     string
	expiresAt time.Time
}

// Cache is a thread-safe LRU cache for tokens with configurable TTL and capacity.
//
// A plain Mutex (not RWMutex) is intentional: every cache access — including
// Get — mutates the LRU recency order, and the underlying lru.Cache already
// serializes operations on its own internal mutex. RWMutex would only add
// per-op overhead without unlocking real read parallelism.
type Cache struct {
	mu  sync.Mutex
	lru *lru.Cache[cacheKey, cacheEntry]
	ttl time.Duration
	now func() time.Time
}

// NewCache creates a new token cache with the given fallback TTL and max size.
// A non-positive ttl resolves to cacheTTL; a non-positive maxSize to
// defaultMaxSize, which lru.New requires.
func NewCache(ttl time.Duration, maxSize int) *Cache {
	if ttl <= 0 {
		ttl = cacheTTL
	}
	if maxSize <= 0 {
		maxSize = defaultMaxSize
	}
	l, err := lru.New[cacheKey, cacheEntry](maxSize)
	if err != nil {
		// maxSize <= 0 is the only error case, already guarded above.
		panic(fmt.Sprintf("failed to create LRU cache: %v", err))
	}
	return &Cache{
		lru: l,
		ttl: ttl,
		now: time.Now,
	}
}

// SetClock replaces the cache's time source. For tests.
func (c *Cache) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// NewCacheFromEnv creates a token cache configured from environment variables.
// TOKEN_CACHE_TTL sets the fallback TTL (parsed via time.ParseDuration).
// TOKEN_CACHE_MAX_SIZE overrides the default max size.
func NewCacheFromEnv() *Cache {
	return NewCache(cacheTTL, cacheMaxSize)
}

// Get retrieves a token from the cache by credentialProviderName and resourceID.
// Returns the token and true if found and not expired, or ("", false) otherwise.
// On a successful get, the entry is moved to the front of the LRU list.
//
// The whole get / expired-check / remove sequence runs under a single write
// lock so a concurrent Set cannot have its fresh entry deleted by a stale
// expired-check from this goroutine.
func (c *Cache) Get(credentialProviderName, resourceID string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey{credentialProviderName: credentialProviderName, resourceID: resourceID}
	entry, ok := c.lru.Get(key)
	if !ok {
		return "", false
	}
	if c.now().After(entry.expiresAt) {
		c.lru.Remove(key)
		return "", false
	}
	return entry.token, true
}

// Set adds or updates a token in the cache, expiring after the cache's
// configured TTL. If the cache is at capacity, the least recently used entry
// is evicted.
func (c *Cache) Set(credentialProviderName, resourceID, token string) {
	c.SetWithTTL(credentialProviderName, resourceID, token, 0)
}

// SetWithTTL adds or updates a token that expires after ttl. A non-positive ttl
// uses the cache's configured TTL. No safety margin is subtracted.
func (c *Cache) SetWithTTL(credentialProviderName, resourceID, token string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ttl <= 0 {
		ttl = c.ttl
	}
	key := cacheKey{credentialProviderName: credentialProviderName, resourceID: resourceID}
	entry := cacheEntry{token: token, expiresAt: c.now().Add(ttl)}
	c.lru.Add(key, entry)
}

// Delete removes an entry from the cache.
func (c *Cache) Delete(credentialProviderName, resourceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey{credentialProviderName: credentialProviderName, resourceID: resourceID}
	c.lru.Remove(key)
}

// Len returns the current number of entries in the cache.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// ConfigInfo returns a human-readable string of cache configuration for logging.
// Values are the raw env input; NewCache clamps a non-positive maxSize.
func ConfigInfo() string {
	return fmt.Sprintf("fallbackTTL=%s, maxSize=%d", cacheTTL, cacheMaxSize)
}
