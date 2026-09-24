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
// Package tokencache provides thread-safe LRU caches for credentials obtained
// from the credential provider: API-key tokens (Cache) and STS triplets
// (STSCache). Both share one mechanism — an LRU of values with absolute
// expirations (ttlCache) — and differ only in how the expiration is derived:
// Cache applies a fallback TTL per entry, STSCache the provider's expiration
// timestamp minus a safety margin. The LRU backing uses
// github.com/hashicorp/golang-lru/v2.
package tokencache

import "time"

// DefaultMaxSize is the capacity used when none is specified.
const DefaultMaxSize = 100000

// Cache is a thread-safe LRU cache for tokens with configurable TTL and
// capacity.
type Cache struct {
	store *ttlCache[string]
	// ttl is the fallback time-to-live for entries stored without an
	// explicit one; a non-positive value disables caching.
	ttl time.Duration
}

// NewCache creates a new token cache with the given fallback TTL and max size.
// A non-positive ttl disables caching without a per-entry TTL. A non-positive
// maxSize uses DefaultMaxSize, which keeps the LRU capacity valid.
func NewCache(ttl time.Duration, maxSize int) *Cache {
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	return &Cache{
		store: newTTLCache[string](maxSize),
		ttl:   ttl,
	}
}

// SetClock replaces the cache's time source. For tests.
func (c *Cache) SetClock(now func() time.Time) {
	c.store.SetClock(now)
}

// Get retrieves a token from the cache by credentialProviderName and resourceID.
// Returns the token and true if found and not expired, or ("", false) otherwise.
// On a successful get, the entry is moved to the front of the LRU list.
func (c *Cache) Get(credentialProviderName, resourceID string) (string, bool) {
	return c.store.Get(credentialProviderName, resourceID)
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
	if ttl <= 0 {
		ttl = c.ttl
	}
	c.store.SetWithTTL(credentialProviderName, resourceID, token, ttl)
}

// Delete removes an entry from the cache.
func (c *Cache) Delete(credentialProviderName, resourceID string) {
	c.store.Delete(credentialProviderName, resourceID)
}

// Len returns the current number of entries in the cache.
func (c *Cache) Len() int {
	return c.store.Len()
}
