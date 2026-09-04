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
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// cacheKey is the composite key for a cached credential.
type cacheKey struct {
	credentialProviderName string
	resourceID             string
}

// entry is the internal representation stored in the LRU.
type entry[V any] struct {
	value     V
	expiresAt time.Time
}

// ttlCache is the mechanism shared by Cache and STSCache: an LRU of values
// with absolute expirations. The two public caches differ only in how the
// expiration is derived.
//
// A plain Mutex (not RWMutex) is intentional: every access — including Get —
// mutates the LRU recency order, and holding one lock across the
// get/expired-check/remove sequence keeps a concurrent Set from having its
// fresh entry deleted by a stale expired-check from another goroutine.
type ttlCache[V any] struct {
	mu  sync.Mutex
	lru *lru.Cache[cacheKey, entry[V]]
	now func() time.Time
}

// newTTLCache creates the backing LRU. maxSize must be positive; callers
// clamp before calling.
func newTTLCache[V any](maxSize int) *ttlCache[V] {
	l, err := lru.New[cacheKey, entry[V]](maxSize)
	if err != nil {
		// maxSize <= 0 is the only error case, already guarded by callers.
		panic(fmt.Sprintf("failed to create LRU cache: %v", err))
	}
	return &ttlCache[V]{lru: l, now: time.Now}
}

// SetClock replaces the cache's time source. For tests.
func (c *ttlCache[V]) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// Get returns the value for a live entry and promotes it in the LRU. Expired
// entries are removed immediately.
func (c *ttlCache[V]) Get(credentialProviderName, resourceID string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var zero V
	key := cacheKey{credentialProviderName: credentialProviderName, resourceID: resourceID}
	e, ok := c.lru.Get(key)
	if !ok {
		return zero, false
	}
	if c.now().After(e.expiresAt) {
		c.lru.Remove(key)
		return zero, false
	}
	return e.value, true
}

// SetWithTTL stores a value expiring ttl from now on the cache's clock. A
// non-positive ttl stores an entry that is already expired, which is how a
// non-positive fallback TTL disables caching.
func (c *ttlCache[V]) SetWithTTL(credentialProviderName, resourceID string, value V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey{credentialProviderName: credentialProviderName, resourceID: resourceID}
	c.lru.Add(key, entry[V]{value: value, expiresAt: c.now().Add(ttl)})
}

// SetIfFresh stores a value with an absolute expiration only while that
// expiration is still in the future, and reports whether it was stored.
func (c *ttlCache[V]) SetIfFresh(credentialProviderName, resourceID string, value V, expiresAt time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.now().After(expiresAt) {
		return false
	}
	key := cacheKey{credentialProviderName: credentialProviderName, resourceID: resourceID}
	c.lru.Add(key, entry[V]{value: value, expiresAt: expiresAt})
	return true
}

// Delete removes an entry from the cache.
func (c *ttlCache[V]) Delete(credentialProviderName, resourceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lru.Remove(cacheKey{credentialProviderName: credentialProviderName, resourceID: resourceID})
}

// Len returns the current number of entries, including ones not yet reaped.
func (c *ttlCache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
