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

package cache

import (
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
)

type entry[V any] struct {
	value     V
	expiresAt time.Time
}

func (e *entry[V]) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && !now.Before(e.expiresAt)
}

// Cache is a concurrent value cache. Values are not cloned; callers own their
// immutability or synchronization. Construct it with NewBuilder.
// Expiration is checked on reads; no background cleanup runs.
type Cache[K comparable, V any] struct {
	mu    sync.Mutex
	lru   *simplelru.LRU[K, *entry[V]] // Used only when capacity eviction is enabled.
	items map[K]*entry[V]              // Used only for unbounded storage.
	ttl   time.Duration
	now   func() time.Time
}

// Get returns a live value, promoting its LRU position without extending expiration.
// At the expiration deadline the entry is removed and the lookup misses.
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.peek(key)
	if ok {
		now := c.now()
		if e.expired(now) {
			c.remove(key)
		} else {
			if c.lru != nil {
				c.lru.Get(key)
			}
			return e.value, true
		}
	}
	var zero V
	return zero, false
}

// Set inserts or replaces a value using the default TTL from this write.
// With no default TTL it has no expiration.
func (c *Cache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	var expiresAt time.Time
	if c.ttl > 0 {
		expiresAt = now.Add(c.ttl)
	}
	c.setLocked(key, value, expiresAt)
}

// SetWithExpiration inserts or replaces a value with a deadline overriding the
// default TTL. A zero deadline disables absolute expiration for this value.
// An already expired value is rejected without replacing an existing value.
func (c *Cache[K, V]) SetWithExpiration(key K, value V, expiresAt time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !expiresAt.IsZero() && !now.Before(expiresAt) {
		return false
	}
	c.setLocked(key, value, expiresAt)
	return true
}

// setLocked publishes a value with its resolved expiration while holding mu.
func (c *Cache[K, V]) setLocked(key K, value V, expiresAt time.Time) {
	e := &entry[V]{value: value, expiresAt: expiresAt}
	if c.lru != nil {
		c.lru.Add(key, e)
	} else {
		c.items[key] = e
	}
}

// Remove deletes a value, if present.
func (c *Cache[K, V]) Remove(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remove(key)
}

// Len returns the number of retained entries, including expired entries not yet removed.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lru != nil {
		return c.lru.Len()
	}
	return len(c.items)
}

// Keys returns a snapshot of retained keys, including expired entries not yet removed.
// Ordering is unspecified; it does not promote entries.
func (c *Cache[K, V]) Keys() []K {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lru != nil {
		return c.lru.Keys()
	}
	return slices.Collect(maps.Keys(c.items))
}

// Storage helpers run under mu. simplelru supplies ordering and capacity eviction;
// the map variant avoids maintaining access order when capacity is unbounded.
func (c *Cache[K, V]) peek(key K) (*entry[V], bool) {
	if c.lru != nil {
		return c.lru.Peek(key)
	}
	e, ok := c.items[key]
	return e, ok
}

func (c *Cache[K, V]) remove(key K) {
	if c.lru != nil {
		c.lru.Remove(key)
		return
	}
	delete(c.items, key)
}
