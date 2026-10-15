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

// Package cache provides concurrent value caches with expiration and optional LRU capacity limits.
package cache

import (
	"errors"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
)

// Builder configures a cache before construction. It is not safe for concurrent use.
// With methods only record settings; Build creates independent caches.
// Repeating an option replaces its previous value.
type Builder[K comparable, V any] struct {
	capacity int
	ttl      time.Duration
	now      func() time.Time
}

// NewBuilder starts with unbounded storage and no expiration.
func NewBuilder[K comparable, V any]() *Builder[K, V] {
	return &Builder[K, V]{now: time.Now}
}

// WithLRU bounds retained entries using least-recently-used eviction. Zero
// disables capacity eviction. Expired entries occupy space until read, removed or evicted.
func (b *Builder[K, V]) WithLRU(capacity int) *Builder[K, V] {
	b.capacity = capacity
	return b
}

// WithTTL sets the default lifetime from each Set. Reads do not refresh it.
// Zero disables the default expiration. SetWithExpiration overrides this setting.
func (b *Builder[K, V]) WithTTL(ttl time.Duration) *Builder[K, V] {
	b.ttl = ttl
	return b
}

// WithClock supplies a time source, primarily for tests.
// The function must be safe for concurrent use and not reenter the cache.
func (b *Builder[K, V]) WithClock(now func() time.Time) *Builder[K, V] {
	b.now = now
	return b
}

// Build validates settings and snapshots them into a new, empty cache.
func (b *Builder[K, V]) Build() (*Cache[K, V], error) {
	if b.capacity < 0 || b.ttl < 0 {
		return nil, errors.New("cache capacity and default TTL must not be negative")
	}
	if b.now == nil {
		return nil, errors.New("cache clock is required")
	}
	c := &Cache[K, V]{
		ttl: b.ttl,
		now: b.now,
	}
	if b.capacity > 0 {
		store, err := simplelru.NewLRU[K, *entry[V]](b.capacity, nil)
		if err != nil {
			return nil, err
		}
		c.lru = store
	} else {
		c.items = make(map[K]*entry[V])
	}
	return c, nil
}
