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

	"github.com/openkruise/agentio/pkg/cache"
)

type cacheKey struct {
	credentialProviderName string
	resourceID             string
}

// ttlCache adapts provider keys and lifetime calculations to the shared cache.
// mu serializes the test clock with cache operations; no background sweep runs here.
type ttlCache[V any] struct {
	mu    sync.Mutex
	store *cache.Cache[cacheKey, V]
	now   func() time.Time
}

func newTTLCache[V any](maxSize int) *ttlCache[V] {
	c := &ttlCache[V]{now: time.Now}
	store, err := cache.NewBuilder[cacheKey, V]().
		WithLRU(maxSize).
		WithClock(func() time.Time { return c.now() }).
		Build()
	if err != nil {
		panic(fmt.Sprintf("create credential cache: %v", err))
	}
	c.store = store
	return c
}

// SetClock replaces the time source for tests.
func (c *ttlCache[V]) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// Get returns a live credential and updates its LRU position.
func (c *ttlCache[V]) Get(provider, resource string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.Get(cacheKey{credentialProviderName: provider, resourceID: resource})
}

// SetWithTTL replaces a credential, or removes it when caching is disabled.
func (c *ttlCache[V]) SetWithTTL(provider, resource string, value V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := cacheKey{credentialProviderName: provider, resourceID: resource}
	if ttl <= 0 {
		c.store.Remove(key)
		return
	}
	c.store.SetWithExpiration(key, value, c.now().Add(ttl))
}

// SetIfFresh retains a credential only until its provider-derived deadline.
func (c *ttlCache[V]) SetIfFresh(provider, resource string, value V, expiresAt time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A missing credential deadline is not an immortal credential.
	if expiresAt.IsZero() {
		return false
	}
	return c.store.SetWithExpiration(cacheKey{credentialProviderName: provider, resourceID: resource}, value, expiresAt)
}

// Delete removes a credential.
func (c *ttlCache[V]) Delete(provider, resource string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store.Remove(cacheKey{credentialProviderName: provider, resourceID: resource})
}

// Len returns retained entries, including ones not yet cleaned.
func (c *ttlCache[V]) Len() int {
	return c.store.Len()
}
