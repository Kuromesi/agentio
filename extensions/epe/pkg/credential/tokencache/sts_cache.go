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
	"os"
	"strconv"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	stsMaxSizeEnvVar        = "STS_CACHE_MAX_SIZE"
	defaultSTSMaxSize       = 100000
	defaultExpirationMargin = 5 * time.Minute
)

// STSCacheEntry holds the STS credential triplet returned by the
// credential provider.
type STSCacheEntry struct {
	AccessKeyID     string
	AccessKeySecret string
	SecurityToken   string
}

// stsCacheEntry is the internal representation stored in the LRU.
type stsCacheEntry struct {
	STSCacheEntry
	expiresAt time.Time
}

// STSCache is a thread-safe LRU cache for STS credentials with per-entry
// expiration derived from the credential provider's expiration timestamp.
//
// A plain Mutex (not RWMutex) is used for the same reason as Cache: every
// Get mutates the LRU recency order.
type STSCache struct {
	mu               sync.Mutex
	lru              *lru.Cache[cacheKey, stsCacheEntry]
	expirationMargin time.Duration
	now              func() time.Time
}

// NewSTSCache creates a new STS credential cache with the given max size.
// If maxSize is zero or negative, the default is used.
func NewSTSCache(maxSize int) *STSCache {
	if maxSize <= 0 {
		maxSize = defaultSTSMaxSize
	}
	l, err := lru.New[cacheKey, stsCacheEntry](maxSize)
	if err != nil {
		panic(fmt.Sprintf("failed to create STS LRU cache: %v", err))
	}
	return &STSCache{
		lru:              l,
		expirationMargin: defaultExpirationMargin,
		now:              time.Now,
	}
}

// SetClock replaces the cache's time source. For tests.
func (c *STSCache) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// NewSTSCacheFromEnv creates an STS cache configured from environment
// variables. STS_CACHE_MAX_SIZE overrides the default max size.
func NewSTSCacheFromEnv() *STSCache {
	maxSize := defaultSTSMaxSize
	if v := os.Getenv(stsMaxSizeEnvVar); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			maxSize = parsed
		}
	}
	return NewSTSCache(maxSize)
}

// Get retrieves an STS credential from the cache. Returns the entry and
// true if found and not expired, or (nil, false) otherwise. Expired
// entries are removed immediately.
func (c *STSCache) Get(credentialProviderName, resourceID string) (*STSCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey{credentialProviderName: credentialProviderName, resourceID: resourceID}
	entry, ok := c.lru.Get(key)
	if !ok {
		return nil, false
	}
	if c.now().After(entry.expiresAt) {
		c.lru.Remove(key)
		return nil, false
	}
	result := entry.STSCacheEntry
	return &result, true
}

// SetWithExpiration adds or updates an STS credential in the cache. The
// entry expires at (expiration - expirationMargin). If the resulting
// expiry is already in the past, the entry is not cached.
func (c *STSCache) SetWithExpiration(credentialProviderName, resourceID string, entry STSCacheEntry, expiration time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiresAt := expiration.Add(-c.expirationMargin)
	if c.now().After(expiresAt) {
		return
	}

	key := cacheKey{credentialProviderName: credentialProviderName, resourceID: resourceID}
	c.lru.Add(key, stsCacheEntry{
		STSCacheEntry: entry,
		expiresAt:     expiresAt,
	})
}

// Delete removes an entry from the cache.
func (c *STSCache) Delete(credentialProviderName, resourceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey{credentialProviderName: credentialProviderName, resourceID: resourceID}
	c.lru.Remove(key)
}

// Len returns the current number of entries in the cache.
func (c *STSCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// STSCacheConfigInfo returns a human-readable string of STS cache
// configuration for logging.
func STSCacheConfigInfo() string {
	maxSize := defaultSTSMaxSize
	if v := os.Getenv(stsMaxSizeEnvVar); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			maxSize = parsed
		}
	}
	return fmt.Sprintf("expirationMargin=%s, maxSize=%d", defaultExpirationMargin, maxSize)
}
