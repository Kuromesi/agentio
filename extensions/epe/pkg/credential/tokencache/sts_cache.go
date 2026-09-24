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

import "time"

const defaultExpirationMargin = 5 * time.Minute

// STSCacheEntry holds the STS credential triplet returned by the
// credential provider.
type STSCacheEntry struct {
	AccessKeyID     string
	AccessKeySecret string
	SecurityToken   string
}

// STSCache is a thread-safe LRU cache for STS credentials with per-entry
// expiration derived from the credential provider's expiration timestamp.
type STSCache struct {
	store *ttlCache[STSCacheEntry]
	// expirationMargin is how long before the provider's expiration the
	// entry is treated as stale.
	expirationMargin time.Duration
}

// NewSTSCache creates a new STS credential cache with the given max size.
// If maxSize is zero or negative, the default is used.
func NewSTSCache(maxSize int) *STSCache {
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	return &STSCache{
		store:            newTTLCache[STSCacheEntry](maxSize),
		expirationMargin: defaultExpirationMargin,
	}
}

// SetClock replaces the cache's time source. For tests.
func (c *STSCache) SetClock(now func() time.Time) {
	c.store.SetClock(now)
}

// Get retrieves an STS credential from the cache. Returns the entry and
// true if found and not expired, or (nil, false) otherwise. Expired
// entries are removed immediately.
func (c *STSCache) Get(credentialProviderName, resourceID string) (*STSCacheEntry, bool) {
	value, ok := c.store.Get(credentialProviderName, resourceID)
	if !ok {
		return nil, false
	}
	return &value, true
}

// SetWithExpiration adds or updates an STS credential in the cache. The
// entry expires at (expiration - expirationMargin). If the resulting
// expiry is already in the past, the entry is not cached.
func (c *STSCache) SetWithExpiration(credentialProviderName, resourceID string, entry STSCacheEntry, expiration time.Time) {
	c.store.SetIfFresh(credentialProviderName, resourceID, entry, expiration.Add(-c.expirationMargin))
}

// Delete removes an entry from the cache.
func (c *STSCache) Delete(credentialProviderName, resourceID string) {
	c.store.Delete(credentialProviderName, resourceID)
}

// Len returns the current number of entries in the cache.
func (c *STSCache) Len() int {
	return c.store.Len()
}
