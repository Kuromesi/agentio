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

package credential

import (
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/openkruise/agentio/pkg/cache"
)

type oauth2CacheKey struct {
	identityToken          string
	credentialProviderName string
	resourceID             string
	scope                  string
	scopeSet               bool
}

type oauth2CacheEntry struct {
	response       OAuth2Response
	cacheExpiresAt time.Time
	tokenExpiresAt time.Time
}

// oauth2Cache belongs to one provider configuration version. The caller token
// is part of the key: a hit must not bypass Identity for a different caller.
// Unlike the API-key cache, OAuth has no fallback TTL when the service gives zero.
type oauth2Cache struct {
	mu    sync.Mutex
	store *cache.Cache[oauth2CacheKey, oauth2CacheEntry]
	now   func() time.Time
}

func newOAuth2Cache(maxSize int) *oauth2Cache {
	c := &oauth2Cache{now: time.Now}
	store, err := cache.NewBuilder[oauth2CacheKey, oauth2CacheEntry]().
		WithLRU(maxSize).
		WithClock(func() time.Time { return c.now() }).
		Build()
	if err != nil {
		panic(fmt.Sprintf("create OAuth2 cache: %v", err)) // Positive internal capacity is required.
	}
	c.store = store
	return c
}

func oauth2Key(identityToken string, request OAuth2Request) oauth2CacheKey {
	scope, scopeSet := request.Parameters["scope"]
	return oauth2CacheKey{
		identityToken:          identityToken,
		credentialProviderName: request.CredentialProviderName,
		resourceID:             request.ResourceID,
		scope:                  scope,
		scopeSet:               scopeSet,
	}
}

func (c *oauth2Cache) get(identityToken string, request OAuth2Request) (*OAuth2Response, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := oauth2Key(identityToken, request)
	entry, ok := c.store.Get(key)
	if !ok {
		return nil, false
	}
	now := c.now()
	result := entry.response
	result.AccessTokenExpiresInSeconds = int64(entry.tokenExpiresAt.Sub(now) / time.Second)
	if result.AccessTokenExpiresInSeconds <= 0 {
		c.store.Remove(key)
		return nil, false
	}
	result.CacheExpiresInSeconds = int64(entry.cacheExpiresAt.Sub(now) / time.Second)
	return &result, true
}

func (c *oauth2Cache) set(identityToken string, request OAuth2Request, result OAuth2Response, startedAt time.Time) {
	const maxLifetimeSeconds = math.MaxInt64 / int64(time.Second)
	if result.HTTPStatus != http.StatusOK || result.Status != OAuth2StatusReady ||
		result.AccessToken == "" || strings.IndexFunc(result.AccessToken, func(c rune) bool { return c < 0x21 || c == 0x7f }) >= 0 ||
		!strings.EqualFold(result.TokenType, "Bearer") ||
		(result.Outcome != nil && result.Outcome.OAuth2Error != nil) ||
		result.CacheExpiresInSeconds <= 0 || result.AccessTokenExpiresInSeconds <= 0 ||
		result.AccessTokenExpiresInSeconds > maxLifetimeSeconds {
		return
	}
	// Taking the minimum before duration conversion also bounds a very large cache TTL.
	cacheTTL := time.Duration(min(result.CacheExpiresInSeconds, result.AccessTokenExpiresInSeconds)) * time.Second
	entry := oauth2CacheEntry{
		response:       result,
		cacheExpiresAt: startedAt.Add(cacheTTL),
		tokenExpiresAt: startedAt.Add(time.Duration(result.AccessTokenExpiresInSeconds) * time.Second),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store.SetWithExpiration(oauth2Key(identityToken, request), entry, entry.cacheExpiresAt)
}

// invalidate clears all scope and caller variants after a session/Token RPC.
// Changes made outside this client remain visible within the server's cache TTL.
func (c *oauth2Cache) invalidate(request OAuth2Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, key := range c.store.Keys() {
		if key.credentialProviderName == request.CredentialProviderName && key.resourceID == request.ResourceID {
			c.store.Remove(key)
		}
	}
}
