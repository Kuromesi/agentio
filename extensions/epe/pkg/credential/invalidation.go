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
package credential

import (
	"fmt"
	"time"
)

// InvalidationRequest selects one provider across all resources, metadata variants and credential types.
type InvalidationRequest struct {
	ProviderName string `json:"providerName"`
}

// InvalidationResult counts removed entries in this process, including expired
// entries not yet reaped. Zero is successful: in-flight fills are fenced too.
type InvalidationResult struct {
	APIKeyEntries int `json:"apiKeyEntries"`
	STSEntries    int `json:"stsEntries"`
	OAuth2Entries int `json:"oauth2Entries"`
}

type refreshState struct {
	inflight   int
	generation uint64
	shortUntil time.Time
}

// InvalidateCredentials synchronously invalidates this client's local caches.
// It does not fetch credentials, broadcast to other replicas, or revoke values
// already returned to in-flight requests. When configured, every call restarts
// the window during which new cache entries use the shorter TTL limit.
func (c *Client) InvalidateCredentials(req InvalidationRequest) (InvalidationResult, error) {
	if req.ProviderName == "" {
		return InvalidationResult{}, fmt.Errorf("providerName is required")
	}

	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	now := c.now()
	for name, state := range c.refresh {
		if state.inflight == 0 && !now.Before(state.shortUntil) {
			delete(c.refresh, name)
		}
	}
	state := c.refresh[req.ProviderName]
	state.generation++
	state.shortUntil = now.Add(c.invalidationWindow)
	c.refresh[req.ProviderName] = state
	var result InvalidationResult
	if c.cache != nil {
		result.APIKeyEntries = c.cache.Invalidate(req.ProviderName)
	}
	if c.stsCache != nil {
		result.STSEntries = c.stsCache.Invalidate(req.ProviderName)
	}
	result.OAuth2Entries = c.oauth2Cache.invalidateProvider(req.ProviderName)
	return result, nil
}

// beginFill is called with refreshMu held. Keep the generation alive until every
// fetch that could write against it has finished, including failed fetches.
func (c *Client) beginFill(providerName string) uint64 {
	state := c.refresh[providerName]
	state.inflight++
	c.refresh[providerName] = state
	return state.generation
}

func (c *Client) finishFill(providerName string) {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	state := c.refresh[providerName]
	state.inflight--
	if state.inflight == 0 && !c.now().Before(state.shortUntil) {
		delete(c.refresh, providerName)
	} else {
		c.refresh[providerName] = state
	}
}

// generation and maxTTL are called with refreshMu held, including across the
// final generation check and cache insertion, so invalidation cannot race a fill.
func (c *Client) generation(providerName string) uint64 {
	return c.refresh[providerName].generation
}

func (c *Client) maxTTL(providerName string) time.Duration {
	if c.invalidationWindow <= 0 || c.invalidationMaxTTL <= 0 {
		return 0
	}
	now := c.now()
	if now.Before(c.refresh[providerName].shortUntil) {
		return c.invalidationMaxTTL
	}
	return 0
}
