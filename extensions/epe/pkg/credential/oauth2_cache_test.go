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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential/tokencache"
)

func TestOAuth2CacheRequiresServicePermission(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cacheTTL  *int64
		tokenTTL  int64
		status    string
		httpCode  int
		token     string
		finalErr  bool
		wantCalls int32
	}{
		{"positive", new(int64(10)), 60, OAuth2StatusReady, 200, "token", false, 1},
		{"zero", new(int64(0)), 60, OAuth2StatusReady, 200, "token", false, 2},
		{"missing", nil, 60, OAuth2StatusReady, 200, "token", false, 2},
		{"negative", new(int64(-1)), 60, OAuth2StatusReady, 200, "token", false, 2},
		{"unknown token lifetime", new(int64(10)), 0, OAuth2StatusReady, 200, "token", false, 2},
		{"pending", new(int64(10)), 60, OAuth2StatusInProgress, 200, "token", false, 2},
		{"transport failure", new(int64(10)), 60, OAuth2StatusReady, 503, "token", false, 2},
		{"final OAuth error", new(int64(10)), 60, OAuth2StatusReady, 200, "token", true, 2},
		{"invalid bearer", new(int64(10)), 60, OAuth2StatusReady, 200, "bad token", false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body := map[string]any{
					"status":                      tc.status,
					"accessToken":                 tc.token,
					"tokenType":                   "Bearer",
					"accessTokenExpiresInSeconds": tc.tokenTTL,
				}
				if tc.cacheTTL != nil {
					body["cacheExpiresInSeconds"] = *tc.cacheTTL
				}
				if tc.finalErr {
					body["outcome"] = map[string]any{"oauth2Error": map[string]any{"errorCode": "invalid_token"}}
				}
				w.WriteHeader(tc.httpCode)
				if err := json.NewEncoder(w).Encode(body); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			// An API-key fallback must not turn OAuth zero/missing TTL into caching.
			client := NewClient(server.URL, server.Client(), tokencache.NewCache(time.Hour, 10), nil)
			client.oauth2Cache.now = func() time.Time { return time.Unix(1000, 0) }
			request := OAuth2Request{
				Operation:              OAuth2OperationResource,
				CredentialProviderName: "provider",
				ResourceID:             "sandbox",
			}
			for range 2 {
				if _, err := client.CallOAuth2(t.Context(), "caller", request); err != nil {
					t.Fatal(err)
				}
			}
			if calls.Load() != tc.wantCalls {
				t.Fatalf("Identity calls=%d, want %d", calls.Load(), tc.wantCalls)
			}
		})
	}
}

func TestOAuth2CacheAbsoluteDeadlines(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cacheTTL int64
		tokenTTL int64
	}{
		{"service TTL", 3, 10},
		{"token lifetime ceiling", 20, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			var elapsed atomic.Int64
			var fail atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if fail.Load() {
					w.WriteHeader(http.StatusServiceUnavailable)
					if _, err := io.WriteString(w, `{"status":"Failed"}`); err != nil {
						t.Error(err)
					}
					return
				}
				if err := json.NewEncoder(w).Encode(OAuth2Response{
					Status:                      OAuth2StatusReady,
					AccessToken:                 "token",
					TokenType:                   "Bearer",
					AccessTokenExpiresInSeconds: tc.tokenTTL,
					CacheExpiresInSeconds:       tc.cacheTTL,
					Scope:                       new("doc.read"),
				}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client := NewClient(server.URL, server.Client(), nil, nil)
			client.oauth2Cache.now = func() time.Time { return time.Unix(1000, 0).Add(time.Duration(elapsed.Load())) }
			request := OAuth2Request{
				Operation:              OAuth2OperationResource,
				CredentialProviderName: "provider",
				ResourceID:             "sandbox",
			}
			if _, err := client.CallOAuth2(t.Context(), "caller", request); err != nil {
				t.Fatal(err)
			}
			elapsed.Store(int64(2 * time.Second))
			result, err := client.CallOAuth2(t.Context(), "caller", request)
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 || result.AccessTokenExpiresInSeconds != tc.tokenTTL-2 ||
				result.CacheExpiresInSeconds != min(tc.cacheTTL, tc.tokenTTL)-2 ||
				result.Scope == nil || *result.Scope != "doc.read" {
				t.Fatalf("cache hit: calls=%d, response=%+v", calls.Load(), result)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := client.CallOAuth2(ctx, "caller", request); !errors.Is(err, context.Canceled) {
				t.Fatalf("cached request ignored cancellation: %v", err)
			}
			// Hitting the cache did not restart either deadline. Never serve stale on error.
			elapsed.Store(min(tc.cacheTTL, tc.tokenTTL) * int64(time.Second))
			fail.Store(true)
			for range 2 {
				result, err := client.CallOAuth2(t.Context(), "caller", request)
				if err != nil || result.HTTPStatus != 503 || result.AccessToken != "" {
					t.Fatalf("expired cache fallback: response=%+v, err=%v", result, err)
				}
			}
			if calls.Load() != 3 {
				t.Fatalf("expiry/failure calls=%d, want 3", calls.Load())
			}
		})
	}
}

func TestOAuth2CacheNetworkTimeConsumesTTL(t *testing.T) {
	var calls atomic.Int32
	var elapsed atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		elapsed.Add(int64(2 * time.Second))
		if _, err := io.WriteString(
			w,
			`{"status":"Ready","accessToken":"token","tokenType":"Bearer","accessTokenExpiresInSeconds":60,"cacheExpiresInSeconds":1}`,
		); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL, server.Client(), nil, nil)
	client.oauth2Cache.now = func() time.Time { return time.Unix(1000, 0).Add(time.Duration(elapsed.Load())) }
	request := OAuth2Request{
		Operation:              OAuth2OperationResource,
		CredentialProviderName: "provider",
		ResourceID:             "sandbox",
	}
	for range 2 {
		if _, err := client.CallOAuth2(t.Context(), "caller", request); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("RPC latency extended TTL: calls=%d", calls.Load())
	}
}

func TestOAuth2CacheIdentityAndBindingIsolation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if err := json.NewEncoder(w).Encode(OAuth2Response{
			Status:                      OAuth2StatusReady,
			AccessToken:                 fmt.Sprintf("token-%d", n),
			TokenType:                   "Bearer",
			AccessTokenExpiresInSeconds: 60,
			CacheExpiresInSeconds:       10,
		}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL, server.Client(), nil, nil)
	for i, tc := range []struct {
		caller   string
		provider string
		resource string
		params   map[string]string
	}{
		{"caller", "provider", "sandbox", nil},
		{"other-caller", "provider", "sandbox", nil},
		{"caller", "other-provider", "sandbox", nil},
		{"caller", "provider", "other-sandbox", nil},
		{"caller", "provider", "sandbox", map[string]string{"scope": ""}},
		{"caller", "provider", "sandbox", map[string]string{"scope": "doc.read"}},
		{"caller", "provider", "sandbox", map[string]string{"scope": "doc.write"}},
	} {
		request := OAuth2Request{
			Operation:              OAuth2OperationResource,
			CredentialProviderName: tc.provider,
			ResourceID:             tc.resource,
			Parameters:             tc.params,
		}
		for range 2 {
			result, err := client.CallOAuth2(t.Context(), tc.caller, request)
			if err != nil {
				t.Fatal(err)
			}
			if result.AccessToken != fmt.Sprintf("token-%d", i+1) {
				t.Fatalf("credential crossed a cache boundary: %+v", result)
			}
		}
	}
	// Replacing a provider client does not inherit the old version's credentials.
	replacement := NewClient(server.URL, server.Client(), nil, nil)
	request := OAuth2Request{
		Operation:              OAuth2OperationResource,
		CredentialProviderName: "provider",
		ResourceID:             "sandbox",
	}
	if _, err := replacement.CallOAuth2(t.Context(), "caller", request); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 8 {
		t.Fatalf("isolated Identity calls=%d, want 8", calls.Load())
	}
}

func TestOAuth2SessionOperationsInvalidateResourceCache(t *testing.T) {
	for _, tc := range []struct {
		operation string
		grantType string
	}{
		{OAuth2OperationDeviceAuthorization, ""},
		{OAuth2OperationToken, OAuth2GrantDeviceCode},
		{OAuth2OperationToken, OAuth2GrantRefreshToken},
	} {
		t.Run(tc.operation+tc.grantType, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if _, err := io.WriteString(
					w,
					`{"status":"Ready","accessToken":"token","tokenType":"Bearer","accessTokenExpiresInSeconds":60,"cacheExpiresInSeconds":10}`,
				); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client := NewClient(server.URL, server.Client(), nil, nil)
			bindings := []OAuth2Request{
				{Operation: OAuth2OperationResource, CredentialProviderName: "provider", ResourceID: "sandbox"},
				{
					Operation:              OAuth2OperationResource,
					CredentialProviderName: "provider",
					ResourceID:             "sandbox",
					Parameters:             map[string]string{"scope": "doc.read"},
				},
				{Operation: OAuth2OperationResource, CredentialProviderName: "provider", ResourceID: "other-sandbox"},
			}
			for _, binding := range bindings {
				if _, err := client.CallOAuth2(t.Context(), "caller", binding); err != nil {
					t.Fatal(err)
				}
			}
			request := bindings[0]
			request.Operation, request.GrantType = tc.operation, tc.grantType
			for range 2 {
				if _, err := client.CallOAuth2(t.Context(), "caller", request); err != nil {
					t.Fatal(err)
				}
			}
			if calls.Load() != 5 {
				t.Fatalf("session/Token RPC was cached: calls=%d", calls.Load())
			}
			for _, binding := range bindings {
				if _, err := client.CallOAuth2(t.Context(), "caller", binding); err != nil {
					t.Fatal(err)
				}
			}
			if calls.Load() != 7 {
				t.Fatalf("scope invalidation crossed bindings or missed one: calls=%d", calls.Load())
			}
		})
	}
}

func TestOAuth2CacheConcurrentHitsAndCapacity(t *testing.T) {
	cache := newOAuth2Cache(2)
	startedAt := time.Unix(1000, 0)
	cache.now = func() time.Time { return startedAt }
	response := OAuth2Response{
		HTTPStatus:                  200,
		Status:                      OAuth2StatusReady,
		AccessToken:                 "token",
		TokenType:                   "Bearer",
		AccessTokenExpiresInSeconds: 60,
		CacheExpiresInSeconds:       10,
	}
	request := OAuth2Request{
		Operation:              OAuth2OperationResource,
		CredentialProviderName: "provider",
		ResourceID:             "sandbox",
	}
	cache.set("caller", request, response, startedAt, 0)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 100 {
				result, ok := cache.get("caller", request)
				if !ok || result.AccessToken != "token" || result.AccessTokenExpiresInSeconds != 60 {
					t.Error("concurrent cache hit lost credential or extended lifetime")
				}
				cache.set("caller", request, response, startedAt, 0)
			}
		})
	}
	wg.Wait()
	for _, id := range []string{"sandbox-2", "sandbox-3"} {
		next := request
		next.ResourceID = id
		cache.set("caller", next, response, startedAt, 0)
	}
	if _, ok := cache.get("caller", request); ok {
		t.Fatal("bounded cache retained the evicted oldest credential")
	}
}
