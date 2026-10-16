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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential/tokencache"
)

func TestInvalidationCachePolicyConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		opts       []Option
		wantWindow time.Duration
		wantMaxTTL time.Duration
	}{
		{name: "defaults", wantWindow: 30 * time.Second, wantMaxTTL: 5 * time.Second},
		{name: "disabled", opts: []Option{WithInvalidationCachePolicy(0, 0)}},
		{name: "explicit", opts: []Option{WithInvalidationCachePolicy(20*time.Second, 3*time.Second)}, wantWindow: 20 * time.Second, wantMaxTTL: 3 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient("", http.DefaultClient, nil, nil, tc.opts...)
			if c.invalidationWindow != tc.wantWindow || c.invalidationMaxTTL != tc.wantMaxTTL {
				t.Fatalf("window=%s maxTTL=%s", c.invalidationWindow, c.invalidationMaxTTL)
			}
		})
	}
}

func TestInvalidateCredentialsScope(t *testing.T) {
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := json.NewEncoder(w).
			Encode(credentialResponse{ApiKey: "key", StsToken: &stsToken{AccessKeyID: "ak", AccessKeySecret: "sk", SecurityToken: "st", Expiration: time.Now().Add(time.Hour).Format(time.RFC3339)}}); err != nil {
			t.Errorf("encode credential response: %v", err)
		}
	}))
	defer provider.Close()
	c := NewClient(provider.URL, provider.Client(), tokencache.NewCache(time.Hour, 20), tokencache.NewSTSCache(20))
	for _, name := range []string{"p", "p#other"} {
		for _, resource := range []string{"r1", "r2"} {
			for _, metadata := range []map[string]any{nil, {"tenant": "a"}} {
				if _, err := c.GetTokenWithExtraMetadata(
					context.Background(),
					"access",
					resource,
					name,
					metadata,
				); err != nil {
					t.Fatal(err)
				}
				if _, err := c.GetSTSCredentialWithExtraMetadata(
					context.Background(),
					"access",
					resource,
					name,
					metadata,
				); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if calls.Load() != 16 {
		t.Fatalf("calls = %d", calls.Load())
	}
	if _, err := c.InvalidateCredentials(InvalidationRequest{}); err == nil {
		t.Fatal("empty provider must be rejected")
	}
	result, err := c.InvalidateCredentials(InvalidationRequest{ProviderName: "p"})
	if err != nil || result != (InvalidationResult{APIKeyEntries: 4, STSEntries: 4}) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err = c.GetToken(context.Background(), "access", "r1", "p#other"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 16 {
		t.Fatal("unrelated provider was invalidated")
	}
	result, err = c.InvalidateCredentials(InvalidationRequest{ProviderName: "p#other"})
	if err != nil || result != (InvalidationResult{APIKeyEntries: 4, STSEntries: 4}) {
		t.Fatalf("other provider: result=%+v err=%v", result, err)
	}
	result, err = c.InvalidateCredentials(InvalidationRequest{ProviderName: "p#other"})
	if err != nil || result != (InvalidationResult{}) {
		t.Fatalf("empty: result=%+v err=%v", result, err)
	}
}

func TestInvalidationCacheLifetime(t *testing.T) {
	for _, kind := range []string{"apiKey", "stsToken"} {
		for _, tc := range []struct {
			name          string
			invalidate    bool
			otherProvider bool
			window        time.Duration
			maxTTL        time.Duration
			elapsed       time.Duration
			baseTTL       time.Duration
			stsTTL        time.Duration
			fallback      bool
			wantTTL       time.Duration
		}{
			{name: "disabled", invalidate: true, wantTTL: time.Minute},
			{name: "zero window", invalidate: true, maxTTL: 3 * time.Second, wantTTL: time.Minute},
			{name: "zero TTL", invalidate: true, window: 20 * time.Second, wantTTL: time.Minute},
			{name: "negative window", invalidate: true, window: -time.Second, maxTTL: 3 * time.Second, wantTTL: time.Minute},
			{name: "negative TTL", invalidate: true, window: 20 * time.Second, maxTTL: -time.Second, wantTTL: time.Minute},
			{name: "no invalidation", window: 20 * time.Second, maxTTL: 3 * time.Second, wantTTL: time.Minute},
			{name: "provider window", invalidate: true, window: 20 * time.Second, maxTTL: 3 * time.Second, wantTTL: 3 * time.Second},
			{name: "unrelated provider", invalidate: true, otherProvider: true, window: 20 * time.Second, maxTTL: 3 * time.Second, wantTTL: time.Minute},
			{name: "just inside window", invalidate: true, window: 20 * time.Second, maxTTL: 3 * time.Second, elapsed: 19 * time.Second, wantTTL: 3 * time.Second},
			{name: "window ended", invalidate: true, window: 20 * time.Second, maxTTL: 3 * time.Second, elapsed: 20 * time.Second, wantTTL: time.Minute},
			{name: "do not extend shorter TTL", invalidate: true, window: 20 * time.Second, maxTTL: 3 * time.Second, baseTTL: time.Second, wantTTL: time.Second},
			{name: "provider hint without window", baseTTL: 2 * time.Second, stsTTL: time.Minute, wantTTL: 2 * time.Second},
			{name: "cap fallback TTL", invalidate: true, window: 20 * time.Second, maxTTL: 3 * time.Second, fallback: true, wantTTL: 3 * time.Second},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				now := time.Unix(1000, 0)
				if tc.baseTTL == 0 {
					tc.baseTTL = time.Minute
				}
				response := credentialResponse{ApiKey: "key", CacheExpiresInSeconds: int64(tc.baseTTL / time.Second)}
				if tc.fallback {
					response.CacheExpiresInSeconds = 0
				}
				firstFetch := now.Add(tc.elapsed)
				stsTTL := tc.stsTTL
				if stsTTL == 0 {
					stsTTL = tc.baseTTL
				}
				response.StsToken = &stsToken{
					AccessKeyID:     "ak",
					AccessKeySecret: "sk",
					SecurityToken:   "st",
					Expiration:      firstFetch.Add(5*time.Minute + stsTTL).Format(time.RFC3339),
				}
				var calls atomic.Int32
				provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if err := json.NewEncoder(w).Encode(response); err != nil {
						t.Errorf("encode credential response: %v", err)
					}
				}))
				defer provider.Close()
				cache, sts := tokencache.NewCache(time.Minute, 10), tokencache.NewSTSCache(10)
				cache.SetClock(func() time.Time { return now })
				sts.SetClock(func() time.Time { return now })
				c := NewClient(
					provider.URL,
					provider.Client(),
					cache,
					sts,
					WithInvalidationCachePolicy(tc.window, tc.maxTTL),
				)
				c.now = func() time.Time { return now }
				if tc.invalidate {
					req := InvalidationRequest{ProviderName: "p"}
					if tc.otherProvider {
						req.ProviderName = "other"
					}
					if _, err := c.InvalidateCredentials(req); err != nil {
						t.Fatal(err)
					}
				}
				now = firstFetch
				fetch := func() {
					t.Helper()
					var err error
					if kind == "apiKey" {
						_, err = c.GetToken(context.Background(), "a", "r", "p")
					} else {
						_, err = c.GetSTSCredential(context.Background(), "a", "r", "p")
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				fetch()
				now = firstFetch.Add(tc.wantTTL - time.Nanosecond)
				fetch()
				if calls.Load() != 1 {
					t.Fatalf("expired early: calls=%d", calls.Load())
				}
				now = firstFetch.Add(tc.wantTTL)
				fetch()
				if calls.Load() != 2 {
					t.Fatalf("not expired at deadline: calls=%d", calls.Load())
				}
			})
		}
	}
}

func TestInvalidationFencesInflightFill(t *testing.T) {
	for _, kind := range []string{"apiKey", "stsToken"} {
		t.Run(kind, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			var calls atomic.Int32
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				value := "new"
				if calls.Add(1) == 1 {
					close(started)
					<-release
					value = "old"
				}
				if err := json.NewEncoder(w).
					Encode(credentialResponse{ApiKey: value, StsToken: &stsToken{AccessKeyID: value, AccessKeySecret: "sk", SecurityToken: "st", Expiration: time.Now().Add(time.Hour).Format(time.RFC3339)}}); err != nil {
					t.Errorf("encode credential response: %v", err)
				}
			}))
			defer provider.Close()
			defer releaseOnce.Do(func() { close(release) })
			c := NewClient(
				provider.URL,
				provider.Client(),
				tokencache.NewCache(time.Hour, 10),
				tokencache.NewSTSCache(10),
				WithInvalidationCachePolicy(time.Second, time.Second),
			)
			now := time.Unix(1000, 0)
			c.now = func() time.Time { return now }
			fetch := func() (string, error) {
				if kind == "apiKey" {
					return c.GetToken(context.Background(), "a", "r", "p")
				}
				v, e := c.GetSTSCredential(context.Background(), "a", "r", "p")
				return v.AccessKeyID, e
			}
			done := make(chan error, 1)
			go func() {
				_, err := fetch()
				done <- err
			}()
			<-started
			req := InvalidationRequest{ProviderName: "p"}
			result, err := c.InvalidateCredentials(req)
			if err != nil || result != (InvalidationResult{}) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			// A sweep after the window ends must retain the generation while the old fetch is in flight.
			now = now.Add(2 * time.Second)
			if _, err := c.InvalidateCredentials(InvalidationRequest{ProviderName: "other"}); err != nil {
				t.Fatal(err)
			}
			// A request started after invalidation can fill before the old one finishes.
			if value, err := fetch(); err != nil || value != "new" {
				t.Fatalf("fresh=%q err=%v", value, err)
			}
			releaseOnce.Do(func() { close(release) })
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if _, exists := c.refresh["p"]; exists {
				t.Fatal("finished provider retained expired refresh state")
			}
			if value, err := fetch(); err != nil || value != "new" {
				t.Fatalf("cached=%q err=%v", value, err)
			}
			if calls.Load() != 2 {
				t.Fatalf("calls=%d; fresh cache was lost", calls.Load())
			}
		})
	}
}

func TestInvalidationRestartsWindow(t *testing.T) {
	req := InvalidationRequest{ProviderName: "p"}
	c := NewClient("", http.DefaultClient, nil, nil, WithInvalidationCachePolicy(20*time.Second, 3*time.Second))
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	if _, err := c.InvalidateCredentials(req); err != nil {
		t.Fatal(err)
	}
	now = now.Add(15 * time.Second)
	if _, err := c.InvalidateCredentials(req); err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	if c.maxTTL("p") != 3*time.Second {
		t.Fatal("repeat did not restart short window")
	}
	now = now.Add(15 * time.Second)
	if c.maxTTL("p") != 0 {
		t.Fatal("short window did not end")
	}
}

func TestInvalidationDoesNotCacheUncacheableSTS(t *testing.T) {
	for _, expiration := range []string{"", time.Now().Add(time.Minute).Format(time.RFC3339)} {
		var calls atomic.Int32
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if err := json.NewEncoder(w).
				Encode(credentialResponse{StsToken: &stsToken{AccessKeyID: "ak", AccessKeySecret: "sk", SecurityToken: "st", Expiration: expiration}}); err != nil {
				t.Errorf("encode credential response: %v", err)
			}
		}))
		c := NewClient(
			provider.URL,
			provider.Client(),
			nil,
			tokencache.NewSTSCache(10),
			WithInvalidationCachePolicy(20*time.Second, 3*time.Second),
		)
		if _, err := c.InvalidateCredentials(InvalidationRequest{ProviderName: "p"}); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err := c.GetSTSCredential(context.Background(), "a", "r", "p"); err != nil {
				t.Fatal(err)
			}
		}
		provider.Close()
		if calls.Load() != 2 {
			t.Fatalf("expiration %q: calls=%d", expiration, calls.Load())
		}
	}
}

func TestConcurrentInvalidationAndRequests(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).
			Encode(credentialResponse{ApiKey: "key", StsToken: &stsToken{AccessKeyID: "ak", AccessKeySecret: "sk", SecurityToken: "st", Expiration: time.Now().Add(time.Hour).Format(time.RFC3339)}}); err != nil {
			t.Errorf("encode credential response: %v", err)
		}
	}))
	defer provider.Close()
	c := NewClient(
		provider.URL,
		provider.Client(),
		tokencache.NewCache(time.Hour, 10),
		tokencache.NewSTSCache(10),
		WithInvalidationCachePolicy(20*time.Second, 3*time.Second),
	)
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			for range 20 {
				var err error
				switch i {
				case 0:
					_, err = c.InvalidateCredentials(InvalidationRequest{ProviderName: "p"})
				case 1:
					_, err = c.InvalidateCredentials(InvalidationRequest{ProviderName: "other"})
				case 2:
					_, err = c.GetToken(context.Background(), "a", "r", "p")
				case 3:
					_, err = c.GetSTSCredential(context.Background(), "a", "r", "p")
				}
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}

func TestInvalidationReclaimsExpiredState(t *testing.T) {
	c := NewClient("", http.DefaultClient, nil, nil, WithInvalidationCachePolicy(10*time.Second, time.Second))
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	for i := range 100 {
		if _, err := c.InvalidateCredentials(InvalidationRequest{ProviderName: fmt.Sprintf("p-%d", i)}); err != nil {
			t.Fatal(err)
		}
		if len(c.refresh) > 10 {
			t.Fatalf("expired providers accumulated: %d", len(c.refresh))
		}
		now = now.Add(time.Second)
	}
	if c.maxTTL("p-99") != time.Second {
		t.Fatal("sweep removed an active short-TTL window")
	}
	now = now.Add(10 * time.Second)
	if _, err := c.InvalidateCredentials(InvalidationRequest{ProviderName: "next"}); err != nil {
		t.Fatal(err)
	}
	if len(c.refresh) != 1 {
		t.Fatalf("expired providers retained: %d", len(c.refresh))
	}
}

func TestCredentialFetchReleasesRefreshState(t *testing.T) {
	for _, kind := range []string{"apiKey", "stsToken"} {
		for _, tc := range []struct {
			name      string
			status    int
			body      string
			wantError bool
		}{
			{name: "success", status: http.StatusOK, body: `{"apiKey":"key","stsToken":{"accessKeyId":"ak","accessKeySecret":"sk","securityToken":"st"}}`},
			{name: "provider error", status: http.StatusServiceUnavailable, body: "unavailable", wantError: true},
			{name: "invalid JSON", status: http.StatusOK, body: "{", wantError: true},
			{name: "incomplete credential", status: http.StatusOK, body: "{}", wantError: true},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tc.status)
					if _, err := w.Write([]byte(tc.body)); err != nil {
						t.Errorf("write credential response: %v", err)
					}
				}))
				defer provider.Close()
				c := NewClient(provider.URL, provider.Client(), nil, nil)
				var err error
				if kind == "apiKey" {
					_, err = c.GetToken(context.Background(), "a", "r", "p")
				} else {
					_, err = c.GetSTSCredential(context.Background(), "a", "r", "p")
				}
				if (err != nil) != tc.wantError {
					t.Fatalf("err=%v wantError=%v", err, tc.wantError)
				}
				if len(c.refresh) != 0 {
					t.Fatalf("fetch retained refresh state: %+v", c.refresh)
				}
			})
		}
	}
}

func TestOAuth2ProviderInvalidationScopeAndTTL(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(OAuth2Response{
			Status:                      OAuth2StatusReady,
			AccessToken:                 "fresh",
			TokenType:                   "Bearer",
			CacheExpiresInSeconds:       100,
			AccessTokenExpiresInSeconds: 300,
		}); err != nil {
			t.Error(err)
		}
	}))
	defer provider.Close()
	for _, tc := range []struct {
		name   string
		window time.Duration
		cap    time.Duration
		want   time.Duration
	}{
		{"enabled", 30 * time.Second, 5 * time.Second, 5 * time.Second},
		{"disabled window", 0, 5 * time.Second, 100 * time.Second},
		{"disabled cap", 30 * time.Second, 0, 100 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(provider.URL, provider.Client(), nil, nil, WithInvalidationCachePolicy(tc.window, tc.cap))
			now := time.Unix(1000, 0)
			c.now = func() time.Time { return now }
			c.oauth2Cache.now = c.now
			request := OAuth2Request{Operation: OAuth2OperationResource, CredentialProviderName: "p", ResourceID: "r"}
			for _, caller := range []string{"a", "b"} {
				for _, scope := range []string{"read", "write"} {
					request.Parameters = map[string]string{"scope": scope}
					if _, err := c.CallOAuth2(t.Context(), caller, request); err != nil {
						t.Fatal(err)
					}
				}
			}
			request.CredentialProviderName = "other"
			if _, err := c.CallOAuth2(t.Context(), "a", request); err != nil {
				t.Fatal(err)
			}
			result, err := c.InvalidateCredentials(InvalidationRequest{ProviderName: "p"})
			if err != nil || result.OAuth2Entries != 4 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if _, ok := c.oauth2Cache.get("a", request); !ok {
				t.Fatal("unrelated provider removed")
			}
			request.CredentialProviderName = "p"
			if _, err := c.CallOAuth2(t.Context(), "a", request); err != nil {
				t.Fatal(err)
			}
			now = now.Add(tc.want)
			if _, ok := c.oauth2Cache.get("a", request); ok {
				t.Fatal("OAuth cache exceeded its TTL")
			}
			// After the window, the normal lifetime is restored.
			now = now.Add(30 * time.Second)
			if _, err := c.CallOAuth2(t.Context(), "b", request); err != nil {
				t.Fatal(err)
			}
			now = now.Add(6 * time.Second)
			if _, ok := c.oauth2Cache.get("b", request); !ok {
				t.Fatal("normal OAuth TTL was not restored")
			}
		})
	}
}

func TestOAuth2InvalidationFencesOldFill(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := "fresh"
		if calls.Add(1) == 1 {
			close(started)
			<-release
			value = "old"
		}
		if err := json.NewEncoder(w).Encode(OAuth2Response{
			Status:                      OAuth2StatusReady,
			AccessToken:                 value,
			TokenType:                   "Bearer",
			CacheExpiresInSeconds:       100,
			AccessTokenExpiresInSeconds: 300,
		}); err != nil {
			t.Error(err)
		}
	}))
	defer provider.Close()
	defer once.Do(func() { close(release) })
	c := NewClient(provider.URL, provider.Client(), nil, nil)
	request := OAuth2Request{Operation: OAuth2OperationResource, CredentialProviderName: "p", ResourceID: "r"}
	done := make(chan error, 1)
	go func() {
		_, err := c.CallOAuth2(t.Context(), "a", request)
		done <- err
	}()
	<-started
	if _, err := c.InvalidateCredentials(InvalidationRequest{ProviderName: "p"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CallOAuth2(t.Context(), "a", request); err != nil {
		t.Fatal(err)
	}
	once.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	result, err := c.CallOAuth2(t.Context(), "a", request)
	if err != nil || result.AccessToken != "fresh" || calls.Load() != 2 {
		t.Fatalf("result=%+v err=%v calls=%d", result, err, calls.Load())
	}
}
