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
package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
	"github.com/openkruise/agentio/extensions/epe/pkg/credential/credentialtest"
	"github.com/openkruise/agentio/extensions/epe/pkg/credential/tokencache"
)

func TestCredentialInvalidationHTTP(t *testing.T) {
	p := credentialtest.NewAPIKeyProvider(t, "fresh")
	cache := tokencache.NewCache(time.Hour, 10)
	key := tokencache.Key{ProviderName: "p", ResourceID: "r"}
	cache.Set(key, "old")
	c := p.ClientWithCache(cache, nil)
	// Operational cache controls remain available with debug disabled.
	handler := NewHandler(Options{Credentials: c})
	response := httptest.NewRecorder()
	handler.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodPost, credentialInvalidationPath, strings.NewReader(`{"providerName":"p"}`)),
	)
	var result credential.InvalidationResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || result.APIKeyEntries != 1 || result.STSEntries != 0 {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
	if p.Calls.Load() != 0 {
		t.Fatal("invalidation must not fetch a credential")
	}
	value, err := c.GetToken(context.Background(), "access", "r", "p")
	if err != nil || value != "fresh" || p.Calls.Load() != 1 {
		t.Fatalf("value=%q calls=%d err=%v", value, p.Calls.Load(), err)
	}
	index := httptest.NewRecorder()
	handler.ServeHTTP(index, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(index.Body.String(), credentialInvalidationPath) {
		t.Fatal("index missing cache control")
	}
}

func TestCredentialInvalidationRejectsInvalidRequests(t *testing.T) {
	cache := tokencache.NewCache(time.Hour, 10)
	key := tokencache.Key{ProviderName: "p", ResourceID: "r"}
	cache.Set(key, "old")
	c := credential.NewClient("", http.DefaultClient, cache, nil)
	handler := NewHandler(Options{Credentials: c})
	for _, body := range []string{
		"", "{", "null", "[]", "{}", `{"providerName":""}`,
		`{"providerName":"p","unknown":true}`,
		`{"providerName":123}`,
		`{"providerName":"p"} {}`, `{"providerName":"p"} trailing`,
		`{"providerName":"` + strings.Repeat("x", maxCredentialInvalidationBodyBytes) + `"}`,
		`{"providerName":"p"}` + strings.Repeat(" ", maxCredentialInvalidationBodyBytes),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(
			response,
			httptest.NewRequest(http.MethodPost, credentialInvalidationPath, strings.NewReader(body)),
		)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %.60q status=%d", body, response.Code)
		}
		if token, ok := cache.Get(key); !ok || token != "old" {
			t.Fatalf("invalid body %.60q changed cache", body)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, credentialInvalidationPath, nil))
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "POST" {
			t.Fatalf("%s status=%d allow=%s", method, response.Code, response.Header().Get("Allow"))
		}
	}
	response := httptest.NewRecorder()
	NewHandler(
		Options{},
	).ServeHTTP(response, httptest.NewRequest(http.MethodPost, credentialInvalidationPath, strings.NewReader(`{"providerName":"p"}`)))
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing dependency status=%d", response.Code)
	}
}
