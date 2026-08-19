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

// Package credentialtest provides a fake credential-provider HTTP server for
// tests that exercise the credential.Client GetResourceCredential protocol
// (POST JSON {resourceId, credentialProviderName, credentialType} answered
// with {requestId, apiKey} or {requestId, stsToken:{...}}).
//
// These are regular (non _test.go) declarations on purpose, so both the
// credential package's own tests and downstream plugin tests can share one
// fake. The package must stay a leaf: it depends only on pkg/credential —
// never on the plugin chain or the enginetest harness.
package credentialtest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"istio.io/istio/extensions/epe/pkg/credential"
	"istio.io/istio/extensions/epe/pkg/credential/tokencache"
)

// FakeProvider is an httptest-backed credential provider returning a canned
// response. It records how often it was called and what the last request
// carried so tests can assert both the happy path and cache short-circuits.
type FakeProvider struct {
	// Server is the underlying test server; closed automatically via
	// t.Cleanup. Its URL stays readable after Close for network-error tests.
	Server *httptest.Server
	// Calls counts upstream HTTP requests.
	Calls atomic.Int64
	// LastAuthorization holds the Authorization header of the most recent
	// request as a string.
	LastAuthorization atomic.Value
	// LastRequestBody holds the body of the most recent request as []byte.
	LastRequestBody atomic.Value
}

// newFakeProvider starts a server answering every request with the given
// status and body verbatim.
func newFakeProvider(t testing.TB, status int, body string) *FakeProvider {
	t.Helper()
	p := &FakeProvider{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.Calls.Add(1)
		p.LastAuthorization.Store(r.Header.Get("Authorization"))
		b, _ := io.ReadAll(r.Body)
		p.LastRequestBody.Store(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(p.Server.Close)
	return p
}

// NewAPIKeyProvider returns a provider answering every request with an
// apiKey credential response.
func NewAPIKeyProvider(t testing.TB, apiKey string) *FakeProvider {
	t.Helper()
	return newFakeProvider(t, http.StatusOK, mustMarshal(t, map[string]any{
		"requestId": "fake-request-id",
		"apiKey":    apiKey,
	}))
}

// NewSTSProvider returns a provider answering every request with an STS
// triplet credential response. expiration may be empty to omit the field.
func NewSTSProvider(t testing.TB, ak, sk, token, expiration string) *FakeProvider {
	t.Helper()
	sts := map[string]any{
		"accessKeyId":     ak,
		"accessKeySecret": sk,
		"securityToken":   token,
	}
	if expiration != "" {
		sts["expiration"] = expiration
	}
	return newFakeProvider(t, http.StatusOK, mustMarshal(t, map[string]any{
		"requestId": "fake-request-id",
		"stsToken":  sts,
	}))
}

// NewErrorProvider returns a provider answering every request with the given
// status code and raw body (e.g. an upstream 5xx, or malformed JSON).
func NewErrorProvider(t testing.TB, status int, body string) *FakeProvider {
	t.Helper()
	return newFakeProvider(t, status, body)
}

// NewRawProvider returns a provider answering every request 200 OK with the
// given body verbatim, for tests that need a specific wire form.
func NewRawProvider(t testing.TB, body string) *FakeProvider {
	t.Helper()
	return newFakeProvider(t, http.StatusOK, body)
}

// Client returns a cache-less credential.Client pointed at the fake server
// via credential.WithProviderURL (no environment mutation).
func (p *FakeProvider) Client(opts ...credential.Option) *credential.Client {
	return p.ClientWithCache(nil, nil, opts...)
}

// ClientWithCache is like Client but wires the given token caches.
func (p *FakeProvider) ClientWithCache(cache *tokencache.Cache, stsCache *tokencache.STSCache, opts ...credential.Option) *credential.Client {
	allOpts := append([]credential.Option{credential.WithProviderURL(p.Server.URL)}, opts...)
	return credential.NewClientWithCache(cache, stsCache, nil, allOpts...)
}

// mustMarshal renders a response body. The fake builds the wire shape by hand
// rather than marshalling the client's own struct, so a wrong json tag in the
// client shows up as a test failure instead of round-tripping unnoticed.
func mustMarshal(t testing.TB, body map[string]any) string {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal fake credential response: %v", err)
	}
	return string(b)
}
