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
// Package credential provides a client for communicating with the
// credential provider API to obtain tokens.
package credential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/certs"
	"istio.io/istio/extensions/epe/pkg/credential/tokencache"
	"istio.io/istio/extensions/epe/pkg/logging"
	"istio.io/istio/pkg/env"
)

const (
	apiActionGetResourceCredential = "GetResourceCredential"

	credentialTypeAPIKey   = "apiKey"
	credentialTypeStsToken = "stsToken"

	// Default HTTP timeout for credential provider calls.
	defaultHTTPTimeout = 10 * time.Second

	// idleConnTimeout bounds how long an idle connection to the credential
	// provider is kept for reuse. The mTLS material is resolved per handshake,
	// so it only changes what a NEW connection presents; the zero value keeps
	// idle connections indefinitely, which would let a rotated certificate go
	// unused until the provider chose to close the connection.
	idleConnTimeout = 90 * time.Second
)

// Environment variables for the credential provider client. Resolved once at
// init, as everywhere else in the tree; tests override the resulting values
// directly with test.SetForTest rather than through the environment.
var (
	identityProviderURL = env.Register("IDENTITY_PROVIDER_URL", "",
		"Base URL of the credential provider API. The client fails every credential lookup while it is unset").Get()

	// insecureSkipVerify disables verification of the credential provider's
	// server certificate. It is orthogonal to the client identity, which is
	// still whatever the Provider supplies — see buildHTTPClient.
	insecureSkipVerify = env.Register("CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY", false,
		"Skip verification of the credential provider's server certificate. The client certificate, when one is "+
			"configured, is still presented. Intended for self-signed providers on trusted networks; any on-path "+
			"attacker can then read the bearer token and forge the credential response").Get()
)

// STSToken holds the STS triplet returned by the credential provider.
type STSToken struct {
	AccessKeyID     string `json:"accessKeyId"`
	AccessKeySecret string `json:"accessKeySecret"`
	SecurityToken   string `json:"securityToken"`
	Expiration      string `json:"expiration,omitempty"`
}

// CredentialResponse is the response from GetResourceCredential.
// Depending on the requested credentialType, either ApiKey or StsToken is set.
type CredentialResponse struct {
	RequestID string    `json:"requestId"`
	ApiKey    string    `json:"apiKey,omitempty"`
	StsToken  *STSToken `json:"stsToken,omitempty"`
}

// STSCredentialResponse aliases CredentialResponse for callers that use the
// STS-specific name.
type STSCredentialResponse = CredentialResponse

// Client is a thread-safe HTTP client for communicating with the
// credential provider.
type Client struct {
	httpClient  *http.Client
	providerURL string
	cache       *tokencache.Cache
	stsCache    *tokencache.STSCache
}

// Option customizes a Client.
type Option func(*Client)

// WithProviderURL overrides the credential provider base URL, taking
// precedence over the IDENTITY_PROVIDER_URL environment variable. For
// tests and callers with explicit configuration.
func WithProviderURL(url string) Option {
	return func(c *Client) {
		if url != "" {
			c.providerURL = url
		}
	}
}

// NewClient creates a credential provider client with no mTLS material, so it
// presents no client identity and verifies the provider against the system
// trust store.
func NewClient() *Client {
	return NewClientWithCache(nil, nil, nil)
}

// NewClientWithCache creates a credential provider client with optional token
// caches and an optional certificate Provider supplying the mTLS material.
//
// The Provider is consulted on every handshake rather than read once here, so
// material that appears or rotates after startup takes effect without a
// restart. Where that material comes from — a Secret, files on disk, or
// nothing — is the composition root's decision (see pkg/wiring); a nil Provider
// means no client identity.
func NewClientWithCache(cache *tokencache.Cache, stsCache *tokencache.STSCache, provider certs.Provider, opts ...Option) *Client {
	c := &Client{
		providerURL: identityProviderURL,
		cache:       cache,
		stsCache:    stsCache,
	}
	for _, opt := range opts {
		opt(c)
	}
	// Built after the options on purpose: the verification pipeline fixes the
	// expected server name when the config is assembled, and WithProviderURL
	// can still change which host that is.
	c.httpClient = buildHTTPClient(provider, c.providerURL)
	return c
}

// buildHTTPClient constructs the HTTP client used to call the credential
// provider. The client is built once; the certificate and the trust anchors are
// resolved from the Provider on every handshake.
//
// insecureSkipVerify governs only whether the provider's server certificate is
// verified, never whether a client certificate is presented. A provider that
// serves a self-signed certificate *and* requires mTLS is a common combination,
// and dropping the client identity in that mode made it inexpressible: the
// provider answered 403 "extraMetadata requires an mTLS client".
//
// That mode deliberately bypasses certs.ClientTLSConfig, whose stated invariant
// is that callers can never disable verification. Rather than punch a hole in
// that package, the one place with a reason to skip verification assembles its
// own config here and still sources the client identity from the Provider.
func buildHTTPClient(provider certs.Provider, providerURL string) *http.Client {
	logger := log.Log.WithName("credential")
	if provider == nil {
		// No mTLS material configured: present no client identity and verify
		// against the system trust store.
		provider = certs.NoMaterial()
	}

	if insecureSkipVerify {
		logger.Info(
			"Credential provider server certificate verification is disabled; the bearer token and returned credentials are exposed to any on-path attacker. A configured client certificate is still presented",
			"envVar", "CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY")
		return newHTTPClient(&tls.Config{
			MinVersion:           tls.VersionTLS12,
			GetClientCertificate: provider.GetClientCertificate,
			//nolint:gosec // opt-in via CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY, warned about above
			InsecureSkipVerify: true,
		})
	}

	host, hostErr := providerHost(providerURL)
	if hostErr != nil {
		// Say why here. The empty server name below makes the verification
		// pipeline fail closed, but on its own that surfaces as an opaque
		// "no identity verification configured" on every single request.
		logger.Error(hostErr,
			"Cannot determine the credential provider host, so its certificate cannot be verified; every credential lookup will fail",
			"envVar", "IDENTITY_PROVIDER_URL")
	}

	cfg, err := certs.ClientTLSConfig(provider, certs.WithServerName(host))
	if err != nil {
		// Unreachable: WithServerName always satisfies the identity requirement
		// ClientTLSConfig enforces. Fail closed rather than fall back to an
		// unverified client.
		logger.Error(err, "Building the credential provider TLS configuration failed; every credential lookup will fail")
		return newHTTPClient(failClosedTLSConfig())
	}
	return newHTTPClient(cfg)
}

// failClosedTLSConfig refuses every peer: verification is on and the trust
// anchor pool is empty, so no certificate can chain to it.
func failClosedTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool()}
}

// providerHost returns the host whose certificate the credential provider must
// present.
//
// An empty URL yields no host and no error: getCredential rejects an unset
// provider URL before any request, so no handshake is ever attempted. A URL that
// is set but carries no host IS an error — getCredential only checks for
// emptiness, so "provider.example.com:8443/creds" (no scheme) parses cleanly
// into a host-less URL and would otherwise fail every request with no
// indication that the configuration is at fault.
func providerHost(rawURL string) (string, error) {
	if rawURL == "" {
		return "", nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parsing %q: %w", rawURL, err)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("%q has no host; an absolute URL is required, e.g. https://provider.example.com/creds", rawURL)
	}
	return u.Hostname(), nil
}

// newHTTPClient wraps a TLS configuration in the HTTP client every source
// funnels through, so the request timeout and the idle connection bound are
// applied in one place.
func newHTTPClient(cfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout: defaultHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: cfg,
			IdleConnTimeout: idleConnTimeout,
		},
	}
}

// credentialRequest is the request body for GetResourceCredential.
type credentialRequest struct {
	ResourceID             string         `json:"resourceId"`
	CredentialProviderName string         `json:"credentialProviderName"`
	CredentialType         string         `json:"credentialType"`
	ExtraMetadata          map[string]any `json:"extraMetadata,omitempty"`
}

// getCredential calls the GetResourceCredential API.
func (c *Client) getCredential(ctx context.Context, accessToken, sandboxClientID, credentialProviderName, credentialType string, extraMetadata map[string]any) (*CredentialResponse, error) {
	logger := log.FromContext(ctx)

	if c.providerURL == "" {
		return nil, fmt.Errorf("credential provider URL is not configured; set %s", "IDENTITY_PROVIDER_URL")
	}

	reqBody := credentialRequest{
		ResourceID:             sandboxClientID,
		CredentialProviderName: credentialProviderName,
		CredentialType:         credentialType,
		ExtraMetadata:          extraMetadata,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.providerURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create credential request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	httpReq.Header.Set("X-Api-Action-Name", apiActionGetResourceCredential)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send credential request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read credential response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		logger.V(logging.DEFAULT).Info("Credential request failed",
			"status", resp.StatusCode,
			"credentialType", credentialType,
			"body", string(body))
		return nil, fmt.Errorf("credential request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var credResp CredentialResponse
	if err := json.Unmarshal(body, &credResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential response (body=%s): %w", string(body), err)
	}

	return &credResp, nil
}

// GetToken retrieves an API key from the credential provider.
func (c *Client) GetToken(ctx context.Context, accessToken, sandboxClientID, credentialProviderName string) (string, error) {
	return c.GetTokenWithExtraMetadata(ctx, accessToken, sandboxClientID, credentialProviderName, nil)
}

// GetTokenWithExtraMetadata retrieves an API key and sends extraMetadata to
// the credential provider. Metadata participates in the cache key.
func (c *Client) GetTokenWithExtraMetadata(ctx context.Context, accessToken, sandboxClientID, credentialProviderName string, extraMetadata map[string]any) (string, error) {
	logger := log.FromContext(ctx)
	cacheProviderName, err := providerCacheKey(credentialProviderName, extraMetadata)
	if err != nil {
		return "", err
	}

	if c.cache != nil {
		if token, ok := c.cache.Get(cacheProviderName, sandboxClientID); ok {
			logger.V(logging.DEBUG).Info("Token retrieved from cache",
				"credentialProvider", credentialProviderName)
			return token, nil
		}
	}

	credResp, err := c.getCredential(ctx, accessToken, sandboxClientID, credentialProviderName, credentialTypeAPIKey, extraMetadata)
	if err != nil {
		return "", err
	}

	if credResp.ApiKey == "" {
		return "", fmt.Errorf("empty apiKey returned from credential provider")
	}

	if c.cache != nil {
		c.cache.Set(cacheProviderName, sandboxClientID, credResp.ApiKey)
	}

	logger.V(logging.DEBUG).Info("Token retrieved successfully",
		"credentialProvider", credentialProviderName)

	return credResp.ApiKey, nil
}

// GetSTSCredential retrieves STS credentials (AK/SK/SecurityToken triplet)
// from the credential provider. Results are cached using the token's own
// expiration timestamp when an STS cache is configured.
func (c *Client) GetSTSCredential(ctx context.Context, accessToken, sandboxClientID, credentialProviderName string) (*STSCredentialResponse, error) {
	return c.GetSTSCredentialWithExtraMetadata(ctx, accessToken, sandboxClientID, credentialProviderName, nil)
}

// GetSTSCredentialWithExtraMetadata retrieves STS credentials and sends
// extraMetadata to the credential provider. Metadata participates in the
// cache key.
func (c *Client) GetSTSCredentialWithExtraMetadata(ctx context.Context, accessToken, sandboxClientID, credentialProviderName string, extraMetadata map[string]any) (*STSCredentialResponse, error) {
	logger := log.FromContext(ctx)
	cacheProviderName, err := providerCacheKey(credentialProviderName, extraMetadata)
	if err != nil {
		return nil, err
	}

	if c.stsCache != nil {
		if entry, ok := c.stsCache.Get(cacheProviderName, sandboxClientID); ok {
			logger.V(logging.DEBUG).Info("STS credential retrieved from cache",
				"credentialProvider", credentialProviderName)
			return &CredentialResponse{
				StsToken: &STSToken{
					AccessKeyID:     entry.AccessKeyID,
					AccessKeySecret: entry.AccessKeySecret,
					SecurityToken:   entry.SecurityToken,
				},
			}, nil
		}
	}

	credResp, err := c.getCredential(ctx, accessToken, sandboxClientID, credentialProviderName, credentialTypeStsToken, extraMetadata)
	if err != nil {
		return nil, err
	}

	if credResp.StsToken == nil || credResp.StsToken.AccessKeyID == "" || credResp.StsToken.AccessKeySecret == "" || credResp.StsToken.SecurityToken == "" {
		return nil, fmt.Errorf("incomplete STS credential from credential provider")
	}

	if c.stsCache != nil && credResp.StsToken.Expiration != "" {
		if exp, parseErr := time.Parse(time.RFC3339, credResp.StsToken.Expiration); parseErr == nil {
			c.stsCache.SetWithExpiration(cacheProviderName, sandboxClientID, tokencache.STSCacheEntry{
				AccessKeyID:     credResp.StsToken.AccessKeyID,
				AccessKeySecret: credResp.StsToken.AccessKeySecret,
				SecurityToken:   credResp.StsToken.SecurityToken,
			}, exp)
		}
	}

	logger.V(logging.DEBUG).Info("STS credential retrieved successfully",
		"credentialProvider", credentialProviderName)

	return credResp, nil
}

func providerCacheKey(providerName string, extraMetadata map[string]any) (string, error) {
	if len(extraMetadata) == 0 {
		return providerName, nil
	}
	canonical, err := json.Marshal(extraMetadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal credential extraMetadata for cache key: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("%s#%x", providerName, sum), nil
}
