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
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	log "sigs.k8s.io/controller-runtime/pkg/log"

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

	// Default paths when env vars are not set.
	defaultClientCertPath = "/etc/epe/mtls/client.crt"
	defaultClientKeyPath  = "/etc/epe/mtls/client.key"
	defaultCACertPath     = "/etc/epe/mtls/ca.crt"

	// Secret data keys.
	secretKeyCACert     = "ca.crt"
	secretKeyClientCert = "client.crt"
	secretKeyClientKey  = "client.key"
)

// Environment variables for the credential provider client. Resolved once at
// init, as everywhere else in the tree; tests override the resulting values
// directly with test.SetForTest rather than through the environment.
var (
	identityProviderURL = env.Register("IDENTITY_PROVIDER_URL", "",
		"Base URL of the credential provider API. The client fails every credential lookup while it is unset").Get()

	// insecureSkipVerify disables verification of the credential provider's
	// server certificate. It takes precedence over every mTLS source below, so
	// no certificate, key, or CA has to be provisioned when it is enabled.
	insecureSkipVerify = env.Register("CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY", false,
		"Skip verification of the credential provider's server certificate and present no client certificate. "+
			"Intended for self-signed providers on trusted networks; any on-path attacker can then read the "+
			"bearer token and forge the credential response").Get()

	clientCertPath = env.Register("CREDENTIAL_PROVIDER_CLIENT_CERT_PATH", defaultClientCertPath,
		"Path to the client certificate presented to the credential provider").Get()
	clientKeyPath = env.Register("CREDENTIAL_PROVIDER_CLIENT_KEY_PATH", defaultClientKeyPath,
		"Path to the private key for CREDENTIAL_PROVIDER_CLIENT_CERT_PATH").Get()
	caCertPath = env.Register("CREDENTIAL_PROVIDER_CA_CERT_PATH", defaultCACertPath,
		"Path to the CA certificate used to verify the credential provider's server certificate").Get()

	// Namespace and name of the K8s Secret holding mTLS material. Both must be
	// set for the Secret source to be attempted at all.
	secretNamespace = env.Register("CREDENTIAL_PROVIDER_SECRET_NAMESPACE", "",
		"Namespace of the Secret holding the credential provider mTLS certificate, key, and CA").Get()
	secretName = env.Register("CREDENTIAL_PROVIDER_SECRET_NAME", "",
		"Name of the Secret holding the credential provider mTLS certificate, key, and CA").Get()
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

// NewClient creates a new credential provider client without a K8s clientset
// (falls back to file-path mTLS or default TLS).
func NewClient() *Client {
	return NewClientWithCache(nil, nil, nil)
}

// NewClientWithCache creates a new credential provider client with optional
// token caches and an optional K8s clientset for loading mTLS material from a
// Secret. When secrets is non-nil, the client first tries to read the mTLS
// cert/key/CA from the configured Secret before falling back to file paths.
func NewClientWithCache(cache *tokencache.Cache, stsCache *tokencache.STSCache, secrets kubernetes.Interface, opts ...Option) *Client {
	c := &Client{
		providerURL: identityProviderURL,
		httpClient:  buildHTTPClient(secrets),
		cache:       cache,
		stsCache:    stsCache,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// buildHTTPClient constructs an HTTP client with the following priority:
//  1. Skip server verification entirely (when insecureSkipVerify is enabled)
//  2. Read mTLS material from K8s Secret (when secrets is non-nil)
//  3. Read mTLS material from file paths (env var or defaults)
//  4. Fall back to default-TLS (no client cert, system trust store)
func buildHTTPClient(secrets kubernetes.Interface) *http.Client {
	if insecureSkipVerify {
		log.Log.WithName("credential").Info(
			"Credential provider TLS verification is disabled; the bearer token and returned credentials are exposed to any on-path attacker",
			"envVar", "CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY")
		return newInsecureTLSClient()
	}

	if secrets != nil {
		if c, err := newMTLSClientFromSecret(secrets); err == nil {
			return c
		}
	}

	if c, err := newMTLSClient(clientCertPath, clientKeyPath, caCertPath); err == nil {
		return c
	}
	return newDefaultTLSClient()
}

// newMTLSClientFromSecret reads the mTLS certificate, key and CA from a K8s
// Secret and returns a configured HTTP client. The Secret namespace/name come
// from env vars and both must be set.
func newMTLSClientFromSecret(secrets kubernetes.Interface) (*http.Client, error) {
	ns := secretNamespace
	name := secretName
	if ns == "" || name == "" {
		return nil, fmt.Errorf("%s and %s must both be set to read mTLS material from a Secret",
			"CREDENTIAL_PROVIDER_SECRET_NAMESPACE", "CREDENTIAL_PROVIDER_SECRET_NAME")
	}

	sec, err := secrets.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to read mTLS secret %s/%s: %w", ns, name, err)
	}

	caCertPEM, ok := sec.Data[secretKeyCACert]
	if !ok || len(caCertPEM) == 0 {
		return nil, fmt.Errorf("mTLS secret %s/%s missing data key %q", ns, name, secretKeyCACert)
	}
	certPEM, ok := sec.Data[secretKeyClientCert]
	if !ok || len(certPEM) == 0 {
		return nil, fmt.Errorf("mTLS secret %s/%s missing data key %q", ns, name, secretKeyClientCert)
	}
	keyPEM, ok := sec.Data[secretKeyClientKey]
	if !ok || len(keyPEM) == 0 {
		return nil, fmt.Errorf("mTLS secret %s/%s missing data key %q", ns, name, secretKeyClientKey)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate from secret: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA cert from secret %s/%s", ns, name)
	}

	return &http.Client{
		Timeout: defaultHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,
				MinVersion:   tls.VersionTLS12,
			},
		},
	}, nil
}

// newMTLSClient loads a client certificate, key, and CA cert, then returns an
// HTTP client configured for mTLS with server CA verification.
func newMTLSClient(certPath, keyPath, caCertPath string) (*http.Client, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read client cert %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read client key %s: %w", keyPath, err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate: %w", err)
	}

	caCertPool, err := loadCACertPool(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA cert %s: %w", caCertPath, err)
	}

	return &http.Client{
		Timeout: defaultHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,
				MinVersion:   tls.VersionTLS12,
			},
		},
	}, nil
}

// loadCACertPool reads a CA certificate file and returns a CertPool.
func loadCACertPool(caCertPath string) (*x509.CertPool, error) {
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert %s: %w", caCertPath, err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA cert from %s", caCertPath)
	}
	return caCertPool, nil
}

// newInsecureTLSClient returns an HTTP client that does not verify the
// credential provider's certificate and presents no client certificate, so no
// mTLS material has to be provisioned. Selected by insecureSkipVerify.
func newInsecureTLSClient() *http.Client {
	return &http.Client{
		Timeout: defaultHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true, //nolint:gosec // opt-in via insecureSkipVerify
			},
		},
	}
}

// newDefaultTLSClient returns an HTTP client with a default TLS transport
// (no client certificate). Server certificates are verified against the
// system trust store; TLS 1.2 is the minimum version. This is the fallback
// used when mTLS material is unavailable — it does NOT skip verification.
func newDefaultTLSClient() *http.Client {
	return &http.Client{
		Timeout: defaultHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
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
