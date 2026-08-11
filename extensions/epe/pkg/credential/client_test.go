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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"istio.io/istio/pkg/test"
)

// generateSelfSignedCert creates a self-signed certificate and private key,
// returning their PEM-encoded bytes.
func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certBuf, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	defer os.Remove(certBuf.Name())

	keyBuf, err := os.CreateTemp("", "key-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer os.Remove(keyBuf.Name())

	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("failed to encode cert PEM: %v", err)
	}
	certBuf.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	if err := pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("failed to encode key PEM: %v", err)
	}
	keyBuf.Close()

	certPEM, err = os.ReadFile(certBuf.Name())
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}
	keyPEM, err = os.ReadFile(keyBuf.Name())
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}

	return certPEM, keyPEM
}

// generateCACert creates a self-signed CA certificate and returns its PEM bytes.
func generateCACert(t *testing.T) (caCertPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-ca", Organization: []string{"Test CA"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	f, err := os.CreateTemp("", "ca-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp CA file: %v", err)
	}
	defer os.Remove(f.Name())

	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("failed to encode CA cert PEM: %v", err)
	}
	f.Close()

	caCertPEM, err = os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("failed to read CA cert file: %v", err)
	}

	return caCertPEM
}

// writeTempFile writes data to a fresh temp file and returns its path. The
// file is removed automatically when the (sub)test finishes.
func writeTempFile(t *testing.T, pattern string, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		t.Fatalf("failed to create temp file %s: %v", pattern, err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	if _, err := f.Write(data); err != nil {
		t.Fatalf("failed to write temp file %s: %v", pattern, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file %s: %v", pattern, err)
	}
	return f.Name()
}

// TestBuildHTTPClient_FallsBackToDefaultTLS covers every input that must make
// buildHTTPClient(nil) fall back to the plain default-TLS client: unset or
// partial env vars, nonexistent files, and unparseable cert/key/CA data.
func TestBuildHTTPClient_FallsBackToDefaultTLS(t *testing.T) {
	cases := []struct {
		name string
		// paths returns the cert/key/CA env var values for the case; an empty
		// value leaves the corresponding path unset (default path kicks in).
		paths func(t *testing.T) (cert, key, ca string)
	}{
		{
			name:  "no certs",
			paths: func(t *testing.T) (string, string, string) { return "", "", "" },
		},
		{
			name:  "missing cert path",
			paths: func(t *testing.T) (string, string, string) { return "", "/nonexistent/key.pem", "" },
		},
		{
			name:  "missing key path",
			paths: func(t *testing.T) (string, string, string) { return "/nonexistent/cert.pem", "", "" },
		},
		{
			name: "nonexistent cert and key paths",
			paths: func(t *testing.T) (string, string, string) {
				return "/nonexistent/cert.pem", "/nonexistent/key.pem", ""
			},
		},
		{
			name:  "nil secret reader and nonexistent paths including CA",
			paths: func(t *testing.T) (string, string, string) { return "/nonexistent", "/nonexistent", "/nonexistent" },
		},
		{
			name: "invalid cert data",
			paths: func(t *testing.T) (string, string, string) {
				cert := writeTempFile(t, "bad-cert-*.pem", []byte("not-a-valid-pem-cert"))
				key := writeTempFile(t, "bad-key-*.pem", []byte("not-a-valid-pem-key"))
				return cert, key, ""
			},
		},
		{
			name: "invalid CA data",
			paths: func(t *testing.T) (string, string, string) {
				certPEM, keyPEM := generateSelfSignedCert(t)
				cert := writeTempFile(t, "valid-cert-*.pem", certPEM)
				key := writeTempFile(t, "valid-key-*.pem", keyPEM)
				ca := writeTempFile(t, "bad-ca-*.pem", []byte("not-a-valid-ca"))
				return cert, key, ca
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, key, ca := tc.paths(t)
			test.SetForTest(t, &clientCertPath, cert)
			test.SetForTest(t, &clientKeyPath, key)
			test.SetForTest(t, &caCertPath, ca)

			client := buildHTTPClient(nil)
			if client == nil {
				t.Fatal("expected non-nil http client (should fall back to plain HTTPS)")
			}
			if client.Transport == nil {
				t.Fatal("expected non-nil transport")
			}
		})
	}
}

func TestBuildHTTPClient_ValidCerts_ReturnsMTLSClient(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	caPEM := generateCACert(t)

	test.SetForTest(t, &clientCertPath, writeTempFile(t, "mtls-cert-*.pem", certPEM))
	test.SetForTest(t, &clientKeyPath, writeTempFile(t, "mtls-key-*.pem", keyPEM))
	test.SetForTest(t, &caCertPath, writeTempFile(t, "mtls-ca-*.pem", caPEM))

	client := buildHTTPClient(nil)
	if client == nil {
		t.Fatal("expected non-nil http client")
	}
	if client.Transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

// transportTLSConfig returns the TLS config behind an HTTP client's transport.
func transportTLSConfig(t *testing.T, c *http.Client) *tls.Config {
	t.Helper()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", c.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("expected non-nil TLSClientConfig")
	}
	return tr.TLSClientConfig
}

// TestBuildHTTPClient_InsecureSkipVerify_ReachesUnknownCA is the behavioral
// contract of insecureSkipVerify: with no mTLS material configured at
// all, the client completes a handshake against a server whose self-signed
// certificate is in no trust store, and the same client rejects it when the
// env var is absent.
func TestBuildHTTPClient_InsecureSkipVerify_ReachesUnknownCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	// No cert, key, or CA anywhere: insecure mode must not need them.
	setPaths := func(t *testing.T) {
		t.Helper()
		test.SetForTest(t, &clientCertPath, "/nonexistent/cert.pem")
		test.SetForTest(t, &clientKeyPath, "/nonexistent/key.pem")
		test.SetForTest(t, &caCertPath, "/nonexistent/ca.pem")
	}

	t.Run("disabled rejects unknown CA", func(t *testing.T) {
		setPaths(t)
		test.SetForTest(t, &insecureSkipVerify, false)

		resp, err := buildHTTPClient(nil).Get(srv.URL)
		if err == nil {
			resp.Body.Close()
			t.Fatal("expected the handshake to fail against an untrusted self-signed cert")
		}
		// Assert the failure is certificate verification specifically, so the
		// case cannot pass on an unrelated dial or protocol error.
		var verifyErr *tls.CertificateVerificationError
		if !errors.As(err, &verifyErr) {
			t.Fatalf("expected a tls.CertificateVerificationError, got %T: %v", err, err)
		}
	})

	t.Run("enabled reaches server with no certs configured", func(t *testing.T) {
		setPaths(t)
		test.SetForTest(t, &insecureSkipVerify, true)

		resp, err := buildHTTPClient(nil).Get(srv.URL)
		if err != nil {
			t.Fatalf("expected the request to succeed with insecure skip verify: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
	})
}

// TestBuildHTTPClient_InsecureSkipVerify_KeepsClientCertificate pins the two
// axes as orthogonal: insecure mode turns off server verification and leaves
// every mTLS source in place. A provider serving a self-signed certificate while
// requiring mTLS is the case that matters — dropping the client identity here
// made it answer 403 "extraMetadata requires an mTLS client".
func TestBuildHTTPClient_InsecureSkipVerify_KeepsClientCertificate(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	caPEM := generateCACert(t)

	cases := []struct {
		name   string
		setup  func(t *testing.T) kubernetes.Interface
		wantCA bool
	}{
		{
			name: "from secret",
			setup: func(t *testing.T) kubernetes.Interface {
				test.SetForTest(t, &secretNamespace, "epe-system")
				test.SetForTest(t, &secretName, "epe-mtls")
				return k8sfake.NewSimpleClientset(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "epe-system", Name: "epe-mtls"},
					Data: map[string][]byte{
						secretKeyCACert:     caPEM,
						secretKeyClientCert: certPEM,
						secretKeyClientKey:  keyPEM,
					},
				})
			},
			wantCA: true,
		},
		{
			name: "from file paths",
			setup: func(t *testing.T) kubernetes.Interface {
				test.SetForTest(t, &clientCertPath, writeTempFile(t, "insecure-cert-*.pem", certPEM))
				test.SetForTest(t, &clientKeyPath, writeTempFile(t, "insecure-key-*.pem", keyPEM))
				test.SetForTest(t, &caCertPath, writeTempFile(t, "insecure-ca-*.pem", caPEM))
				return nil
			},
			wantCA: true,
		},
		{
			// The self-signed provider case: there is no CA to provision, which
			// must not cost the client its certificate.
			name: "from file paths without a CA",
			setup: func(t *testing.T) kubernetes.Interface {
				test.SetForTest(t, &clientCertPath, writeTempFile(t, "insecure-cert-*.pem", certPEM))
				test.SetForTest(t, &clientKeyPath, writeTempFile(t, "insecure-key-*.pem", keyPEM))
				test.SetForTest(t, &caCertPath, "/nonexistent/ca.pem")
				return nil
			},
			wantCA: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			test.SetForTest(t, &secretNamespace, "")
			test.SetForTest(t, &secretName, "")
			test.SetForTest(t, &clientCertPath, "/nonexistent/cert.pem")
			test.SetForTest(t, &clientKeyPath, "/nonexistent/key.pem")
			test.SetForTest(t, &caCertPath, "/nonexistent/ca.pem")
			test.SetForTest(t, &insecureSkipVerify, true)
			secrets := tc.setup(t)

			cfg := transportTLSConfig(t, buildHTTPClient(secrets))
			if !cfg.InsecureSkipVerify {
				t.Error("expected InsecureSkipVerify to be set")
			}
			if len(cfg.Certificates) != 1 {
				t.Errorf("expected the configured client certificate to be presented, got %d", len(cfg.Certificates))
			}
			if gotCA := cfg.RootCAs != nil; gotCA != tc.wantCA {
				t.Errorf("RootCAs loaded = %v, want %v", gotCA, tc.wantCA)
			}
			if cfg.MinVersion != tls.VersionTLS12 {
				t.Errorf("expected MinVersion TLS 1.2, got %x", cfg.MinVersion)
			}
		})
	}
}

// TestBuildHTTPClient_InsecureSkipVerify_MTLSHandshake is the end-to-end form of
// the test above: a server presenting an untrusted certificate *and* demanding a
// client certificate is reachable only when both axes hold at once.
func TestBuildHTTPClient_InsecureSkipVerify_MTLSHandshake(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)

	var sawPeerCert bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPeerCert = r.TLS != nil && len(r.TLS.PeerCertificates) > 0
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	test.SetForTest(t, &secretNamespace, "")
	test.SetForTest(t, &secretName, "")
	test.SetForTest(t, &clientCertPath, writeTempFile(t, "handshake-cert-*.pem", certPEM))
	test.SetForTest(t, &clientKeyPath, writeTempFile(t, "handshake-key-*.pem", keyPEM))
	test.SetForTest(t, &caCertPath, "/nonexistent/ca.pem")
	test.SetForTest(t, &insecureSkipVerify, true)

	resp, err := buildHTTPClient(nil).Get(srv.URL)
	if err != nil {
		t.Fatalf("handshake against a self-signed server requiring mTLS failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if !sawPeerCert {
		t.Error("server saw no client certificate")
	}
}

func TestNewMTLSClient_CertKeyMismatch(t *testing.T) {
	certPEM, _ := generateSelfSignedCert(t)
	_, keyPEM2 := generateSelfSignedCert(t)
	caPEM := generateCACert(t)

	certPath := writeTempFile(t, "mismatch-cert-*.pem", certPEM)
	keyPath := writeTempFile(t, "mismatch-key-*.pem", keyPEM2)
	caPath := writeTempFile(t, "mismatch-ca-*.pem", caPEM)

	_, err := newMTLSClient(certPath, keyPath, caPath)
	if err == nil {
		t.Log("newMTLSClient unexpectedly succeeded with mismatched cert/key")
	}
}

// TestNewMTLSClient_MissingFiles verifies newMTLSClient fails when the cert,
// key, or CA file does not exist. Files earlier in the read order are real so
// each case reaches the intended missing file.
func TestNewMTLSClient_MissingFiles(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	certPath := writeTempFile(t, "test-cert-*.pem", certPEM)
	keyPath := writeTempFile(t, "test-key-*.pem", keyPEM)

	cases := []struct {
		name          string
		cert, key, ca string
	}{
		{name: "nonexistent cert file", cert: "/nonexistent/cert.pem", key: "/nonexistent/key.pem", ca: "/nonexistent/ca.pem"},
		{name: "nonexistent key file", cert: certPath, key: "/nonexistent/key.pem", ca: "/nonexistent/ca.pem"},
		{name: "nonexistent CA file", cert: certPath, key: keyPath, ca: "/nonexistent/ca.pem"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newMTLSClient(tc.cert, tc.key, tc.ca); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}

	// The CA is the one piece insecure mode does without: it is never consulted,
	// so requiring it would cost the source its client certificate.
	t.Run("nonexistent CA file with insecure skip verify", func(t *testing.T) {
		test.SetForTest(t, &insecureSkipVerify, true)
		c, err := newMTLSClient(certPath, keyPath, "/nonexistent/ca.pem")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg := transportTLSConfig(t, c); len(cfg.Certificates) != 1 {
			t.Errorf("expected the client certificate to be presented, got %d", len(cfg.Certificates))
		}
	})
}

// --- GetToken ---------------------------------------------------------------

func TestNewClient_DefaultsAndExplicit(t *testing.T) {
	test.SetForTest(t, &identityProviderURL, "")
	c := NewClient()
	if c == nil || c.providerURL != "" {
		t.Errorf("expected unset URL, got %q", c.providerURL)
	}

	test.SetForTest(t, &identityProviderURL, "http://example.com/")
	c2 := NewClientWithCache(nil, nil, nil)
	if c2 == nil || c2.providerURL != "http://example.com/" {
		t.Errorf("expected explicit URL, got %q", c2.providerURL)
	}
}

// TestGetToken_BadURL covers http.NewRequestWithContext failure (invalid URL).
func TestGetToken_BadURL(t *testing.T) {
	test.SetForTest(t, &identityProviderURL, "http://[::1") // malformed
	test.SetForTest(t, &clientCertPath, "/nonexistent")
	c := NewClient()
	if _, err := c.GetToken(context.Background(), "a", "b", "c"); err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

func TestLoadCACertPool_InvalidCA(t *testing.T) {
	caPath := writeTempFile(t, "invalid-ca-*.pem", []byte("not-a-cert"))

	if _, err := loadCACertPool(caPath); err == nil {
		t.Fatal("expected error for invalid CA cert")
	}

	// Unparseable material is not an error when nothing will read the pool.
	t.Run("insecure skip verify", func(t *testing.T) {
		test.SetForTest(t, &insecureSkipVerify, true)
		pool, err := loadCACertPool(caPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pool != nil {
			t.Error("expected a nil pool, which means the system trust store")
		}
	})
}

// --- Secret-based mTLS tests ------------------------------------------------

func buildFakeClientsetWithSecret(t *testing.T, ns, name string, certPEM, keyPEM, caPEM []byte) *k8sfake.Clientset {
	t.Helper()
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Data: map[string][]byte{
			secretKeyCACert:     caPEM,
			secretKeyClientCert: certPEM,
			secretKeyClientKey:  keyPEM,
		},
	}
	return k8sfake.NewSimpleClientset(sec)
}

// TestNewMTLSClientFromSecret_Success verifies the Secret-based mTLS client is
// built from whatever namespace/name the env vars point at.
func TestNewMTLSClientFromSecret_Success(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	caPEM := generateCACert(t)

	cases := []struct {
		name              string
		namespace, secret string
	}{
		{name: "default names", namespace: "default-ns", secret: "default-secret"},
		{name: "custom env vars", namespace: "custom-ns", secret: "custom-secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secrets := buildFakeClientsetWithSecret(t, tc.namespace, tc.secret, certPEM, keyPEM, caPEM)

			test.SetForTest(t, &secretNamespace, tc.namespace)
			test.SetForTest(t, &secretName, tc.secret)

			c, err := newMTLSClientFromSecret(secrets)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c == nil {
				t.Fatal("expected non-nil http client")
			}
			if c.Transport == nil {
				t.Fatal("expected non-nil transport")
			}
		})
	}
}

// TestNewMTLSClientFromSecret_Errors covers every input that must make
// newMTLSClientFromSecret fail: unset env vars, a Secret that does not exist,
// a Secret missing a required data key, and unparseable certificate data.
func TestNewMTLSClientFromSecret_Errors(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	caPEM := generateCACert(t)

	cases := []struct {
		name      string
		namespace string
		secName   string
		data      map[string][]byte // nil means no Secret exists in the cluster
	}{
		{
			name:      "env vars unset",
			namespace: "",
			secName:   "",
		},
		{
			name:      "secret not found",
			namespace: "missing-ns",
			secName:   "missing-secret",
		},
		{
			name:      "missing client cert key",
			namespace: "default-ns",
			secName:   "default-secret",
			data: map[string][]byte{
				secretKeyCACert:    caPEM,
				secretKeyClientKey: keyPEM,
			},
		},
		{
			name:      "missing CA cert key",
			namespace: "default-ns",
			secName:   "default-secret",
			data: map[string][]byte{
				secretKeyClientCert: certPEM,
				secretKeyClientKey:  keyPEM,
			},
		},
		{
			name:      "invalid cert data",
			namespace: "default-ns",
			secName:   "default-secret",
			data: map[string][]byte{
				secretKeyCACert:     caPEM,
				secretKeyClientCert: []byte("not-valid-pem"),
				secretKeyClientKey:  []byte("not-valid-pem"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secrets := k8sfake.NewSimpleClientset()
			if tc.data != nil {
				secrets = k8sfake.NewSimpleClientset(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: tc.namespace, Name: tc.secName},
					Data:       tc.data,
				})
			}

			test.SetForTest(t, &secretNamespace, tc.namespace)
			test.SetForTest(t, &secretName, tc.secName)

			if _, err := newMTLSClientFromSecret(secrets); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestBuildHTTPClient_SecretAvailable_ReturnsMTLSClient(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	caPEM := generateCACert(t)

	secrets := buildFakeClientsetWithSecret(t, "default-ns", "default-secret", certPEM, keyPEM, caPEM)

	test.SetForTest(t, &secretNamespace, "default-ns")
	test.SetForTest(t, &secretName, "default-secret")
	test.SetForTest(t, &clientCertPath, "/nonexistent")
	test.SetForTest(t, &clientKeyPath, "/nonexistent")
	test.SetForTest(t, &caCertPath, "/nonexistent")

	c := buildHTTPClient(secrets)
	if c == nil {
		t.Fatal("expected non-nil http client")
	}
	if c.Transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestBuildHTTPClient_SecretUnavailable_FallsBackToFilePath(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	caPEM := generateCACert(t)

	// Empty fake clientset (Secret not found) → should fall back to file paths.
	secrets := k8sfake.NewSimpleClientset()

	test.SetForTest(t, &secretNamespace, "")
	test.SetForTest(t, &secretName, "")
	test.SetForTest(t, &clientCertPath, writeTempFile(t, "fallback-cert-*.pem", certPEM))
	test.SetForTest(t, &clientKeyPath, writeTempFile(t, "fallback-key-*.pem", keyPEM))
	test.SetForTest(t, &caCertPath, writeTempFile(t, "fallback-ca-*.pem", caPEM))

	c := buildHTTPClient(secrets)
	if c == nil {
		t.Fatal("expected non-nil http client")
	}
	if c.Transport == nil {
		t.Fatal("expected non-nil transport")
	}
}
