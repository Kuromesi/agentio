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
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"istio.io/istio/extensions/epe/pkg/certs"
)

// writeSelfSignedPEM writes a throwaway self-signed cert/key (and the cert
// again as a CA bundle) into dir and returns the three paths. FromFiles reads
// the files eagerly, so they must exist before buildExtProcTLS runs.
func writeSelfSignedPEM(t *testing.T, dir string) (certPath, keyPath, caPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tls-flags-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	certPath = filepath.Join(dir, "cert-chain.pem")
	keyPath = filepath.Join(dir, "key.pem")
	caPath = filepath.Join(dir, "root-cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing CA bundle: %v", err)
	}
	return certPath, keyPath, caPath
}

func TestBuildExtProcTLS(t *testing.T) {
	certPath, keyPath, caPath := writeSelfSignedPEM(t, t.TempDir())
	const spiffeID = "spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway"

	tests := []struct {
		name            string
		certPath        string
		keyPath         string
		caPath          string
		spiffeIDs       string
		expectError     string
		expectSecure    bool
		expectMTLS      bool
		expectAllowList bool
	}{
		{
			name: "all empty means plaintext",
		},
		{
			name:        "cert without key is rejected",
			certPath:    certPath,
			expectError: "must be set together",
		},
		{
			name:        "key without cert is rejected",
			keyPath:     keyPath,
			expectError: "must be set together",
		},
		{
			name:        "ca without cert and key is rejected",
			caPath:      caPath,
			expectError: "must be set together",
		},
		{
			name:        "spiffe ids without ca are rejected",
			certPath:    certPath,
			keyPath:     keyPath,
			spiffeIDs:   spiffeID,
			expectError: "requires --tls-ca-path",
		},
		{
			name:        "spiffe ids trimming to empty are rejected",
			certPath:    certPath,
			keyPath:     keyPath,
			caPath:      caPath,
			spiffeIDs:   " , ,",
			expectError: "no SPIFFE IDs",
		},
		{
			name:        "invalid spiffe id is rejected",
			certPath:    certPath,
			keyPath:     keyPath,
			caPath:      caPath,
			spiffeIDs:   "https://not-spiffe",
			expectError: "invalid SPIFFE ID",
		},
		{
			name:        "missing certificate file is rejected",
			certPath:    filepath.Join(t.TempDir(), "missing.pem"),
			keyPath:     keyPath,
			expectError: "no such file",
		},
		{
			name:        "missing CA bundle file is rejected at startup",
			certPath:    certPath,
			keyPath:     keyPath,
			caPath:      filepath.Join(t.TempDir(), "missing-ca.pem"),
			expectError: "reading CA bundle",
		},
		{
			name:         "cert and key enable server TLS",
			certPath:     certPath,
			keyPath:      keyPath,
			expectSecure: true,
		},
		{
			name:         "ca additionally enables required mTLS",
			certPath:     certPath,
			keyPath:      keyPath,
			caPath:       caPath,
			expectSecure: true,
			expectMTLS:   true,
		},
		{
			name:            "spiffe ids additionally install the peer verifier",
			certPath:        certPath,
			keyPath:         keyPath,
			caPath:          caPath,
			spiffeIDs:       spiffeID + " , " + spiffeID,
			expectSecure:    true,
			expectMTLS:      true,
			expectAllowList: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildExtProcTLS(tt.certPath, tt.keyPath, tt.caPath, tt.spiffeIDs)
			if tt.expectError != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.expectError)
				}
				if !strings.Contains(err.Error(), tt.expectError) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.expectError)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildExtProcTLS: %v", err)
			}
			if result.Secure != tt.expectSecure {
				t.Errorf("Secure = %v, want %v", result.Secure, tt.expectSecure)
			}
			if !tt.expectSecure {
				if result.Provider != nil {
					t.Errorf("plaintext result must have a nil Provider, got %v", result.Provider)
				}
				if len(result.Options) != 0 {
					t.Errorf("plaintext result must have no Options, got %d", len(result.Options))
				}
				return
			}
			if result.Provider == nil {
				t.Fatal("secure result must have a non-nil Provider")
			}
			if tt.expectAllowList {
				if result.SPIFFEAllowList == nil {
					t.Errorf("expected a non-nil SPIFFEAllowList")
				}
			} else if result.SPIFFEAllowList != nil {
				t.Errorf("expected a nil SPIFFEAllowList, got %v", result.SPIFFEAllowList)
			}

			// Assert option effects through the resulting server config.
			cfg, err := certs.ServerTLSConfig(result.Provider, result.Options...)
			if err != nil {
				t.Fatalf("ServerTLSConfig: %v", err)
			}
			wantClientAuth := tls.NoClientCert
			if tt.expectMTLS {
				wantClientAuth = tls.RequireAndVerifyClientCert
			}
			if cfg.ClientAuth != wantClientAuth {
				t.Errorf("ClientAuth = %v, want %v", cfg.ClientAuth, wantClientAuth)
			}
			if got := cfg.VerifyPeerCertificate != nil; got != tt.expectAllowList {
				t.Errorf("VerifyPeerCertificate installed = %v, want %v", got, tt.expectAllowList)
			}
		})
	}
}
