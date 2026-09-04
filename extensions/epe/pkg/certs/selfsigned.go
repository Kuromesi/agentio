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
package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// selfSignedProvider serves a self-signed certificate generated once at
// construction time.
type selfSignedProvider struct {
	cert *tls.Certificate
	leaf *x509.Certificate
}

// SelfSigned returns a Provider backed by a freshly generated self-signed
// certificate. RootCAs returns a pool containing the certificate itself so a
// client using this Provider's anchors can trust the server.
func SelfSigned() (Provider, error) {
	cert, err := createSelfSignedTLSCertificate()
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing self-signed certificate: %w", err)
	}
	return &selfSignedProvider{cert: &cert, leaf: leaf}, nil
}

func (p *selfSignedProvider) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.cert, nil
}

func (p *selfSignedProvider) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return p.cert, nil
}

// RootCAs returns a fresh pool containing the provider's own certificate.
func (p *selfSignedProvider) RootCAs() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pool.AddCert(p.leaf)
	return pool, nil
}

// createSelfSignedTLSCertificate creates a self-signed cert the server can
// use to serve TLS.
func createSelfSignedTLSCertificate() (tls.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error creating serial number: %v", err)
	}
	now := time.Now()
	notBefore := now.UTC()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"OpenKruise Agents Egress Policy Enforcer"},
		},
		NotBefore:             notBefore,
		NotAfter:              now.Add(time.Hour * 24 * 365 * 10).UTC(), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error generating key: %v", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error creating certificate: %v", err)
	}

	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error marshalling private key: %v", err)
	}
	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certBytes, keyBytes)
}
