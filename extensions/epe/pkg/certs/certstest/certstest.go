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

// Package certstest builds throwaway certificate material for tests.
//
// These are regular (non _test.go) declarations on purpose: pkg/certs,
// pkg/certs/certsource, pkg/credential and pkg/wiring all need them, and
// _test.go symbols are not visible across packages. Keeping one generator here
// also keeps one set of certificate-template decisions, so a future tightening
// in crypto/x509 has a single place to be fixed rather than four.
package certstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"
)

// CA is a throwaway ECDSA certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	Pool *x509.CertPool
}

// New returns a fresh self-signed authority.
func New(t testing.TB) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "certs-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Cert: cert, Key: key, Pool: pool}
}

// LeafSpec describes the throwaway leaf certificate to issue.
type LeafSpec struct {
	Serial      int64
	DNSNames    []string
	URIs        []string
	IPs         []net.IP
	ExtKeyUsage []x509.ExtKeyUsage
}

// Issue signs a leaf certificate with the authority and returns it in both
// tls.Certificate and parsed x509 form.
func (ca *CA) Issue(t testing.TB, spec LeafSpec) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	var uris []*url.URL
	for _, raw := range spec.URIs {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parsing URI SAN %q: %v", raw, err)
		}
		uris = append(uris, u)
	}
	usages := spec.ExtKeyUsage
	if usages == nil {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(spec.Serial),
		Subject:      pkix.Name{CommonName: "certs-test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
		DNSNames:     spec.DNSNames,
		URIs:         uris,
		IPAddresses:  spec.IPs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing leaf certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// Loopback issues a leaf carrying loopback IP SANs, for a server reached at
// 127.0.0.1.
func (ca *CA) Loopback(t testing.TB, serial int64, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	cert, _ := ca.Issue(t, LeafSpec{
		Serial:      serial,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
		IPs:         []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	})
	return cert
}

// SelfSigned returns a standalone self-signed certificate and key in PEM form,
// for cases that need material with no authority behind it.
func SelfSigned(t testing.TB, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "certs-test-self-signed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return encode(t, der, key)
}

// PEM encodes a leaf and its key the way a Secret or a mounted file carries
// them.
func PEM(t testing.TB, cert tls.Certificate) (certPEM, keyPEM []byte) {
	t.Helper()
	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("certificate key is %T, want *ecdsa.PrivateKey", cert.PrivateKey)
	}
	return encode(t, cert.Certificate[0], key)
}

// CAPEM encodes the authority's own certificate as a trust bundle.
func (ca *CA) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

func encode(t testing.TB, der []byte, key *ecdsa.PrivateKey) (certPEM, keyPEM []byte) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// WritePEM persists a leaf certificate and its key to certPath/keyPath.
func WritePEM(t testing.TB, cert tls.Certificate, certPath, keyPath string) {
	t.Helper()
	certPEM, keyPEM := PEM(t, cert)
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert file: %v", err)
	}
}

// WriteBundle writes the authority's trust bundle to path.
func WriteBundle(t testing.TB, ca *CA, path string) {
	t.Helper()
	if err := os.WriteFile(path, ca.CAPEM(), 0o600); err != nil {
		t.Fatalf("writing CA bundle: %v", err)
	}
}
