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

package ca

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/openkruise/agentio/pkg/security/internal/casecret"
	"github.com/openkruise/agentio/pkg/security/pki"
)

// newTestAuthority builds an Authority directly without the Kubernetes plumbing LoadOrCreateAuthority needs.
func newTestAuthority(t *testing.T, leafLifetime, leafRenewBefore time.Duration) *Authority {
	t.Helper()
	now := time.Now()
	secret, err := casecret.New("agentio-system", "ca", workloadCAKeys, "Agentio Root CA", 10*365*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	signingCA, err := pki.ParseSigningCA(secret.Data[caCertKey], secret.Data[caKeyKey], now)
	if err != nil {
		t.Fatal(err)
	}
	authority := &Authority{
		ca:              signingCA,
		rootPEM:         append([]byte(nil), secret.Data[caCertKey]...),
		leafLifetime:    leafLifetime,
		leafRenewBefore: leafRenewBefore,
		serverNames:     []string{"agentiod", "agentiod.agentio-system.svc", "localhost"},
	}
	authority.serverCert, err = issueServerCertificate(
		signingCA, authority.rootPEM, authority.serverNames, leafLifetime, now)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

// Renewal must depend on the certificate's own expiry, not on a CA change.
func TestServerCertificateRenewsWithoutCAChange(t *testing.T) {
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	original := authority.serverCert.Leaf
	if original == nil {
		t.Fatal("server certificate has no parsed leaf; the renewal check reads NotAfter from it")
	}
	caRevision := authority.ca.Revision()

	// Outside the renewal window: nothing should change.
	renewed, err := authority.renewServerCertificate(original.NotAfter.Add(-20 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if renewed {
		t.Fatal("certificate renewed far outside the renewal window")
	}
	if authority.serverCert.Leaf.SerialNumber.Cmp(original.SerialNumber) != 0 {
		t.Fatal("certificate replaced without renewal being reported")
	}

	// Inside the renewal window: a fresh certificate, still signed by the
	// unchanged CA.
	now := original.NotAfter.Add(-time.Hour)
	renewed, err = authority.renewServerCertificate(now)
	if err != nil {
		t.Fatal(err)
	}
	if !renewed {
		t.Fatal("certificate was not renewed inside the renewal window")
	}
	fresh := authority.serverCert.Leaf
	if fresh.SerialNumber.Cmp(original.SerialNumber) == 0 {
		t.Fatal("renewal reused the previous serial number")
	}
	if !fresh.NotAfter.After(original.NotAfter) {
		t.Fatalf("renewed certificate does not outlive the old one: %s vs %s", fresh.NotAfter, original.NotAfter)
	}
	if authority.ca.Revision() != caRevision {
		t.Fatal("renewal rotated the CA, which it must not touch")
	}
}

// A renewed certificate has to remain usable: same names, and verifiable against the same root.
func TestRenewedServerCertificateStaysValidForTheSameNames(t *testing.T) {
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	original := authority.serverCert.Leaf

	if _, err := authority.renewServerCertificate(original.NotAfter.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	fresh := authority.serverCert.Leaf

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.rootPEM) {
		t.Fatal("failed to add authority root certificate")
	}
	for _, name := range authority.serverNames {
		if _, err := fresh.Verify(x509.VerifyOptions{
			Roots:       roots,
			DNSName:     name,
			CurrentTime: fresh.NotBefore.Add(time.Minute),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Fatalf("renewed certificate does not verify for %q: %v", name, err)
		}
	}
}

// TLSConfig serves whatever is currently installed, so a renewal has to be
// visible to new handshakes without restarting the listener.
func TestTLSConfigServesTheRenewedCertificate(t *testing.T) {
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	before, err := authority.TLSConfig().GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	original := authority.serverCert.Leaf

	if _, err := authority.renewServerCertificate(original.NotAfter.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	after, err := authority.TLSConfig().GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if after.Leaf.SerialNumber.Cmp(before.Leaf.SerialNumber) == 0 {
		t.Fatal("TLSConfig still serves the pre-renewal certificate")
	}
}

// An already-expired certificate must be replaced rather than left in place.
func TestExpiredServerCertificateIsReplaced(t *testing.T) {
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	original := authority.serverCert.Leaf

	renewed, err := authority.renewServerCertificate(original.NotAfter.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !renewed {
		t.Fatal("an expired certificate was not replaced")
	}
	if !authority.serverCert.Leaf.NotAfter.After(original.NotAfter.Add(time.Hour)) {
		t.Fatal("replacement certificate is also expired")
	}
}

// The default renewal window is derived from the lifetime when it is not
// configured, so a caller that only sets a lifetime still gets renewal.
func TestLeafRenewBeforeDefaultsFromLifetime(t *testing.T) {
	options := AuthorityOptions{LeafLifetime: 90 * time.Minute}
	applyAuthorityDefaults(&options)
	if options.LeafRenewBefore != 30*time.Minute {
		t.Fatalf("LeafRenewBefore = %s, want a third of the lifetime", options.LeafRenewBefore)
	}

	// A nonsensical window (at or beyond the lifetime) also falls back, otherwise
	// every certificate would be born already due for renewal.
	options = AuthorityOptions{LeafLifetime: time.Hour, LeafRenewBefore: 2 * time.Hour}
	applyAuthorityDefaults(&options)
	if options.LeafRenewBefore != 20*time.Minute {
		t.Fatalf("LeafRenewBefore = %s, want a third of the lifetime", options.LeafRenewBefore)
	}
}
