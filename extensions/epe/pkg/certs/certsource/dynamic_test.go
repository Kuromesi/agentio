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
package certsource

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/certs"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certstest"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
)

// fakeSource is a Source whose bytes and error can be swapped while a certs.Provider
// built from it is already serving.
type fakeSource struct {
	mu            sync.Mutex
	cert, key, ca []byte
	err           error
	loads         atomic.Int32
}

func (f *fakeSource) Load() (certPEM, keyPEM, caPEM []byte, err error) {
	f.loads.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cert, f.key, f.ca, f.err
}

func (f *fakeSource) Name() string { return "fake" }

func (f *fakeSource) set(cert, key, ca []byte, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cert, f.key, f.ca, f.err = cert, key, ca, err
}

// newTestDynamic builds a certs.Provider that reloads fast enough for a test and is
// torn down with the test.
func newTestDynamic(t *testing.T, src Source) (certs.Provider, chan struct{}) {
	t.Helper()
	triggers := make(chan struct{}, 1)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	return newDynamic(src, triggers, stop, 20*time.Millisecond), triggers
}

// awaitClientCert polls until the presented certificate count matches want.
func awaitClientCert(t *testing.T, p certs.Provider, wantCount int) *tls.Certificate {
	t.Helper()
	var got *tls.Certificate
	testsupport.Eventually(t, 3*time.Second, func() error {
		cert, err := p.GetClientCertificate(&tls.CertificateRequestInfo{})
		if err != nil {
			return err
		}
		if len(cert.Certificate) != wantCount {
			return fmt.Errorf("presented certificate count = %d, want %d", len(cert.Certificate), wantCount)
		}
		got = cert
		return nil
	})
	return got
}

// Nothing configured is a normal steady state, not a failure: no client
// identity, and nil anchors so the pipeline falls back to the system pool.
func TestDynamicWithNothingPresentsNoIdentityAndSystemAnchors(t *testing.T) {
	p, _ := newTestDynamic(t, &fakeSource{})

	cert, err := p.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if len(cert.Certificate) != 0 {
		t.Errorf("presented %d certificates, want 0", len(cert.Certificate))
	}
	pool, err := p.RootCAs()
	if err != nil {
		t.Fatalf("RootCAs: %v", err)
	}
	if pool != nil {
		t.Error("RootCAs returned a pool with nothing configured; want nil for the system pool")
	}
}

// The client identity and the trust anchors are independent axes: a source
// carrying only a CA must still supply anchors, presenting no identity.
func TestDynamicServesCAWithoutClientCertificate(t *testing.T) {
	ca := certstest.New(t)
	src := &fakeSource{}
	src.set(nil, nil, ca.CAPEM(), nil)

	p, triggers := newTestDynamic(t, src)
	triggers <- struct{}{}

	testsupport.Eventually(t, 3*time.Second, func() error {
		pool, err := p.RootCAs()
		if err != nil {
			return err
		}
		if pool == nil {
			return fmt.Errorf("anchors from a CA-only source not yet available")
		}
		return nil
	})

	cert, err := p.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if len(cert.Certificate) != 0 {
		t.Errorf("presented %d certificates from a CA-only source, want 0", len(cert.Certificate))
	}
}

// The defect the whole change exists to fix, at the holder level.
func TestDynamicPicksUpMaterialAppearingLater(t *testing.T) {
	ca := certstest.New(t)
	leaf, _ := ca.Issue(t, certstest.LeafSpec{Serial: 7001})
	src := &fakeSource{}

	p, triggers := newTestDynamic(t, src)
	awaitClientCert(t, p, 0)

	certPEM, keyPEM := certstest.PEM(t, leaf)
	src.set(certPEM, keyPEM, ca.CAPEM(), nil)
	triggers <- struct{}{}

	got := awaitClientCert(t, p, 1)
	if got.Leaf == nil {
		t.Fatal("presented certificate carries no parsed leaf")
	}
	if got.Leaf.SerialNumber.Int64() != 7001 {
		t.Errorf("serial = %d, want 7001", got.Leaf.SerialNumber.Int64())
	}
}

// A torn rotation must not cost the client its identity.
func TestDynamicKeepsPreviousCertificateOnParseFailure(t *testing.T) {
	ca := certstest.New(t)
	leaf, _ := ca.Issue(t, certstest.LeafSpec{Serial: 7101})
	certPEM, keyPEM := certstest.PEM(t, leaf)
	src := &fakeSource{}
	src.set(certPEM, keyPEM, nil, nil)

	p, triggers := newTestDynamic(t, src)
	awaitClientCert(t, p, 1)

	src.set([]byte("not a pem"), []byte("not a pem"), nil, nil)
	triggers <- struct{}{}
	time.Sleep(200 * time.Millisecond)

	got := awaitClientCert(t, p, 1)
	if got.Leaf.SerialNumber.Int64() != 7101 {
		t.Errorf("serial = %d, want the previous 7101", got.Leaf.SerialNumber.Int64())
	}
}

// A source that cannot be read at all is "存在问题": the anchors drop to the
// system pool rather than retaining a stale private CA.
func TestDynamicFallsBackToSystemAnchorsOnSourceError(t *testing.T) {
	ca := certstest.New(t)
	leaf, _ := ca.Issue(t, certstest.LeafSpec{Serial: 7201})
	certPEM, keyPEM := certstest.PEM(t, leaf)
	src := &fakeSource{}
	src.set(certPEM, keyPEM, ca.CAPEM(), nil)

	p, triggers := newTestDynamic(t, src)
	testsupport.Eventually(t, 3*time.Second, func() error {
		if pool, _ := p.RootCAs(); pool == nil {
			return fmt.Errorf("initial anchors not yet loaded")
		}
		return nil
	})

	src.set(nil, nil, nil, errors.New("permission denied"))
	triggers <- struct{}{}

	testsupport.Eventually(t, 3*time.Second, func() error {
		pool, err := p.RootCAs()
		if err != nil {
			return err
		}
		if pool != nil {
			return fmt.Errorf("anchors have not fallen back to the system pool after a source error")
		}
		return nil
	})

	// The identity survives a transient read failure.
	if got := awaitClientCert(t, p, 1); got.Leaf.SerialNumber.Int64() != 7201 {
		t.Errorf("serial = %d, want the retained 7201", got.Leaf.SerialNumber.Int64())
	}
}

// An unparseable CA bundle goes to the system pool, NOT to an empty pool that
// would trust nothing. This pins the invariant the deleted
// TestLoadCACertPool_InvalidCA used to cover.
func TestDynamicUnparseableCAYieldsSystemAnchorsNotEmptyPool(t *testing.T) {
	src := &fakeSource{}
	src.set(nil, nil, []byte("not a pem"), nil)

	p, triggers := newTestDynamic(t, src)
	triggers <- struct{}{}
	time.Sleep(200 * time.Millisecond)

	pool, err := p.RootCAs()
	if err != nil {
		t.Fatalf("RootCAs: %v", err)
	}
	if pool != nil {
		t.Error("an unparseable CA bundle produced a non-nil pool; want nil so the system pool is used")
	}
}

// Re-pins the invariant the deleted TestNewMTLSClient_CertKeyMismatch covered.
func TestDynamicRejectsCertKeyMismatch(t *testing.T) {
	ca := certstest.New(t)
	one, _ := ca.Issue(t, certstest.LeafSpec{Serial: 7301})
	two, _ := ca.Issue(t, certstest.LeafSpec{Serial: 7302})
	certPEM, _ := certstest.PEM(t, one)
	_, keyPEM := certstest.PEM(t, two)

	src := &fakeSource{}
	src.set(certPEM, keyPEM, nil, nil)

	p, triggers := newTestDynamic(t, src)
	triggers <- struct{}{}
	time.Sleep(200 * time.Millisecond)

	cert, err := p.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if len(cert.Certificate) != 0 {
		t.Error("a certificate paired with a foreign key was accepted as the client identity")
	}
}

// Server semantics differ from client semantics: presenting an empty
// certificate would make crypto/tls treat it as real and index Certificate[0].
func TestDynamicGetCertificateFailsWithoutMaterial(t *testing.T) {
	p, _ := newTestDynamic(t, &fakeSource{})

	if _, err := p.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Error("GetCertificate succeeded with no material; a server must fail instead of presenting an empty certificate")
	}
}

// The reload loop must be bounded by stop, or every construction leaks a
// goroutine and a ticker for the life of the process.
func TestDynamicStopsReloadingWhenStopped(t *testing.T) {
	src := &fakeSource{}
	stop := make(chan struct{})
	newDynamic(src, nil, stop, 10*time.Millisecond)

	time.Sleep(100 * time.Millisecond)
	close(stop)
	time.Sleep(100 * time.Millisecond)

	settled := src.loads.Load()
	time.Sleep(200 * time.Millisecond)
	if grew := src.loads.Load() - settled; grew != 0 {
		t.Errorf("source was loaded %d more times after stop closed; the reload loop is unbounded", grew)
	}
}
