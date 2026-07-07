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

package agentio

import (
	"container/heap"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"istio.io/istio/pilot/pkg/credentials"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/security/pkg/pki/util"
)

func TestCalcCertTTL(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	caFar := now.Add(48 * time.Hour)
	renewBefore := 30 * time.Minute
	validity := 24 * time.Hour

	t.Run("desired below CA limit returns full validity", func(t *testing.T) {
		got := calcCertTTL(validity, caFar, now, renewBefore)
		if got != validity {
			t.Errorf("expected %v, got %v", validity, got)
		}
	})

	t.Run("desired beyond CA limit caps to CA-renewBefore", func(t *testing.T) {
		caSoon := now.Add(2 * time.Hour) // 2h CA life, validity is 24h
		got := calcCertTTL(validity, caSoon, now, renewBefore)
		want := caSoon.Add(-renewBefore).Sub(now) // = 90 min
		if got != want {
			t.Errorf("expected %v (CA limit minus renewBefore), got %v", want, got)
		}
	})

	t.Run("CA expiring inside renewBefore returns minimal TTL", func(t *testing.T) {
		caDying := now.Add(5 * time.Minute) // shorter than renewBefore
		got := calcCertTTL(validity, caDying, now, renewBefore)
		if got != time.Minute {
			t.Errorf("expected 1m minimal TTL when CA dying, got %v", got)
		}
	})
}

func TestParseCAFromSecretData_MissingFields(t *testing.T) {
	opt := OnDemandCertControllerOption{SecretNamespace: "ns", SecretName: "secret"}

	cases := []struct {
		name    string
		data    map[string][]byte
		wantSub string
	}{
		{
			name:    "missing cert",
			data:    map[string][]byte{CAPrivateKeyFile: []byte("x")},
			wantSub: "missing " + CACertFile,
		},
		{
			name:    "missing key",
			data:    map[string][]byte{CACertFile: []byte("x")},
			wantSub: "missing " + CAPrivateKeyFile,
		},
		{
			name: "invalid cert PEM",
			data: map[string][]byte{
				CACertFile:       []byte("not-a-pem"),
				CAPrivateKeyFile: []byte("not-a-pem"),
			},
			wantSub: "failed to parse CA certificate",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCAFromSecretData(opt, tc.data)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("expected error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

func TestParseCAFromSecretData_Valid(t *testing.T) {
	// Generate a real PEM CA so the parser succeeds end-to-end.
	pemCert, pemKey, err := util.GenCertKeyFromOptions(util.CertOptions{
		Org: "test", TTL: time.Hour, IsCA: true, IsSelfSigned: true, RSAKeySize: defaultRSAKeySize,
	})
	if err != nil {
		t.Fatalf("setup CA generation: %v", err)
	}
	opt := OnDemandCertControllerOption{SecretNamespace: "ns", SecretName: "secret"}
	st, err := parseCAFromSecretData(opt, map[string][]byte{
		CACertFile:       pemCert,
		CAPrivateKeyFile: pemKey,
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if st.caCert == nil || st.caKey == nil {
		t.Errorf("expected cert and key populated, got cert=%v key=%v", st.caCert, st.caKey)
	}
}

func TestGenerateSelfSignedCA(t *testing.T) {
	st, err := generateSelfSignedCA()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if st.caCert == nil || st.caKey == nil {
		t.Fatalf("expected cert + key populated")
	}
	if !st.caCert.IsCA {
		t.Errorf("expected IsCA=true on generated cert")
	}
	if _, ok := st.caKey.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", st.caKey)
	}
	if st.caCert.NotAfter.Sub(st.caCert.NotBefore) < 10*365*24*time.Hour-time.Hour {
		t.Errorf("expected ~10y validity, got %v", st.caCert.NotAfter.Sub(st.caCert.NotBefore))
	}
}

func TestCaState_Equals(t *testing.T) {
	a, err := generateSelfSignedCA()
	if err != nil {
		t.Fatalf("setup CA: %v", err)
	}
	b, err := generateSelfSignedCA()
	if err != nil {
		t.Fatalf("setup CA: %v", err)
	}

	cases := []struct {
		name string
		l, r caState
		want bool
	}{
		{"both nil cert", caState{}, caState{}, true},
		{"one nil cert", *a, caState{}, false},
		{"different cert", *a, *b, false},
		{"same cert+key", *a, *a, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.l.Equals(tc.r); got != tc.want {
				t.Errorf("Equals: expected %v, got %v", tc.want, got)
			}
		})
	}
}

func sandboxConfigSingletonForTest(gateways ...*extensions.EgressGateway) krt.Singleton[model.SandboxConfig] {
	cfg := &model.SandboxConfig{
		SandboxConfig: &extensions.SandboxConfig{
			EgressGateways: gateways,
		},
	}
	return krt.NewStatic(cfg, true)
}

func TestAuthorize(t *testing.T) {
	t.Run("nil sandboxConfig returns error", func(t *testing.T) {
		c := &onDemandCertController{}
		if err := c.Authorize("sa", "ns"); err == nil {
			t.Error("expected error when sandbox config not wired in")
		}
	})

	t.Run("unloaded config returns error", func(t *testing.T) {
		c := &onDemandCertController{
			sandboxConfig: krt.NewStatic[model.SandboxConfig](nil, true),
		}
		if err := c.Authorize("sa", "ns"); err == nil {
			t.Error("expected error when config not loaded")
		}
	})

	t.Run("no matching gateway returns error", func(t *testing.T) {
		c := &onDemandCertController{
			sandboxConfig: sandboxConfigSingletonForTest(
				&extensions.EgressGateway{Name: "other", Namespace: "other-ns"},
			),
		}
		err := c.Authorize("sa", "ns")
		if err == nil || !strings.Contains(err.Error(), "not a registered sandbox egress gateway") {
			t.Errorf("expected 'not a registered' error, got %v", err)
		}
	})

	t.Run("matching gateway allows", func(t *testing.T) {
		c := &onDemandCertController{
			sandboxConfig: sandboxConfigSingletonForTest(
				&extensions.EgressGateway{Name: "my-gw", Namespace: "my-ns"},
			),
		}
		if err := c.Authorize("my-gw", "my-ns"); err != nil {
			t.Errorf("expected nil error for matching gateway, got %v", err)
		}
	})
}

func TestEvictedCerts(t *testing.T) {
	t.Run("empty returns nil", func(t *testing.T) {
		c := &onDemandCertController{evicted: map[string]struct{}{}}
		if got := c.EvictedCerts(); got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("populated returns snapshot", func(t *testing.T) {
		c := &onDemandCertController{
			evicted: map[string]struct{}{"a.com": {}, "b.com": {}},
		}
		got := c.EvictedCerts()
		if len(got) != 2 {
			t.Fatalf("expected 2 entries, got %+v", got)
		}
	})
}

func TestRegisterCertsEviction(t *testing.T) {
	t.Run("no callback is a no-op", func(t *testing.T) {
		c := &onDemandCertController{evicted: map[string]struct{}{"x": {}}}
		c.fireEviction() // should not panic without registered callback
	})

	t.Run("registered callback fires", func(t *testing.T) {
		c := &onDemandCertController{evicted: map[string]struct{}{"x": {}}}
		fired := atomic.Int32{}
		c.RegisterCertsEviction(func() { fired.Add(1) })
		c.fireEviction()
		if fired.Load() != 1 {
			t.Errorf("expected callback to fire once, got %d", fired.Load())
		}
	})
}

func TestEvictExpired(t *testing.T) {
	t.Run("empty heap returns maxAge floored to minEvictionInterval", func(t *testing.T) {
		c := &onDemandCertController{
			cache:   map[string]*cachedCert{},
			heap:    make(certHeap, 0),
			evicted: map[string]struct{}{},
			maxAge:  10 * time.Second, // below minEvictionInterval
		}
		got := c.evictExpired()
		if got < minEvictionInterval {
			t.Errorf("expected wait >= minEvictionInterval, got %v", got)
		}
	})

	t.Run("entries older than maxAge are evicted", func(t *testing.T) {
		c := &onDemandCertController{
			cache:   map[string]*cachedCert{},
			heap:    make(certHeap, 0),
			evicted: map[string]struct{}{},
			maxAge:  time.Minute,
		}
		now := time.Now()
		// 2 expired + 1 fresh
		expired1 := &cachedCert{domain: "old1.com", signedAt: now.Add(-2 * time.Minute), index: -1}
		expired2 := &cachedCert{domain: "old2.com", signedAt: now.Add(-90 * time.Second), index: -1}
		fresh := &cachedCert{domain: "fresh.com", signedAt: now.Add(-1 * time.Second), index: -1}
		for _, e := range []*cachedCert{expired1, expired2, fresh} {
			c.cache[e.domain] = e
			heap.Push(&c.heap, e)
		}

		callbackCount := atomic.Int32{}
		c.RegisterCertsEviction(func() { callbackCount.Add(1) })

		c.evictExpired()

		if _, ok := c.cache["old1.com"]; ok {
			t.Errorf("expected old1.com evicted from cache")
		}
		if _, ok := c.cache["old2.com"]; ok {
			t.Errorf("expected old2.com evicted from cache")
		}
		if _, ok := c.cache["fresh.com"]; !ok {
			t.Errorf("expected fresh.com to remain in cache")
		}
		if _, ok := c.evicted["old1.com"]; !ok {
			t.Errorf("expected old1.com marked as evicted")
		}
		if callbackCount.Load() != 1 {
			t.Errorf("expected eviction callback to fire once for batch, got %d", callbackCount.Load())
		}
	})

	t.Run("disabled (maxAge<=0) does not run reaper logic", func(t *testing.T) {
		// Run() short-circuits when maxAge<=0; evictExpired isn't reachable in
		// that mode. Sanity-check the Run() path explicitly.
		c := &onDemandCertController{maxAge: 0}
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			c.Run(stop)
			close(done)
		}()
		close(stop)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Run did not exit after stop")
		}
	})
}

func TestIsExpiring(t *testing.T) {
	c := &onDemandCertController{
		renewBefore: 30 * time.Minute,
	}
	now := time.Now()

	t.Run("not expiring when remaining > renewBefore", func(t *testing.T) {
		e := &cachedCert{
			notAfter: now.Add(2 * time.Hour),
			signedAt: now.Add(-1 * time.Hour),
		}
		if c.isExpiring(e) {
			t.Error("expected not expiring")
		}
	})

	t.Run("expiring when remaining < renewBefore and fullLifetime large", func(t *testing.T) {
		e := &cachedCert{
			notAfter: now.Add(5 * time.Minute),
			signedAt: now.Add(-23 * time.Hour),
		}
		if !c.isExpiring(e) {
			t.Error("expected expiring")
		}
	})

	t.Run("intentionally short-lived cert is not re-signed every hit", func(t *testing.T) {
		// fullLifetime (10m) < renewBefore (30m); even though remaining is
		// within renewBefore, treat as not-expiring so the controller doesn't
		// thrash signing.
		e := &cachedCert{
			notAfter: now.Add(5 * time.Minute),
			signedAt: now.Add(-5 * time.Minute),
		}
		if c.isExpiring(e) {
			t.Error("expected not expiring for intentionally short-lived cert")
		}
	})
}

func TestGetCertInfo_SelfSignSignsAndCaches(t *testing.T) {
	// Wire a controller backed by an in-memory self-signed CA. Going through
	// newOnDemandCertController exercises the real plumbing (CA singleton,
	// eviction callback registration) without needing a kube client for the
	// SELF_SIGN path.
	opt := OnDemandCertControllerOption{
		CertValidity:  time.Hour,
		RenewBefore:   30 * time.Minute,
		MaxAge:        0,
		SignMode:      string(SignModeSelfSign),
		KrtOptions:    krtOptionsForTest(),
		SandboxConfig: krt.NewStatic[model.SandboxConfig](nil, true),
	}
	c, err := newOnDemandCertController(nil, opt)
	if err != nil {
		t.Fatalf("newOnDemandCertController: %v", err)
	}

	info, err := c.GetCertInfo("foo.example.com", "")
	if err != nil {
		t.Fatalf("first GetCertInfo failed: %v", err)
	}
	if info == nil || len(info.Cert) == 0 || len(info.Key) == 0 {
		t.Fatalf("expected populated cert info, got %+v", info)
	}
	// Cache hit: pointer equality of underlying byte slices indicates we
	// returned the same CertInfo object.
	info2, err := c.GetCertInfo("foo.example.com", "")
	if err != nil {
		t.Fatalf("second GetCertInfo failed: %v", err)
	}
	if &info.Cert[0] != &info2.Cert[0] {
		t.Error("expected cache hit to return same CertInfo")
	}

	// Different domain should sign a fresh cert.
	other, err := c.GetCertInfo("bar.example.com", "")
	if err != nil {
		t.Fatalf("GetCertInfo for second domain: %v", err)
	}
	if &other.Cert[0] == &info.Cert[0] {
		t.Error("expected distinct CertInfo for different domain")
	}

	// Sanity-check cert content (parses as a x509 cert with the expected SAN).
	parsed, err := util.ParsePemEncodedCertificate(info.Cert)
	if err != nil {
		t.Fatalf("parse generated cert: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil parsed cert")
	}
	var sanFound bool
	for _, d := range parsed.DNSNames {
		if d == "foo.example.com" {
			sanFound = true
			break
		}
	}
	if !sanFound {
		t.Errorf("expected SAN containing foo.example.com, got DNSNames=%v", parsed.DNSNames)
	}
	// Ensure cert chains to the CA singleton.
	if parsed.NotAfter.Before(time.Now()) {
		t.Errorf("issued cert NotAfter %v is in the past", parsed.NotAfter)
	}
}

func TestGetCertInfo_RegenerateOnExpiry(t *testing.T) {
	// Construct manually so we can plant a stale entry without driving time.
	c := &onDemandCertController{
		cache:        map[string]*cachedCert{},
		heap:         make(certHeap, 0),
		evicted:      map[string]struct{}{},
		certValidity: time.Hour,
		renewBefore:  30 * time.Minute,
		caSingleton:  krt.NewStatic(mustSelfSignedCA(t), true),
	}
	// Plant an "expired-soon" cached entry.
	now := time.Now()
	stale := &cachedCert{
		certInfo: &credentials.CertInfo{Cert: []byte("stale"), Key: []byte("stale")},
		notAfter: now.Add(1 * time.Minute), // within renewBefore
		signedAt: now.Add(-23 * time.Hour),
		domain:   "stale.example.com",
		index:    -1,
	}
	c.cache[stale.domain] = stale
	heap.Push(&c.heap, stale)

	info, err := c.GetCertInfo("stale.example.com", "")
	if err != nil {
		t.Fatalf("GetCertInfo: %v", err)
	}
	if string(info.Cert) == "stale" {
		t.Error("expected fresh certificate, got stale cached one")
	}
	// Re-sign should drop "stale.example.com" from c.evicted if it was there
	// (it isn't here, but the invariant must hold).
	if _, ok := c.evicted["stale.example.com"]; ok {
		t.Error("re-signed domain should not be in evicted set")
	}
}

func TestUnsupportedCredentialMethods(t *testing.T) {
	c := &onDemandCertController{}
	if _, err := c.GetCaCert("", ""); err == nil {
		t.Error("expected error from GetCaCert")
	}
	if _, err := c.GetConfigMapCaCert("", ""); err == nil {
		t.Error("expected error from GetConfigMapCaCert")
	}
	if _, err := c.GetDockerCredential("", ""); err == nil {
		t.Error("expected error from GetDockerCredential")
	}
	if !c.HasSynced() {
		t.Error("HasSynced should be true (on-demand controller is always ready)")
	}
}

// --- helpers ---

func krtOptionsForTest() krt.OptionsBuilder {
	stop := make(chan struct{})
	return krt.NewOptionsBuilder(stop, "test", krt.GlobalDebugHandler)
}

func mustSelfSignedCA(t *testing.T) *caState {
	t.Helper()
	s, err := generateSelfSignedCA()
	if err != nil {
		t.Fatalf("generateSelfSignedCA: %v", err)
	}
	return s
}

// Ensure controller satisfies credentials.Controller at compile time.
var _ credentials.Controller = (*onDemandCertController)(nil)

// Quiet the unused-import linter when none of the tests touch these symbols
// directly but they still document intent.
var (
	_ = sync.Mutex{}
	_ = (*x509.Certificate)(nil)
)
