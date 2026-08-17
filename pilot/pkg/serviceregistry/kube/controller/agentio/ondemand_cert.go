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
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"istio.io/istio/pilot/pkg/credentials"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/util/sets"
	"istio.io/istio/security/pkg/pki/util"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type OnDemandCertController interface {
	Authorize(string, string) error
	GetCertInfo(string, string) (*credentials.CertInfo, error)
	EvictedCerts() []string
	RegisterCertsEviction(fn func())
}

type OnDemandCertSignMode string

const (
	SignModeSecret   OnDemandCertSignMode = "SECRET"
	SignModeSelfSign OnDemandCertSignMode = "SELF_SIGN"
)

const (
	CACertFile       = "ca.crt"
	CAPrivateKeyFile = "ca.key"

	defaultRSAKeySize  = 2048
	selfSignCAValidity = 10 * 365 * 24 * time.Hour

	// minEvictionInterval floors the reaper's next-wake delay so spread-out
	// expirations get batched into a single broadcast push instead of one
	// push per cert; certs may live up to this long past maxAge.
	minEvictionInterval = 30 * time.Second
)

type OnDemandCertControllerOption struct {
	SecretNamespace string
	SecretName      string
	CertValidity    time.Duration
	RenewBefore     time.Duration
	// MaxAge bounds how long a cert can stay cached from the moment it was
	// signed; the reaper evicts entries older than this regardless of usage.
	// <=0 disables eviction.
	MaxAge     time.Duration
	SignMode   string
	KrtOptions krt.OptionsBuilder
	// AgentioConfig is consulted by Authorize to gate on-demand cert pulls:
	// only proxies whose ServiceAccount/Namespace match a configured
	// EgressGateway (name == SA, namespace == NS) are allowed.
	AgentioConfig krt.Singleton[model.AgentioConfig]
}

type caState struct {
	caCert *x509.Certificate
	caKey  crypto.PrivateKey
	// caCertPEM is the PEM encoding of caCert, cached so generateCert does not
	// re-encode on every signing call. Built once when the caState is constructed
	// (either from the loaded secret bytes or from the freshly generated cert).
	caCertPEM []byte
}

func (caState) ResourceName() string {
	return "ca-state"
}

// Equals is picked up by krt.Equal so derived collections (including the
// Singleton wrapping this state) suppress noop updates automatically.
func (c caState) Equals(other caState) bool {
	if c.caCert == nil || other.caCert == nil {
		return c.caCert == other.caCert
	}
	if !c.caCert.Equal(other.caCert) {
		return false
	}
	// crypto.PrivateKey is `any`; concrete types (*rsa/*ecdsa/ed25519) all
	// implement Equal(crypto.PrivateKey) bool since Go 1.15. Assert through
	// that shape rather than coupling to a single algorithm.
	ce, ok := c.caKey.(interface{ Equal(crypto.PrivateKey) bool })
	if !ok {
		return false
	}
	return ce.Equal(other.caKey)
}

type cachedCert struct {
	certInfo *credentials.CertInfo
	notAfter time.Time
	domain   string
	// signedAt is when this entry was first issued. The reaper evicts entries
	// whose age (now - signedAt) exceeds maxAge — cache hits do NOT bump it,
	// so envoy reconnect (which re-fetches every InitialResourceVersions entry)
	// can't keep stale domains alive forever.
	signedAt time.Time
	// index is the position in certHeap; -1 means not in heap.
	index int
}

// onDemandCertController reads a CA cert/key from a specified secret and uses them
// to sign certificates on demand for any requested domain.
type onDemandCertController struct {
	// mu guards cache, heap, and evicted together.
	mu    sync.RWMutex
	cache map[string]*cachedCert
	// sf deduplicates concurrent generateCert calls for the same domain so
	// only one RSA keygen runs while others wait for the result.
	sf singleflight.Group
	// heap keeps cached certs ordered by signedAt ascending so the reaper can
	// pop the oldest entries in O(log n) without scanning the whole cache.
	heap certHeap
	// evicted tracks domains the reaper has removed since they were last in
	// cache. EvictedCerts() snapshots it for SDS eviction pushes; a fresh sign
	// drops the domain from the set (it's back in cache, no longer "evicted").
	evicted sets.Set[string]

	certValidity time.Duration
	renewBefore  time.Duration
	maxAge       time.Duration

	caSingleton krt.Singleton[caState]
	// agentioConfig is the live agentio config used by Authorize to decide
	// whether a (SA, NS) pair belongs to a registered EgressGateway.
	agentioConfig krt.Singleton[model.AgentioConfig]

	// onEviction is invoked after the reaper evicts at least one entry. Bootstrap
	// injects a callback that fires an XDS broadcast push so SDS generator can
	// emit removed_resources for the evicted domains.
	evictionMu sync.Mutex
	onEviction func()
}

var (
	_ credentials.Controller = &onDemandCertController{}
	_ OnDemandCertController = &onDemandCertController{}
)

func newOnDemandCertController(kc kube.Client, opt OnDemandCertControllerOption) (*onDemandCertController, error) {
	c := &onDemandCertController{
		cache:         make(map[string]*cachedCert),
		heap:          make(certHeap, 0),
		evicted:       sets.New[string](),
		certValidity:  opt.CertValidity,
		renewBefore:   opt.RenewBefore,
		maxAge:        opt.MaxAge,
		agentioConfig: opt.AgentioConfig,
	}

	switch OnDemandCertSignMode(opt.SignMode) {
	case SignModeSecret:
		c.caSingleton = newDelayedCASecretSingleton(kc, opt)
	case SignModeSelfSign:
		ca, err := generateSelfSignedCA()
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed CA: %v", err)
		}
		c.caSingleton = krt.NewStatic(ca, true, opt.KrtOptions.WithName("OnDemandCert_SelfSign")...)
	default:
		return nil, fmt.Errorf("unknown sign mode: %s", opt.SignMode)
	}

	c.caSingleton.Register(func(o krt.Event[caState]) {
		c.mu.Lock()
		// Mark every currently-cached domain as evicted so SDS surfaces
		// removed_resources for them on the broadcast push below. Envoy will
		// re-subscribe on its next match, and GetCertInfo will sign fresh with
		// the new CA. Each re-sign drops the domain from c.evicted naturally.
		for domain, entry := range c.cache {
			c.evicted.Insert(domain)
			entry.index = -1
		}
		evictedCount := len(c.evicted)
		c.cache = make(map[string]*cachedCert)
		c.heap = c.heap[:0]
		c.mu.Unlock()
		if evictedCount > 0 {
			c.fireEviction()
		}
		log.Infof("CA updated, marked %d cached certificates for refresh", evictedCount)
	})

	log.Infof("OnDemandCertController running in %s mode", opt.SignMode)
	return c, nil
}

func newCASecretSingleton(kc kube.Client, opt OnDemandCertControllerOption) krt.Singleton[caState] {
	clt := kclient.NewFiltered[*v1.Secret](kc, kclient.Filter{
		ObjectFilter:  kc.ObjectFilter(),
		Namespace:     opt.SecretNamespace,
		FieldSelector: fmt.Sprintf("metadata.name=%s", opt.SecretName),
	})
	secrets := krt.WrapClient(clt, opt.KrtOptions.WithName("MITM_Secret_"+opt.SecretName)...)
	clt.Start(opt.KrtOptions.Stop())

	secretKey := types.NamespacedName{Namespace: opt.SecretNamespace, Name: opt.SecretName}.String()
	return krt.NewSingleton(func(ctx krt.HandlerContext) *caState {
		secret := ptr.Flatten(krt.FetchOne(ctx, secrets, krt.FilterKey(secretKey)))
		if secret == nil {
			log.Warnf("CA secret %s/%s not found", opt.SecretNamespace, opt.SecretName)
			return nil
		}
		ca, err := parseCAFromSecretData(opt, secret.Data)
		if err != nil {
			log.Errorf("Failed to parse CA from secret %s/%s: %v", opt.SecretNamespace, opt.SecretName, err)
			return nil
		}
		log.Infof("Loaded CA from secret %s/%s", opt.SecretNamespace, opt.SecretName)
		return ca
	}, opt.KrtOptions.WithName("OnDemandCert_CA")...)
}

func newDelayedCASecretSingleton(kc kube.Client, opt OnDemandCertControllerOption) krt.Singleton[caState] {
	callback := func() krt.Singleton[caState] {
		return newCASecretSingleton(kc, opt)
	}

	waitRbacReady := func(ctx context.Context) bool {
		_, err := kc.Kube().CoreV1().Secrets(opt.SecretNamespace).Get(ctx, opt.SecretName, metav1.GetOptions{})
		return !errors.IsForbidden(err)
	}

	syncer := krt.NewPollingSyncer("MITM_Secret", waitRbacReady, 30*time.Second)
	delayedSecretSingleton := krt.NewDelayedSingleton(syncer, callback, opt.KrtOptions.Stop())
	return delayedSecretSingleton
}

func generateSelfSignedCA() (*caState, error) {
	opts := util.CertOptions{
		TTL:          selfSignCAValidity,
		Org:          "Istio Sandbox",
		IsCA:         true,
		IsSelfSigned: true,
		RSAKeySize:   defaultRSAKeySize,
	}

	pemCert, pemKey, err := util.GenCertKeyFromOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate self-signed CA: %v", err)
	}

	cert, err := util.ParsePemEncodedCertificate(pemCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA cert: %v", err)
	}
	key, err := util.ParsePemEncodedKey(pemKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA key: %v", err)
	}

	return &caState{caCert: cert, caKey: key, caCertPEM: pemCert}, nil
}

func parseCAFromSecretData(opt OnDemandCertControllerOption, data map[string][]byte) (*caState, error) {
	caCertPEM, ok := data[CACertFile]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s missing %s", opt.SecretNamespace, opt.SecretName, CACertFile)
	}
	caKeyPEM, ok := data[CAPrivateKeyFile]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s missing %s", opt.SecretNamespace, opt.SecretName, CAPrivateKeyFile)
	}

	cert, err := util.ParsePemEncodedCertificate(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}
	key, err := util.ParsePemEncodedKey(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %v", err)
	}

	// Keep the original secret PEM bytes so generateCert can append it to every
	// leaf without re-encoding. If the secret stores a multi-cert bundle
	// (e.g. sub-CA followed by intermediate), this preserves the full chain.
	return &caState{caCert: cert, caKey: key, caCertPEM: caCertPEM}, nil
}

func (c *onDemandCertController) GetCertInfo(name, _ string) (*credentials.CertInfo, error) {
	// Fast path: read lock for cache hits.
	c.mu.RLock()
	if cached, ok := c.cache[name]; ok && !c.isExpiring(cached) {
		log.Debugf("Cache hit for domain %s, notAfter=%v", name, cached.notAfter)
		c.mu.RUnlock()
		return cached.certInfo, nil
	}
	c.mu.RUnlock()

	// Slow path: singleflight deduplicates concurrent keygen for the same domain.
	// RSA keygen runs outside the lock so other domains' cache hits are not blocked.
	v, err, _ := c.sf.Do(name, func() (any, error) {
		// Double-check: another goroutine may have signed while we waited.
		c.mu.RLock()
		if cached, ok := c.cache[name]; ok && !c.isExpiring(cached) {
			c.mu.RUnlock()
			return cached.certInfo, nil
		}
		c.mu.RUnlock()

		log.Debugf("Generating new certificate for domain %s", name)
		entry, err := c.generateCert(name)
		if err != nil {
			return nil, err
		}
		entry.domain = name
		entry.signedAt = time.Now()
		entry.index = -1

		c.mu.Lock()
		if old, ok := c.cache[name]; ok && old.index >= 0 {
			heap.Remove(&c.heap, old.index)
		}
		c.cache[name] = entry
		heap.Push(&c.heap, entry)
		c.evicted.Delete(name)
		c.mu.Unlock()

		log.Debugf("Generated certificate for domain %s, notAfter=%v", name, entry.notAfter)
		return entry.certInfo, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*credentials.CertInfo), nil
}

func (c *onDemandCertController) isExpiring(entry *cachedCert) bool {
	remaining := time.Until(entry.notAfter)
	if remaining < c.renewBefore {
		// If this cert was intentionally minted short-lived (its full lifetime is
		// already less than renewBefore — happens when the CA itself is dying and
		// calcCertTTL capped the TTL), don't tag it as "expiring" or every cache
		// hit re-signs and starves the controller. Let envoy use the short cert
		// until it actually expires; subsequent signs will keep producing equally
		// short certs until the CA rotates.
		fullLifetime := entry.notAfter.Sub(entry.signedAt)
		if fullLifetime > 0 && fullLifetime < c.renewBefore {
			return false
		}
		log.Debugf("Certificate expiring soon, remaining=%v, renewBefore=%v", remaining, c.renewBefore)
		return true
	}
	return false
}

func (c *onDemandCertController) GetCaCert(_, _ string) (*credentials.CertInfo, error) {
	return nil, fmt.Errorf("on-demand cert controller does not support GetCaCert")
}

func (c *onDemandCertController) GetConfigMapCaCert(_, _ string) (*credentials.CertInfo, error) {
	return nil, fmt.Errorf("on-demand cert controller does not support GetConfigMapCaCert")
}

func (c *onDemandCertController) GetDockerCredential(_, _ string) ([]byte, error) {
	return nil, fmt.Errorf("on-demand cert controller does not support GetDockerCredential")
}

// Authorize gates on-demand cert pulls by ServiceAccount/Namespace. Only
// proxies whose identity matches a configured EgressGateway are allowed —
// the convention is SA == Deployment name == EgressGateway.name and the
// namespace must match exactly. Domain-level scoping (include_hosts) is
// applied separately by the caller via IsAllowedOnDemandDomain.
func (c *onDemandCertController) Authorize(serviceAccount, namespace string) error {
	if c.agentioConfig == nil {
		return fmt.Errorf("on-demand cert controller has no agentio config wired in")
	}
	cfg := c.agentioConfig.Get()
	if cfg == nil {
		return fmt.Errorf("agentio config not loaded yet")
	}
	for _, g := range cfg.GetEgressGateways() {
		if g.GetName() == serviceAccount && g.GetNamespace() == namespace {
			return nil
		}
	}
	return fmt.Errorf("identity %s/%s is not a registered sandbox egress gateway", namespace, serviceAccount)
}

func (c *onDemandCertController) generateCert(domain string) (*cachedCert, error) {
	ca := c.caSingleton.Get()
	if ca == nil {
		return nil, fmt.Errorf("CA certificate/key not loaded, cannot sign cert for %s", domain)
	}

	now := time.Now()
	ttl := calcCertTTL(c.certValidity, ca.caCert.NotAfter, now, c.renewBefore)
	opts := util.CertOptions{
		Host:       domain,
		NotBefore:  now,
		TTL:        ttl,
		SignerCert: ca.caCert,
		SignerPriv: ca.caKey,
		IsServer:   true,
		RSAKeySize: defaultRSAKeySize,
	}

	pemCert, pemKey, err := util.GenCertKeyFromOptions(opts)
	if err != nil {
		log.Errorf("Failed to generate certificate for domain %s: %v", domain, err)
		return nil, err
	}

	// Append the signing CA chain so the TLS handshake delivers [leaf, ...CA bundle].
	// Without this, clients with only the root CA in their truststore cannot build
	// the chain — they need the intermediate's public key to verify the leaf's
	// signature, and Go/curl/OpenSSL do not fetch intermediates via AIA.
	// ca.caCertPEM is the original secret bundle (parseCAFromSecretData) or the
	// freshly emitted PEM (generateSelfSignedCA), so multi-cert bundles preserve
	// every intermediate above the signing cert automatically.
	chain := util.AppendCertByte(pemCert, ca.caCertPEM)

	return &cachedCert{
		certInfo: &credentials.CertInfo{
			Cert: chain,
			Key:  pemKey,
		},
		notAfter: now.Add(ttl),
	}, nil
}

func calcCertTTL(certValidity time.Duration, caNotAfter time.Time, now time.Time, renewBefore time.Duration) time.Duration {
	desired := now.Add(certValidity)
	caLimit := caNotAfter.Add(-renewBefore)
	if desired.After(caLimit) {
		capped := caLimit.Sub(now)
		if capped <= 0 {
			log.Warnf("CA certificate is expiring in less than %v, issuing cert with minimal TTL", renewBefore)
			return 1 * time.Minute
		}
		log.Infof("Capping cert TTL to %v (CA expires at %v)", capped, caNotAfter)
		return capped
	}
	return certValidity
}

func (c *onDemandCertController) Close() {}

func (c *onDemandCertController) HasSynced() bool {
	return true
}

func (c *onDemandCertController) AddSecretHandler(func(kind.Kind, string, string)) {}

// Run drives the cert reaper. It blocks until stop is closed.
// Each tick pops entries whose age (now - signedAt) exceeds maxAge; the next
// wake is scheduled for when the current heap top would become expired.
func (c *onDemandCertController) Run(stop <-chan struct{}) {
	if c.maxAge <= 0 {
		<-stop
		return
	}
	timer := time.NewTimer(c.maxAge)
	defer timer.Stop()
	for {
		wait := c.evictExpired()
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
		select {
		case <-stop:
			return
		case <-timer.C:
		}
	}
}

// evictExpired drops cache entries whose age (now - signedAt) exceeds maxAge.
// Returns the duration until the next entry becomes expired (or maxAge if empty).
// When at least one entry is evicted, records the domain in c.evicted and fires
// the eviction callback so SDS can push removed_resources to envoy.
func (c *onDemandCertController) evictExpired() time.Duration {
	c.mu.Lock()
	clear(c.evicted)

	evictedCount := 0
	now := time.Now()
	wait := c.maxAge
	for c.heap.Len() > 0 {
		top := c.heap[0]
		age := now.Sub(top.signedAt)
		if age < c.maxAge {
			wait = c.maxAge - age
			break
		}
		heap.Pop(&c.heap)
		delete(c.cache, top.domain)
		c.evicted.Insert(top.domain)
		evictedCount++
		log.Debugf("Evicted on-demand cert for domain %s, age=%v", top.domain, age)
	}
	c.mu.Unlock()

	if evictedCount > 0 {
		c.fireEviction()
	}
	if wait < minEvictionInterval {
		wait = minEvictionInterval
	}
	return wait
}

// EvictedCerts returns a snapshot of domains the reaper has removed and that
// have not been re-signed since. SDS intersects this with each proxy's
// subscribed resource names on an eviction push to build removed_resources.
// Entries linger until a fresh sign (GetCertInfo) or CA rotation clears them,
// so the set is bounded by the universe of domains envoy still cares about but
// istiod no longer caches.
func (c *onDemandCertController) EvictedCerts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.evicted.IsEmpty() {
		return nil
	}
	return c.evicted.UnsortedList()
}

// RegisterCertsEviction registers a function fired after the reaper evicts entries.
// Safe to call once at bootstrap; later calls overwrite the previous callback.
func (c *onDemandCertController) RegisterCertsEviction(fn func()) {
	c.evictionMu.Lock()
	c.onEviction = fn
	c.evictionMu.Unlock()
}

func (c *onDemandCertController) fireEviction() {
	c.evictionMu.Lock()
	fn := c.onEviction
	c.evictionMu.Unlock()
	if fn != nil {
		log.Infof("Evicting expired on-demand certs, size: %d", len(c.evicted))
		fn()
	}
}

// certHeap orders cachedCert pointers by signedAt ascending so the top entry
// is always the oldest candidate for eviction.
type certHeap []*cachedCert

func (h certHeap) Len() int           { return len(h) }
func (h certHeap) Less(i, j int) bool { return h[i].signedAt.Before(h[j].signedAt) }
func (h certHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *certHeap) Push(x any) {
	item := x.(*cachedCert)
	item.index = len(*h)
	*h = append(*h, item)
}

func (h *certHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	item.index = -1
	*h = old[:n-1]
	return item
}
