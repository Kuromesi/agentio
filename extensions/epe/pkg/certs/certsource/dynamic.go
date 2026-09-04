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
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/certs"
	"github.com/openkruise/agentio/pkg/krt"
)

// reloadPollInterval is the backstop for reload drivers that can miss a change:
// filesystem events when the watcher could not be registered, and the periodic
// re-read the Secret source relies on entirely.
const reloadPollInterval = 10 * time.Second

// Source supplies raw PEM material. Load is called on every reload.
//
// The three return values are independent: a source may hold a CA bundle
// without a client certificate, or the reverse. Returning all-nil with a nil
// error means "nothing is configured there yet", which is a normal steady state
// rather than a failure — the material simply has not appeared.
//
// An error means the source could not be read at all (permission denied, an
// unreadable file). That is distinct from absence: see material.merge.
type Source interface {
	Load() (certPEM, keyPEM, caPEM []byte, err error)
	// Name identifies the source in log messages.
	Name() string
}

// material is one immutable snapshot: the client identity and the trust
// anchors, either of which may be absent.
//
// A nil cert means "present no client identity"; a nil pool means "verify
// against the system trust store". Both are legitimate resting states, so this
// type has no notion of being empty-and-therefore-invalid.
type material struct {
	cert *tls.Certificate
	pool *x509.CertPool
}

// ResourceName satisfies krt's key requirement. A dynamicProvider holds exactly
// one material, so the key is constant.
func (material) ResourceName() string { return "material" }

// dynamicProvider serves material that is re-resolved out of band and read on
// every handshake.
//
// The current snapshot lives in a krt Singleton rather than a bare
// atomic.Pointer so the value is observable the same way the rest of the tree's
// dynamic state is: it appears in krt's collection registry and downstream
// consumers can Register for changes. This mirrors krt/files.NewFileSingleton,
// which is likewise a krt Singleton fed by an out-of-band driver rather than an
// informer.
type dynamicProvider struct {
	src Source
	cur krt.StaticSingleton[material]

	// lastComplaint deduplicates reload failures. A source that is absent for
	// the life of the process still gets a reload on every backstop tick, so an
	// unconditional log here would be a permanent 10s heartbeat of noise.
	lastComplaint atomic.Pointer[string]
}

// newDynamic builds a provider over src, reloading whenever triggers fires and
// on a periodic backstop, until stop closes. triggers may be nil for a source
// with no event-driven driver.
//
// The first load happens synchronously so a caller can inspect the result
// before deciding whether the material was mandatory.
func newDynamic(src Source, triggers <-chan struct{}, stop <-chan struct{}, interval time.Duration) *dynamicProvider {
	p := &dynamicProvider{
		src: src,
		cur: krt.NewStatic(&material{}, true, krt.WithName("CertMaterial/"+src.Name()), krt.WithStop(stop)),
	}
	p.reload()
	go p.run(triggers, stop, interval)
	return p
}

// run reloads on triggers and on the backstop tick until stop closes.
func (p *dynamicProvider) run(triggers <-chan struct{}, stop <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-triggers:
		case <-ticker.C:
		}
		p.reload()
	}
}

// reload re-reads the source and swaps in the new snapshot.
//
// The two axes are resolved independently, and they fail differently on
// purpose:
//
//   - The trust anchors drop to nil — verify against the system trust store —
//     whenever the CA cannot be obtained or parsed. That is the configured
//     fallback: a source with a problem must not leave a stale private anchor
//     in place.
//   - The client identity is RETAINED when the new material fails to parse,
//     because a half-written rotation looks exactly like corruption and there
//     is no safe default identity to fall back to. It is dropped only when the
//     source reports the material as genuinely absent.
func (p *dynamicProvider) reload() {
	certPEM, keyPEM, caPEM, err := p.src.Load()
	if err != nil {
		// Could not read the source at all: keep the identity, drop to the
		// system trust store, and say so once.
		p.complain(fmt.Errorf("reading %s: %w", p.src.Name(), err))
		p.cur.Set(&material{cert: p.currentCert(), pool: nil})
		return
	}

	next := material{pool: poolFromPEM(caPEM, p.src.Name())}
	switch cert, certErr := parseKeyPair(certPEM, keyPEM); {
	case certErr != nil:
		p.complain(fmt.Errorf("parsing the client certificate from %s: %w", p.src.Name(), certErr))
		next.cert = p.currentCert()
	case cert != nil:
		p.clearComplaint()
		next.cert = cert
	default:
		// Genuinely absent, not malformed: stop presenting an identity.
		p.clearComplaint()
	}
	p.cur.Set(&next)
}

// parseKeyPair parses a cert/key pair. All-empty input yields (nil, nil): the
// material is absent rather than invalid. A partial pair is an error, since one
// half without the other cannot be a resting state.
func parseKeyPair(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	if len(certPEM) == 0 && len(keyPEM) == 0 {
		return nil, nil
	}
	if len(certPEM) == 0 {
		return nil, errors.New("a client key is present without its certificate")
	}
	if len(keyPEM) == 0 {
		return nil, errors.New("a client certificate is present without its key")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		// Populated so callers can inspect the certificate without re-parsing.
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parsing the certificate leaf: %w", err)
		}
		cert.Leaf = leaf
	}
	return &cert, nil
}

// poolFromPEM parses a CA bundle. Absent or unparseable material yields nil,
// meaning the system trust store — never an empty pool, which would trust
// nothing and fail every handshake. source names the origin in the log.
func poolFromPEM(caPEM []byte, source string) *x509.CertPool {
	if len(caPEM) == 0 {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		ctrllog.Log.WithName("certsource").Info(
			"ignoring an unparseable CA bundle; verifying against the system trust store instead",
			"source", source)
		return nil
	}
	return pool
}

// currentCert returns the identity currently being served, if any.
func (p *dynamicProvider) currentCert() *tls.Certificate {
	if m := p.cur.Get(); m != nil {
		return m.cert
	}
	return nil
}

// complain logs a reload failure at most once per distinct message.
func (p *dynamicProvider) complain(err error) {
	msg := err.Error()
	if last := p.lastComplaint.Load(); last != nil && *last == msg {
		return
	}
	p.lastComplaint.Store(&msg)
	logger := ctrllog.Log.WithName("certs")
	if p.currentCert() == nil {
		// Never had an identity: the expected state when nothing is mounted.
		logger.V(1).Info("no mTLS material loaded yet", "source", p.src.Name(), "reason", msg)
		return
	}
	logger.Error(err, "reloading mTLS material failed; keeping the previous certificate",
		"source", p.src.Name())
}

// clearComplaint re-arms the dedup so a defect that recurs after a good reload
// is reported again.
func (p *dynamicProvider) clearComplaint() { p.lastComplaint.Store(nil) }

// hasIdentity reports whether a client certificate is currently held. Used by
// constructors whose material is mandatory.
func (p *dynamicProvider) hasIdentity() bool { return p.currentCert() != nil }

// GetCertificate serves the server-side certificate. Unlike the client side it
// fails when nothing is held: crypto/tls treats a non-nil return as a real
// certificate and would index into its empty chain.
func (p *dynamicProvider) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := p.currentCert()
	if cert == nil {
		return nil, fmt.Errorf("certs: no certificate loaded from %s", p.src.Name())
	}
	return cert, nil
}

// GetClientCertificate serves the client-side certificate. An empty certificate
// means "present no identity"; returning an error would abort a handshake that
// should still complete without one.
func (p *dynamicProvider) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cert := p.currentCert()
	if cert == nil {
		return &tls.Certificate{}, nil
	}
	return cert, nil
}

// RootCAs returns the current trust anchors, or nil for the system trust store.
func (p *dynamicProvider) RootCAs() (*x509.CertPool, error) {
	if m := p.cur.Get(); m != nil {
		return m.pool, nil
	}
	return nil, nil
}

// The holder is the Provider every source hands back.
var _ certs.Provider = (*dynamicProvider)(nil)
