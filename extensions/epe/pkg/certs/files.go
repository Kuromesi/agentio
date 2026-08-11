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

package certs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/pkg/filewatcher"
)

// reloadPollInterval is the defensive periodic reload backstop for missed
// filesystem events.
const reloadPollInterval = 10 * time.Second

// fileProvider serves certificate material from files on disk. The cert/key
// pair is hot-reloaded on filesystem events (plus a periodic backstop); the
// CA bundle is re-read on every RootCAs call so CA rotation also needs no
// restart.
type fileProvider struct {
	certPath string
	keyPath  string
	caPath   string

	mu   sync.RWMutex
	cert *tls.Certificate
}

// FromFiles returns a Provider backed by PEM files on disk. certPath/keyPath
// are watched for hot reload (the watcher tracks the parent directory, so
// Kubernetes Secret symlink swaps and in-place rewrites both trigger a
// reload); caPath is re-read on every RootCAs call. caPath may be empty,
// meaning the provider has no custom CA (clients then fall back to the
// system pool).
//
// The initial cert/key pair must be loadable or FromFiles fails. The watcher
// runs in a background goroutine for the remainder of the process, so
// callers need neither to start nor to stop it; certificate rotation takes
// effect without a restart. A failed reload (e.g. a torn write between cert
// and key) keeps the previous certificate and retries on the next event or
// poll tick.
func FromFiles(certPath, keyPath, caPath string) (Provider, error) {
	p := &fileProvider{certPath: certPath, keyPath: keyPath, caPath: caPath}
	if err := p.reload(); err != nil {
		return nil, fmt.Errorf("loading initial certificate: %w", err)
	}

	watcher := filewatcher.NewWatcher()
	for _, path := range []string{certPath, keyPath} {
		if err := watcher.Add(path); err != nil {
			_ = watcher.Close()
			return nil, fmt.Errorf("watching %s: %w", path, err)
		}
	}
	go p.watch(watcher)
	return p, nil
}

// watch reloads the cert/key pair on filesystem events from either path and
// on a periodic backstop tick. It never returns.
func (p *fileProvider) watch(watcher filewatcher.FileWatcher) {
	logger := ctrllog.Log.WithName("certs")
	ticker := time.NewTicker(reloadPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-watcher.Events(p.certPath):
		case <-watcher.Events(p.keyPath):
		case err := <-watcher.Errors(p.certPath):
			logger.Error(err, "certificate watcher error", "certPath", p.certPath)
			continue
		case err := <-watcher.Errors(p.keyPath):
			logger.Error(err, "certificate watcher error", "keyPath", p.keyPath)
			continue
		case <-ticker.C:
		}
		if err := p.reload(); err != nil {
			// Keep serving the previous certificate; a torn rotation heals on
			// the next event or poll tick.
			logger.Error(err, "reloading certificate failed, keeping previous",
				"certPath", p.certPath, "keyPath", p.keyPath)
		}
	}
}

// reload parses the cert/key pair from disk and atomically swaps it in.
func (p *fileProvider) reload() error {
	cert, err := tls.LoadX509KeyPair(p.certPath, p.keyPath)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.cert = &cert
	p.mu.Unlock()
	return nil
}

func (p *fileProvider) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.currentCertificate()
}

func (p *fileProvider) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return p.currentCertificate()
}

// currentCertificate returns the cached certificate, failing closed when
// nothing has been loaded (unreachable through FromFiles, which requires a
// successful initial load).
func (p *fileProvider) currentCertificate() (*tls.Certificate, error) {
	p.mu.RLock()
	cert := p.cert
	p.mu.RUnlock()
	if cert == nil {
		return nil, fmt.Errorf("no certificate loaded from %s", p.certPath)
	}
	return cert, nil
}

// RootCAs re-reads the CA bundle from disk so rotated CAs are picked up on
// the next handshake. An empty caPath yields (nil, nil): no custom CA.
func (p *fileProvider) RootCAs() (*x509.CertPool, error) {
	if p.caPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(p.caPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA bundle %s: %w", p.caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("no valid certificates in CA bundle " + p.caPath)
	}
	return pool, nil
}
