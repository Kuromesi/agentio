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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/certs"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
)

// Data keys read from the Secret.
const (
	secretKeyCACert     = "ca.crt"
	secretKeyClientCert = "client.crt"
	secretKeyClientKey  = "client.key"
)

// rbacPollInterval is how often the read permission is re-probed before the
// watch is established.
const rbacPollInterval = 30 * time.Second

// secretProvider serves material from a single watched Secret.
//
// The krt Singleton behind it is built lazily, gated on a probe that confirms
// the Secret is readable. An informer created eagerly joins the shared factory
// and its cache sync then gates kube.Client.RunAndWait, so a Secret the
// ServiceAccount may not watch would block startup indefinitely instead of
// degrading. Deferred, a denied read simply leaves the Singleton empty, which
// this provider serves as "no client identity, system trust store".
type secretProvider struct {
	material krt.Singleton[secretMaterial]
	ns       string
	name     string
}

// secretMaterial is one parsed snapshot of the Secret.
type secretMaterial struct {
	cert *tls.Certificate
	pool *x509.CertPool
}

// ResourceName satisfies krt's key requirement; there is one per provider.
func (secretMaterial) ResourceName() string { return "secret-material" }

// FromSecret returns a certs.Provider backed by the mTLS Secret ns/name,
// watched for the lifetime of stop.
//
// A Secret that does not exist yet is not an error: the provider presents no
// client identity and the system trust store until it appears, and the watch
// picks up its creation — the whole point of watching rather than reading once.
// A Secret that cannot be READ at all degrades the same way rather than
// failing, so the credential provider is contacted without a client
// certificate instead of the process refusing to start.
func FromSecret(c kube.Client, ns, name string, stop <-chan struct{}) (certs.Provider, error) {
	if c == nil {
		return nil, fmt.Errorf("a Kubernetes client is required to read mTLS material from a Secret")
	}
	if ns == "" || name == "" {
		return nil, fmt.Errorf("both a namespace and a name are required to read mTLS material from a Secret, got %q/%q", ns, name)
	}

	// A missing Secret is fine to watch for; a forbidden one is not yet
	// watchable, so keep probing rather than registering an informer that can
	// never sync.
	readable := func(ctx context.Context) bool {
		_, err := c.Kube().CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
		return !apierrors.IsForbidden(err)
	}
	syncer := krt.NewPollingSyncer("epe-mtls-secret", readable, rbacPollInterval)
	singleton := krt.NewDelayedSingleton(syncer, func() krt.Singleton[secretMaterial] {
		return newSecretSingleton(c, ns, name, stop)
	}, stop)

	return &secretProvider{material: singleton, ns: ns, name: name}, nil
}

// newSecretSingleton wires the scoped informer and the parse step. It runs only
// once the Secret is known to be readable.
func newSecretSingleton(c kube.Client, ns, name string, stop <-chan struct{}) krt.Singleton[secretMaterial] {
	// Scoped server-side to the single object, so this never caches every
	// Secret in the cluster.
	client := kclient.NewFiltered[*corev1.Secret](c, kclient.Filter{
		Namespace:     ns,
		FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String(),
	})
	secrets := krt.WrapClient(client, krt.WithName("EPE_MTLS_Secret"), krt.WithStop(stop))
	client.Start(stop)

	key := types.NamespacedName{Namespace: ns, Name: name}.String()
	logger := ctrllog.Log.WithName("certsource")
	return krt.NewSingleton(func(ctx krt.HandlerContext) *secretMaterial {
		sec := ptr.Flatten(krt.FetchOne(ctx, secrets, krt.FilterKey(key)))
		if sec == nil {
			// Absent: present no identity. Recomputed when it appears.
			return nil
		}
		cert, err := parseKeyPair(sec.Data[secretKeyClientCert], sec.Data[secretKeyClientKey])
		if err != nil {
			// Malformed is ambiguous with a half-applied rotation, but krt
			// recomputes from the live object rather than from a retained
			// snapshot, so there is nothing to keep: report it and present no
			// identity until the Secret is fixed.
			logger.Error(err, "mTLS Secret is present but its client certificate is unusable",
				"namespace", ns, "name", name)
			return nil
		}
		return &secretMaterial{
			cert: cert,
			pool: poolFromPEM(sec.Data[secretKeyCACert], "secret "+ns+"/"+name),
		}
	}, krt.WithName("EPE_MTLS_SecretMaterial"), krt.WithStop(stop))
}

// current returns the parsed snapshot, or nil when the watch is not yet
// established, or the Secret is absent or unusable.
func (p *secretProvider) current() *secretMaterial { return p.material.Get() }

// GetCertificate fails when nothing is held: a server has nothing to present,
// and crypto/tls would treat an empty certificate as real. A Secret that carries
// only a CA bundle has no identity either, so m.cert==nil is handled like m==nil.
func (p *secretProvider) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m := p.current()
	if m == nil || m.cert == nil {
		return nil, fmt.Errorf("certs: no certificate loaded from secret %s/%s", p.ns, p.name)
	}
	return m.cert, nil
}

// GetClientCertificate presents the identity, or an empty certificate so the
// handshake still completes without one. Returning a nil *tls.Certificate would
// panic the TLS 1.3 client (it dereferences the result), so the CA-only case
// must yield an empty certificate, not nil.
func (p *secretProvider) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	m := p.current()
	if m == nil || m.cert == nil {
		return &tls.Certificate{}, nil
	}
	return m.cert, nil
}

// RootCAs returns the Secret's anchors, or nil for the system trust store.
func (p *secretProvider) RootCAs() (*x509.CertPool, error) {
	m := p.current()
	if m == nil {
		return nil, nil
	}
	return m.pool, nil
}

var _ certs.Provider = (*secretProvider)(nil)
