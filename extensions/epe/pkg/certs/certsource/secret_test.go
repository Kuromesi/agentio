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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"istio.io/istio/extensions/epe/pkg/certs"
	"istio.io/istio/extensions/epe/pkg/certs/certstest"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient/clienttest"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/retry"
)

const (
	testNamespace  = "epe-system"
	testSecretName = "epe-mtls-client-cert"
)

// mtlsSecret builds a Secret carrying the generation identified by serial.
func mtlsSecret(t test.Failer, ca *certstest.CA, serial int64, withCA bool) *corev1.Secret {
	leaf, _ := ca.Issue(t, certstest.LeafSpec{Serial: serial})
	certPEM, keyPEM := certstest.PEM(t, leaf)
	data := map[string][]byte{"client.crt": certPEM, "client.key": keyPEM}
	if withCA {
		data["ca.crt"] = ca.CAPEM()
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
		Data:       data,
	}
}

// awaitSecretSerial polls until the provider presents the given serial.
func awaitSecretSerial(t *testing.T, p certs.Provider, want int64) {
	t.Helper()
	retry.UntilSuccessOrFail(t, func() error {
		cert, err := p.GetClientCertificate(&tls.CertificateRequestInfo{})
		if err != nil {
			return err
		}
		if len(cert.Certificate) == 0 {
			return fmt.Errorf("no certificate presented")
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
		if got := leaf.SerialNumber.Int64(); got != want {
			return fmt.Errorf("serial = %d, want %d", got, want)
		}
		return nil
	}, retry.Timeout(10*time.Second))
}

func TestFromSecretRequiresNamespaceAndName(t *testing.T) {
	c := kube.NewFakeClient()
	for _, tc := range []struct{ ns, name string }{{"", testSecretName}, {testNamespace, ""}, {"", ""}} {
		if _, err := FromSecret(c, tc.ns, tc.name, test.NewStop(t)); err == nil {
			t.Errorf("FromSecret(%q, %q) succeeded, want an error", tc.ns, tc.name)
		}
	}
}

// The defect this whole change exists to fix: the Secret shows up after the
// process is already running.
func TestFromSecretPicksUpSecretCreatedLater(t *testing.T) {
	ca := certstest.New(t)
	c := kube.NewFakeClient()
	fakeClient := c.Kube().(*k8sfake.Clientset)
	watchStarted := make(chan struct{}, 1)
	fakeClient.PrependWatchReactor("secrets", func(action k8stesting.Action) (bool, watch.Interface, error) {
		w, err := fakeClient.Tracker().Watch(action.GetResource(), action.GetNamespace())
		if err == nil {
			select {
			case watchStarted <- struct{}{}:
			default:
			}
		}
		return true, w, err
	})
	stop := test.NewStop(t)
	c.RunAndWait(stop)

	p, err := FromSecret(c, testNamespace, testSecretName, stop)
	if err != nil {
		t.Fatalf("FromSecret: %v", err)
	}

	cert, err := p.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if len(cert.Certificate) != 0 {
		t.Fatal("a certificate was presented before the Secret existed")
	}

	// The fake tracker does not replay events created between an informer's
	// initial List and Watch registration. Wait for the watch so this test
	// exercises a Secret created later instead of racing that fake-only gap.
	select {
	case <-watchStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the Secret watch to start")
	}

	clienttest.NewWriter[*corev1.Secret](t, c).Create(mtlsSecret(t, ca, 8001, true))

	awaitSecretSerial(t, p, 8001)
	if pool, _ := p.RootCAs(); pool == nil {
		t.Error("no trust anchors despite ca.crt being present")
	}
}

func TestFromSecretRotatesMaterial(t *testing.T) {
	ca := certstest.New(t)
	c := kube.NewFakeClient(mtlsSecret(t, ca, 8101, true))
	stop := test.NewStop(t)
	c.RunAndWait(stop)

	p, err := FromSecret(c, testNamespace, testSecretName, stop)
	if err != nil {
		t.Fatalf("FromSecret: %v", err)
	}
	awaitSecretSerial(t, p, 8101)

	clienttest.NewWriter[*corev1.Secret](t, c).Update(mtlsSecret(t, ca, 8102, true))
	awaitSecretSerial(t, p, 8102)
}

// A Secret without ca.crt still carries a usable identity; the anchors fall
// back to the system trust store rather than the identity being discarded.
func TestFromSecretWithoutCAStillPresentsIdentity(t *testing.T) {
	ca := certstest.New(t)
	c := kube.NewFakeClient(mtlsSecret(t, ca, 8201, false))
	stop := test.NewStop(t)
	c.RunAndWait(stop)

	p, err := FromSecret(c, testNamespace, testSecretName, stop)
	if err != nil {
		t.Fatalf("FromSecret: %v", err)
	}
	awaitSecretSerial(t, p, 8201)

	if pool, _ := p.RootCAs(); pool != nil {
		t.Error("trust anchors returned with no ca.crt; want nil for the system trust store")
	}
}

// The independent-axes case: a Secret carrying only a CA bundle and no client
// certificate. GetClientCertificate must yield an empty certificate, not a nil
// one — the TLS 1.3 client dereferences the returned certificate, so nil panics
// the handshake instead of completing it without an identity.
func TestFromSecretCAOnlyPresentsNoIdentityWithoutPanic(t *testing.T) {
	ca := certstest.New(t)
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
		Data:       map[string][]byte{"ca.crt": ca.CAPEM()},
	}
	c := kube.NewFakeClient(sec)
	stop := test.NewStop(t)
	c.RunAndWait(stop)

	p, err := FromSecret(c, testNamespace, testSecretName, stop)
	if err != nil {
		t.Fatalf("FromSecret: %v", err)
	}

	// Wait for the watch to observe the Secret.
	retry.UntilSuccessOrFail(t, func() error {
		if pool, _ := p.RootCAs(); pool == nil {
			return fmt.Errorf("anchors from the CA-only Secret not yet available")
		}
		return nil
	}, retry.Timeout(10*time.Second))

	cert, err := p.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("GetClientCertificate returned nil; the TLS 1.3 client would panic dereferencing it")
	}
	if len(cert.Certificate) != 0 {
		t.Errorf("presented %d certificates from a CA-only Secret, want 0", len(cert.Certificate))
	}

	// The anchors are still served.
	if pool, _ := p.RootCAs(); pool == nil {
		t.Error("no trust anchors from a CA-only Secret")
	}

	// The server side must fail closed rather than present an empty cert.
	if _, err := p.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Error("GetCertificate succeeded for a CA-only Secret; a server must fail")
	}
}

// The gate's actual contract: while the read permission probe fails, the Secret
// is not used even though it exists and the informer's list/watch would have
// succeeded. That is what keeps the watch from being registered at all.
//
// Note on scope: this pins the gate's OBSERVABLE effect. The reason the gate
// exists — that an eagerly registered informer's cache sync blocks
// kube.Client.RunAndWait forever — is NOT reproducible here. kube.NewFakeClient
// sets fastSync, so RunAndWait skips the unbounded informerFactory
// WaitForCacheSync path; it returns true even with get, list and watch all
// forbidden. That property rests on reading pkg/kube/client.go and on the same
// pattern already being used for this purpose in
// pilot/pkg/serviceregistry/kube/controller/agentio/ondemand_cert.go.
func TestFromSecretDoesNotUseTheSecretWhileReadsAreDenied(t *testing.T) {
	ca := certstest.New(t)
	// The Secret exists and the fake client's list/watch will serve it happily;
	// only the permission probe is refused.
	c := kube.NewFakeClient(mtlsSecret(t, ca, 8401, true))
	c.Kube().(*k8sfake.Clientset).PrependReactor("get", "secrets",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Resource: "secrets"}, testSecretName, errors.New("rbac denied"))
		})
	stop := test.NewStop(t)
	c.RunAndWait(stop)

	p, err := FromSecret(c, testNamespace, testSecretName, stop)
	if err != nil {
		t.Fatalf("FromSecret: %v", err)
	}

	// Long enough for an ungated implementation to have synced and served it.
	time.Sleep(500 * time.Millisecond)
	cert, err := p.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if len(cert.Certificate) != 0 {
		t.Error("the Secret was used despite the read permission probe being refused")
	}
	pool, err := p.RootCAs()
	if err != nil {
		t.Fatalf("RootCAs: %v", err)
	}
	if pool != nil {
		t.Error("trust anchors served despite the read permission probe being refused; want the system trust store")
	}
}

// Construction must not block on the probe: a denied read is resolved in the
// background so startup proceeds.
func TestFromSecretConstructionDoesNotBlock(t *testing.T) {
	c := kube.NewFakeClient()
	c.Kube().(*k8sfake.Clientset).PrependReactor("get", "secrets",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Resource: "secrets"}, testSecretName, errors.New("rbac denied"))
		})
	stop := test.NewStop(t)
	c.RunAndWait(stop)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := FromSecret(c, testNamespace, testSecretName, stop); err != nil {
			t.Errorf("FromSecret: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("FromSecret blocked on a denied Secret read; it must return and let the provider degrade")
	}
}
