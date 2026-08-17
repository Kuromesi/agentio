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
package wiring

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/retry"
)

// pemPair returns a self-signed certificate and key in PEM form, identified by
// serial so a test can tell which source supplied it.
func pemPair(t *testing.T, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: fmt.Sprintf("wiring-test-%d", serial)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// writeFileMaterial writes a cert/key pair into a temp dir and points the file
// path env vars at it.
func writeFileMaterial(t *testing.T, serial int64) {
	t.Helper()
	dir := t.TempDir()
	certPEM, keyPEM := pemPair(t, serial)
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	test.SetForTest(t, &credProviderClientCertPath, certFile)
	test.SetForTest(t, &credProviderClientKeyPath, keyFile)
	test.SetForTest(t, &credProviderCACertPath, filepath.Join(dir, "ca.crt"))
}

// clearCredProviderMTLSEnv points every source at nothing, so each test opts in explicitly.
func clearCredProviderMTLSEnv(t *testing.T) {
	t.Helper()
	test.SetForTest(t, &credProviderMTLSSource, credProviderSourceNone)
	test.SetForTest(t, &credProviderSecretNamespace, "")
	test.SetForTest(t, &credProviderSecretName, "")
	test.SetForTest(t, &credProviderClientCertPath, "/nonexistent/client.crt")
	test.SetForTest(t, &credProviderClientKeyPath, "/nonexistent/client.key")
	test.SetForTest(t, &credProviderCACertPath, "/nonexistent/ca.crt")
}

func secretWith(t *testing.T, ns, name string, serial int64) *corev1.Secret {
	t.Helper()
	certPEM, keyPEM := pemPair(t, serial)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Data:       map[string][]byte{"client.crt": certPEM, "client.key": keyPEM},
	}
}

// awaitPresentedSerial polls the provider until it presents the given serial.
func awaitPresentedSerial(t *testing.T, p interface {
	GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}, want int64) {
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
	}, retry.Timeout(5*time.Second))
}

func TestCredProviderForFilesSource(t *testing.T) {
	clearCredProviderMTLSEnv(t)
	test.SetForTest(t, &credProviderMTLSSource, credProviderSourceFiles)
	writeFileMaterial(t, 5001)

	p, err := credProviderFor(Deps{Stop: test.NewStop(t)})
	if err != nil {
		t.Fatalf("credProviderFor: %v", err)
	}
	awaitPresentedSerial(t, p, 5001)
}

func TestCredProviderForSecretSource(t *testing.T) {
	clearCredProviderMTLSEnv(t)
	test.SetForTest(t, &credProviderMTLSSource, credProviderSourceSecret)
	test.SetForTest(t, &credProviderSecretNamespace, "epe-system")
	test.SetForTest(t, &credProviderSecretName, "epe-mtls")
	// File material is present and must be ignored: there is no fallback
	// between sources.
	writeFileMaterial(t, 5101)

	deps := Deps{
		Kube: kube.NewFakeClient(secretWith(t, "epe-system", "epe-mtls", 5102)),
		Stop: test.NewStop(t),
	}
	p, err := credProviderFor(deps)
	if err != nil {
		t.Fatalf("credProviderFor: %v", err)
	}
	awaitPresentedSerial(t, p, 5102)
}

// The Secret source never borrows the file source's material, even when the
// Secret does not exist.
func TestCredProviderForSecretSourceDoesNotFallBackToFiles(t *testing.T) {
	clearCredProviderMTLSEnv(t)
	test.SetForTest(t, &credProviderMTLSSource, credProviderSourceSecret)
	test.SetForTest(t, &credProviderSecretNamespace, "epe-system")
	test.SetForTest(t, &credProviderSecretName, "absent")
	writeFileMaterial(t, 5201)

	p, err := credProviderFor(Deps{Kube: kube.NewFakeClient(), Stop: test.NewStop(t)})
	if err != nil {
		t.Fatalf("credProviderFor: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	cert, err := p.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if len(cert.Certificate) != 0 {
		t.Error("the Secret source presented a certificate from the file paths")
	}
}

func TestCredProviderForNoneSourcePresentsNoIdentity(t *testing.T) {
	clearCredProviderMTLSEnv(t)
	writeFileMaterial(t, 5301)
	test.SetForTest(t, &credProviderMTLSSource, credProviderSourceNone)

	p, err := credProviderFor(Deps{Stop: test.NewStop(t)})
	if err != nil {
		t.Fatalf("credProviderFor: %v", err)
	}
	if p != nil {
		t.Errorf("credProviderFor returned a provider for source %q, want nil", credProviderSourceNone)
	}
}

// A misconfigured source is the one case that must fail loudly at startup:
// absent material is a resting state, but an unusable configuration is a bug
// the operator has to see.
func TestCredProviderForRejectsMisconfiguration(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T)
		deps   Deps
		expect string
	}{
		{
			name:   "unknown source name",
			setup:  func(t *testing.T) { test.SetForTest(t, &credProviderMTLSSource, "vault") },
			expect: "not one of",
		},
		{
			name: "secret source without a namespace or name",
			setup: func(t *testing.T) {
				test.SetForTest(t, &credProviderMTLSSource, credProviderSourceSecret)
			},
			deps:   Deps{Kube: kube.NewFakeClient()},
			expect: "namespace and a name",
		},
		{
			name: "secret source without a cluster",
			setup: func(t *testing.T) {
				test.SetForTest(t, &credProviderMTLSSource, credProviderSourceSecret)
				test.SetForTest(t, &credProviderSecretNamespace, "epe-system")
				test.SetForTest(t, &credProviderSecretName, "epe-mtls")
			},
			expect: "Kubernetes client is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearCredProviderMTLSEnv(t)
			tc.setup(t)
			deps := tc.deps
			deps.Stop = test.NewStop(t)

			_, err := credProviderFor(deps)
			if err == nil {
				t.Fatalf("credProviderFor succeeded, want an error mentioning %q", tc.expect)
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("error %q does not mention %q", err, tc.expect)
			}
		})
	}
}
