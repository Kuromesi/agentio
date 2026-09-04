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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certstest"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
	"github.com/openkruise/agentio/pkg/kube"
)

// writeFileMaterial writes a cert/key pair into a temp dir and points the file
// path env vars at it.
func writeFileMaterial(t *testing.T, serial int64) {
	t.Helper()
	dir := t.TempDir()
	certPEM, keyPEM := certstest.SelfSigned(t, serial)
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	testsupport.SetForTest(t, &credProviderClientCertPath, certFile)
	testsupport.SetForTest(t, &credProviderClientKeyPath, keyFile)
	testsupport.SetForTest(t, &credProviderCACertPath, filepath.Join(dir, "ca.crt"))
}

// clearCredProviderMTLSEnv points every source at nothing, so each test opts in explicitly.
func clearCredProviderMTLSEnv(t *testing.T) {
	t.Helper()
	testsupport.SetForTest(t, &credProviderMTLSSource, credProviderSourceNone)
	testsupport.SetForTest(t, &credProviderSecretNamespace, "")
	testsupport.SetForTest(t, &credProviderSecretName, "")
	testsupport.SetForTest(t, &credProviderClientCertPath, "/nonexistent/client.crt")
	testsupport.SetForTest(t, &credProviderClientKeyPath, "/nonexistent/client.key")
	testsupport.SetForTest(t, &credProviderCACertPath, "/nonexistent/ca.crt")
}

func secretWith(t *testing.T, ns, name string, serial int64) *corev1.Secret {
	t.Helper()
	certPEM, keyPEM := certstest.SelfSigned(t, serial)
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
	testsupport.Eventually(t, 5*time.Second, func() error {
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
	})
}

func TestCredProviderForFilesSource(t *testing.T) {
	clearCredProviderMTLSEnv(t)
	testsupport.SetForTest(t, &credProviderMTLSSource, credProviderSourceFiles)
	writeFileMaterial(t, 5001)

	p, err := credProviderFor(Deps{Stop: t.Context().Done()})
	if err != nil {
		t.Fatalf("credProviderFor: %v", err)
	}
	awaitPresentedSerial(t, p, 5001)
}

func TestCredProviderForSecretSource(t *testing.T) {
	clearCredProviderMTLSEnv(t)
	testsupport.SetForTest(t, &credProviderMTLSSource, credProviderSourceSecret)
	testsupport.SetForTest(t, &credProviderSecretNamespace, "epe-system")
	testsupport.SetForTest(t, &credProviderSecretName, "epe-mtls")
	// File material is present and must be ignored: there is no fallback
	// between sources.
	writeFileMaterial(t, 5101)

	deps := Deps{
		Kube: kube.NewFakeClient(secretWith(t, "epe-system", "epe-mtls", 5102)),
		Stop: t.Context().Done(),
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
	testsupport.SetForTest(t, &credProviderMTLSSource, credProviderSourceSecret)
	testsupport.SetForTest(t, &credProviderSecretNamespace, "epe-system")
	testsupport.SetForTest(t, &credProviderSecretName, "absent")
	writeFileMaterial(t, 5201)

	p, err := credProviderFor(Deps{Kube: kube.NewFakeClient(), Stop: t.Context().Done()})
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
	testsupport.SetForTest(t, &credProviderMTLSSource, credProviderSourceNone)

	p, err := credProviderFor(Deps{Stop: t.Context().Done()})
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
	tests := []struct {
		name   string
		setup  func(t *testing.T)
		deps   Deps
		expect string
	}{
		{
			name:   "unknown source name",
			setup:  func(t *testing.T) { testsupport.SetForTest(t, &credProviderMTLSSource, "vault") },
			expect: "not one of",
		},
		{
			name: "secret source without a namespace or name",
			setup: func(t *testing.T) {
				testsupport.SetForTest(t, &credProviderMTLSSource, credProviderSourceSecret)
			},
			deps:   Deps{Kube: kube.NewFakeClient()},
			expect: "namespace and a name",
		},
		{
			name: "secret source without a cluster",
			setup: func(t *testing.T) {
				testsupport.SetForTest(t, &credProviderMTLSSource, credProviderSourceSecret)
				testsupport.SetForTest(t, &credProviderSecretNamespace, "epe-system")
				testsupport.SetForTest(t, &credProviderSecretName, "epe-mtls")
			},
			expect: "Kubernetes client is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearCredProviderMTLSEnv(t)
			tt.setup(t)
			deps := tt.deps
			deps.Stop = t.Context().Done()

			_, err := credProviderFor(deps)
			if err == nil {
				t.Fatalf("credProviderFor succeeded, want an error mentioning %q", tt.expect)
			}
			if !strings.Contains(err.Error(), tt.expect) {
				t.Errorf("error %q does not mention %q", err, tt.expect)
			}
		})
	}
}
