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

package casecret

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/openkruise/agentio/pkg/security/pki"
)

func TestRotatePreservesTrailingCertificateChain(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	active, err := pki.NewSelfSignedCA("active MITM CA", 5*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	trailing, err := pki.NewSelfSignedCA("trailing MITM CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	keys := Keys{
		Certificate:           "ca.crt",
		PrivateKey:            "ca.key",
		AllowCertificateChain: true,
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "mitm-ca"},
		Data: map[string][]byte{
			keys.Certificate: append(active.BundlePEM(), trailing.BundlePEM()...),
			keys.PrivateKey:  active.PrivateKeyPEM(),
		},
	}
	client := fake.NewSimpleClientset(secret)

	if err := Rotate(context.Background(), client, secret.Namespace, secret.Name, keys, time.Hour, 10*time.Minute, now); err != nil {
		t.Fatal(err)
	}
	updated, err := client.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	certificates := parseTestCertificates(t, updated.Data[keys.Certificate])
	if len(certificates) != 2 {
		t.Fatalf("rotated certificate bundle has %d certificates, want 2", len(certificates))
	}
	if bytes.Equal(certificates[0].Raw, parseTestCertificates(t, active.BundlePEM())[0].Raw) {
		t.Fatal("active certificate was not renewed")
	}
	wantTrailing := parseTestCertificates(t, trailing.BundlePEM())[0]
	if !bytes.Equal(certificates[1].Raw, wantTrailing.Raw) {
		t.Fatal("rotation did not preserve the trailing certificate")
	}
}

func parseTestCertificates(t *testing.T, value []byte) []*x509.Certificate {
	t.Helper()
	var certificates []*x509.Certificate
	for len(bytes.TrimSpace(value)) > 0 {
		block, rest := pem.Decode(value)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("value is not a certificate-only PEM bundle")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certificates = append(certificates, certificate)
		value = rest
	}
	return certificates
}
