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

package mitm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"testing/synctest"
	"time"

	"github.com/openkruise/agentio/pkg/security/pki"
)

func TestOnDemandDeadlineAndEvictionFollowCAChainExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		now := time.Now()
		root := newMITMSecret(t, "agentio-system", "mitm", 5*time.Minute, now)
		rootBlock, _ := pem.Decode(root.Data[mitmCACertKey])
		rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		keyBlock, _ := pem.Decode(root.Data[mitmCAKeyKey])
		rootKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: "intermediate"},
			NotBefore:             now.Add(-time.Minute),
			NotAfter:              now.Add(2 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, rootCert, key.Public(), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), root.Data[mitmCACertKey]...)
		ca, err := pki.ParseSigningCABundle(
			bundle,
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
			now,
		)
		if err != nil {
			t.Fatal(err)
		}
		signer := newInstalledMITMSigner(t, ca, root.UID, time.Minute)
		issuer, err := NewOnDemandIssuer(
			ctx,
			DomainSignerSource{Signer: signer, State: signer.State()},
			&fakeGatewayAuthorizer{},
			OnDemandOptions{
				LeafLifetime: 15 * time.Minute,
				ResourceTTL:  15 * time.Minute,
				RenewBefore:  time.Minute,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := issuer.certificate(ctx, "api.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if !certificate.NotAfter.Equal(now.Add(4*time.Minute)) ||
			!certificate.UsableUntil.Equal(now.Add(3*time.Minute)) {
			t.Fatalf("leaf/SDS deadlines did not follow the ancestor: %+v", certificate)
		}
		time.Sleep(3 * time.Minute)
		synctest.Wait()
		if cached := issuer.cachedCertificate("api.example.com"); cached != nil {
			t.Fatal("certificate remained cached after its chain-constrained SDS deadline")
		}
		if _, err := issuer.certificate(ctx, "api.example.com"); err == nil {
			t.Fatal("reissued a certificate inside the ancestor CA renewal window")
		}
	})
}
