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
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
)

func TestCredentialProviderFromEnvSources(t *testing.T) {
	testsupport.SetForTest(t, &identityProviderURL, "https://credentials.example")
	testsupport.SetForTest(t, &insecureSkipVerify, true)
	testsupport.SetForTest(t, &credProviderSecretNamespace, "credentials")
	testsupport.SetForTest(t, &credProviderSecretName, "client")
	for _, source := range []string{credProviderSourceSecret, credProviderSourceNone} {
		t.Run(source, func(t *testing.T) {
			testsupport.SetForTest(t, &credProviderMTLSSource, source)
			p, err := credentialProviderFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			if p.Url != identityProviderURL || p.Timeout != "10s" {
				t.Fatalf("environment settings lost: %v", p)
			}
			if !p.Tls.Optional || !p.Tls.InsecureSkipVerify {
				t.Fatal("TLS options lost")
			}
			switch source {
			case credProviderSourceSecret:
				ref := p.Tls.GetClientCertificateSecretRef()
				if ref.Namespace != "credentials" || ref.Name != "client" ||
					p.Tls.GetCaSecretRef().Namespace != "credentials" || p.Tls.GetCaSecretRef().Name != "client" {
					t.Fatal("Secret name or namespace lost")
				}
			case credProviderSourceNone:
				if p.Tls.GetCaSource() != nil || p.Tls.GetClientCertificateSource() != nil {
					t.Fatal("none source included certificate material")
				}
			}
		})
	}
}

func TestCredentialProviderFromEnvRejectsMisconfiguredSource(t *testing.T) {
	testsupport.SetForTest(t, &identityProviderURL, "https://credentials.example")
	testsupport.SetForTest(t, &credProviderSecretNamespace, "")
	testsupport.SetForTest(t, &credProviderSecretName, "")
	for source, expected := range map[string]string{"unknown": "not one of", "files": "not one of", "secret": "namespace and a name"} {
		t.Run(source, func(t *testing.T) {
			testsupport.SetForTest(t, &credProviderMTLSSource, source)
			_, err := credentialProviderFromEnv()
			if err == nil || !strings.Contains(err.Error(), expected) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
