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

package debug

import (
	"encoding/json"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/anypb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/pkg/model"
)

func TestConfigDebugSerializationRedactsSensitiveValues(t *testing.T) {
	tlsCertificate, err := marshalConfigDebugProto(&tlsv3.TlsCertificate{
		CertificateChain: &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: "certificate-material"}},
		PrivateKey:       &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: []byte("private-key-material")}},
		Password:         &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: "private-key-password"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	header, err := marshalConfigDebugProto(&corev3.HeaderValue{Key: "x-backend-token", Value: "header-credential"})
	if err != nil {
		t.Fatal(err)
	}
	headerAny, err := anypb.New(&corev3.HeaderValue{Key: "x-nested-token", Value: "nested-header-credential"})
	if err != nil {
		t.Fatal(err)
	}
	nestedHeader, err := marshalConfigDebugProto(&corev3.TypedExtensionConfig{Name: "header", TypedConfig: headerAny})
	if err != nil {
		t.Fatal(err)
	}
	dataSourceAny, err := anypb.New(&corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: "nested-data-source-credential"}})
	if err != nil {
		t.Fatal(err)
	}
	nestedDataSource, err := marshalConfigDebugProto(&corev3.TypedExtensionConfig{Name: "data-source", TypedConfig: dataSourceAny})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := configDebugSecurityProfile(model.SecurityProfile{
		Name:      "sensitive",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{},
			Inputs: []agentsv1alpha1.SecurityProfileInput{{
				Name: "request-data",
				Inline: map[string]string{
					"accessKeySecret": "policy-credential",
					"sharedSecret":    "second-policy-credential",
					"backendAuth":     "third-policy-credential",
					"region":          "cn-hangzhou",
				},
			}},
			Rules: []agentsv1alpha1.SecurityRule{{
				Name: "set-header",
				Actions: agentsv1alpha1.SecurityRuleActions{
					HeaderManipulation: &agentsv1alpha1.HeaderManipulationAction{
						Set: []agentsv1alpha1.HeaderValue{{Name: "x-backend-token", Value: "profile-header-credential"}},
					},
				},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	combined := string(tlsCertificate) + string(header) + string(nestedHeader) + string(nestedDataSource) + string(profile.Spec)
	for _, secret := range []string{
		"certificate-material",
		"private-key-material",
		"cHJpdmF0ZS1rZXktbWF0ZXJpYWw=",
		"private-key-password",
		"header-credential",
		"nested-header-credential",
		"nested-data-source-credential",
		"profile-header-credential",
		"policy-credential",
		"second-policy-credential",
		"third-policy-credential",
		"cn-hangzhou",
	} {
		if strings.Contains(combined, secret) {
			t.Fatalf("debug serialization exposed %q: %s", secret, combined)
		}
	}
	if strings.Count(combined, "[REDACTED]") < 4 {
		t.Fatalf("sensitive values were not visibly redacted: %s", combined)
	}
}

func TestConfigDebugSecurityProfileRedactsAuditHeadersWithoutMutatingSource(t *testing.T) {
	profile := model.SecurityProfile{
		Name:      "audit-headers",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{},
			Audit: []agentsv1alpha1.AuditAction{{
				Name: "profile-audit",
				Webhook: &agentsv1alpha1.AuditWebhook{URL: "https://audit.example.com", Request: &agentsv1alpha1.AuditRequest{
					Headers: []agentsv1alpha1.AuditHeader{{Name: "Authorization", Value: "Bearer profile-audit-credential"}},
				}},
			}},
			Rules: []agentsv1alpha1.SecurityRule{{
				Name: "rule-audit",
				Actions: agentsv1alpha1.SecurityRuleActions{Audit: []agentsv1alpha1.AuditAction{{
					Name: "rule-audit",
					Webhook: &agentsv1alpha1.AuditWebhook{URL: "https://audit.example.com", Request: &agentsv1alpha1.AuditRequest{
						Headers: []agentsv1alpha1.AuditHeader{{Name: "x-audit-token", Value: "rule-audit-credential"}},
					}},
				}}},
			}},
		},
	}

	item, err := configDebugSecurityProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{"profile-audit-credential", "rule-audit-credential"} {
		if strings.Contains(string(item.Spec), credential) {
			t.Fatalf("audit header credential %q exposed: %s", credential, item.Spec)
		}
	}
	if got := profile.Spec.Audit[0].Webhook.Request.Headers[0].Value; got != "Bearer profile-audit-credential" {
		t.Fatalf("profile audit source header mutated: %q", got)
	}
	if got := profile.Spec.Rules[0].Actions.Audit[0].Webhook.Request.Headers[0].Value; got != "rule-audit-credential" {
		t.Fatalf("rule audit source header mutated: %q", got)
	}
}

func TestConfigDebugRedactionPreservesCredentialReferenceShape(t *testing.T) {
	got, err := redactConfigDebugJSON([]byte(`{
		"credentialRef": {
			"secret": {"name": "backend-credentials", "namespace": "demo"},
			"credentialProvider": {"name": "vault"}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		CredentialRef struct {
			Secret struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"secret"`
			CredentialProvider struct {
				Name string `json:"name"`
			} `json:"credentialProvider"`
		} `json:"credentialRef"`
	}
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("redaction changed credential reference shape: %v: %s", err, got)
	}
	if decoded.CredentialRef.Secret.Name != "backend-credentials" || decoded.CredentialRef.Secret.Namespace != "demo" ||
		decoded.CredentialRef.CredentialProvider.Name != "vault" {
		t.Fatalf("credential references changed by redaction: %s", got)
	}
}
