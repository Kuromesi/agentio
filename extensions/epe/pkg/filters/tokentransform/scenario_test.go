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

// Scenario tests drive the real extproc.Server over a scripted Envoy stream
// with tokentransform's own payload schema — no policy CRD, so the CRD's
// defaulting never runs and the filter-side defaults (target header, fail
// strategy) are what these scenarios pin. CRD-shaped payload translation is
// testing/securityprofile's job.
package tokentransform_test

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"istio.io/istio/extensions/epe/pkg/filters/tokentransform"
	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
)

const injectPayload = `{
	"credentialRef": {"secret": {"name": "api-cred", "namespace": "test-ns"}},
	"apiKey": {"valueTemplate": "Bearer {{ .Token }}"}
}`

func newInjectHarness(t *testing.T, payload string, objects ...*corev1.Secret) *enginetest.Harness {
	t.Helper()
	cs := k8sfake.NewClientset()
	for _, s := range objects {
		if _, err := cs.CoreV1().Secrets(s.Namespace).Create(t.Context(), s, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	return enginetest.NewSingleFilter(t, enginetest.SingleFilter{
		Definition: tokentransform.NewDefinition(tokentransform.Deps{Kube: cs}),
		Payload:    payload,
	})
}

func apiKeySecret(namespace, name, token string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data:       map[string][]byte{"apiKey": []byte(token)},
	}
}

func injectRequest() *enginetest.RequestBuilder {
	return enginetest.NewRequest("GET", "api.example.com", "/v1").
		Peer("test-ns", "sandbox-a", map[string]string{"app": "sandbox"})
}

// The golden path: the Secret is read, the value template renders the token,
// and — via the filter-side default — the mutation lands on the lower-cased
// authorization header.
func TestScenario_SecretTokenInjectedIntoDefaultHeader(t *testing.T) {
	h := newInjectHarness(t, injectPayload, apiKeySecret("test-ns", "api-cred", "secret-token-123"))
	verdict := h.Run(t, injectRequest())
	verdict.RequireOutcome(t, "mutated")
	verdict.RequireHeader(t, "authorization", "Bearer secret-token-123")
}

// A missing credential resolves through the payload's failStrategy, never
// through an ext_proc processing error: the zero value fails closed (the CRD
// defaults it to Block, and a payload that skipped defaulting must too),
// Allow forwards unmodified.
func TestScenario_MissingSecretFailStrategy(t *testing.T) {
	t.Run("zero value blocks with 403", func(t *testing.T) {
		verdict := newInjectHarness(t, injectPayload).Run(t, injectRequest())
		verdict.RequireBlocked(t, 403)
		if verdict.Err != nil {
			t.Fatalf("failStrategy must resolve the failure, got processing error: %v", verdict.Err)
		}
	})
	t.Run("Allow passes through", func(t *testing.T) {
		payload := `{
			"failStrategy": "Allow",
			"credentialRef": {"secret": {"name": "api-cred", "namespace": "test-ns"}},
			"apiKey": {"valueTemplate": "Bearer {{ .Token }}"}
		}`
		verdict := newInjectHarness(t, payload).Run(t, injectRequest())
		if verdict.Err != nil {
			t.Fatalf("Process: %v", verdict.Err)
		}
		if verdict.Kind != enginetest.VerdictPassthrough {
			t.Fatalf("verdict = %s, want the request forwarded unmodified", verdict.Kind)
		}
	})
}
