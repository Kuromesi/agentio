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

	"github.com/openkruise/agentio/extensions/epe/pkg/credential/credentialtest"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

const injectPayload = `{
	"credentialRef": {"secret": {"name": "api-cred", "namespace": "test-ns"}},
	"apiKey": {"valueTemplate": "Bearer {{ .Token }}"}
}`

func newInjectHarness(t *testing.T, payload string, objects ...*corev1.Secret) *enginetest.Harness {
	t.Helper()
	return newInjectHarnessWithDeps(t, payload, tokentransform.Deps{}, objects...)
}

func newInjectHarnessWithDeps(
	t *testing.T,
	payload string,
	deps tokentransform.Deps,
	objects ...*corev1.Secret,
) *enginetest.Harness {
	t.Helper()
	cs := k8sfake.NewClientset()
	for _, s := range objects {
		if _, err := cs.CoreV1().Secrets(s.Namespace).Create(t.Context(), s, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	deps.Kube = cs
	return enginetest.NewSingleFilter(t, enginetest.SingleFilter{
		Definition: tokentransform.NewDefinition(deps),
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

// One targetHeaders selector drives one credential fetch into multiple
// headers, and the shared value source lands on each lower-cased name.
func TestScenario_SecretTokenInjectedIntoMultipleHeaders(t *testing.T) {
	payload := `{
			"credentialRef": {"secret": {"name": "api-cred", "namespace": "test-ns"}},
			"apiKey": {
				"targetHeaders": {"names": ["Authorization", "X-API-Key"]},
				"value": {"template": "Bearer {{ .Token }}"}
			}
		}`
	h := newInjectHarness(t, payload, apiKeySecret("test-ns", "api-cred", "secret-token-123"))
	verdict := h.Run(t, injectRequest())
	verdict.RequireOutcome(t, "mutated")
	verdict.RequireHeader(t, "authorization", "Bearer secret-token-123")
	verdict.RequireHeader(t, "x-api-key", "Bearer secret-token-123")
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

func TestScenario_ApiKeyHeaderSelectorFetchesOnceAndTouchesOnlySelectedHeaders(t *testing.T) {
	provider := credentialtest.NewAPIKeyProvider(t, "provider-token")
	payload := `{
		"credentialRef": {"credentialProvider": {"name": "provider"}},
		"apiKey": {
			"targetHeaders": {"cel": "request.headers.filter(name, name.startsWith('x-token-'))"},
			"value": {"template": "Bearer {{ .Token }}"}
		}
	}`
	h := newInjectHarnessWithDeps(t, payload, tokentransform.Deps{Tokens: provider.Client()})
	verdict := h.Run(t, injectRequest().
		SandboxToken("request-1", "sandbox-access-token", "sandbox-client").
		Header("x-token-a", "caller-a").
		Header("x-token-b", "caller-b").
		Header("x-other", "keep"))

	verdict.RequireOutcome(t, "mutated")
	verdict.RequireHeader(t, "x-token-a", "Bearer provider-token")
	verdict.RequireHeader(t, "x-token-b", "Bearer provider-token")
	if got := verdict.RequestHeaderValues("x-other"); len(got) != 0 {
		t.Fatalf("x-other mutations = %v, want none", got)
	}
	if got := provider.Calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1 for both selected headers", got)
	}
}

func TestScenario_ApiKeyPlaceholderSelectorRewritesEveryOriginalPlaceholder(t *testing.T) {
	provider := credentialtest.NewAPIKeyProvider(t, "provider-token")
	payload := `{
		"credentialRef": {"credentialProvider": {"name": "provider"}},
		"apiKey": {
			"targetHeaders": {"cel": "request.headers.filter(name, request.headers[name] == '${AGENTIO_TOKEN}')"},
			"value": {"template": "Bearer {{ .Token }}"}
		}
	}`
	h := newInjectHarnessWithDeps(t, payload, tokentransform.Deps{Tokens: provider.Client()})
	verdict := h.Run(t, injectRequest().
		SandboxToken("request-1", "sandbox-access-token", "sandbox-client").
		Header("authorization", "${AGENTIO_TOKEN}").
		Header("x-unknown-at-config-time", "${AGENTIO_TOKEN}").
		Header("x-other", "keep"))

	verdict.RequireOutcome(t, "mutated")
	verdict.RequireHeader(t, "authorization", "Bearer provider-token")
	verdict.RequireHeader(t, "x-unknown-at-config-time", "Bearer provider-token")
	if got := verdict.RequestHeaderValues("x-other"); len(got) != 0 {
		t.Fatalf("x-other mutations = %v, want none", got)
	}
	if got := provider.Calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1 for every placeholder target", got)
	}
}

func TestScenario_ApiKeySelectorWithNoTargetsSkipsProviderWithoutPeerToken(t *testing.T) {
	provider := credentialtest.NewErrorProvider(t, 500, "unreachable")
	payload := `{
		"credentialRef": {"credentialProvider": {"name": "provider"}},
		"apiKey": {
			"targetHeaders": {"cel": "request.headers.filter(name, name.startsWith('x-token-'))"},
			"value": {"value": "unused"}
		}
	}`
	h := newInjectHarnessWithDeps(t, payload, tokentransform.Deps{Tokens: provider.Client()})
	verdict := h.Run(t, injectRequest().Header("x-other", "keep"))

	verdict.RequirePassthrough(t)
	if len(verdict.RequestHeaderOps) != 0 {
		t.Fatalf("mutations = %+v, want none", verdict.RequestHeaderOps)
	}
	if got := provider.Calls.Load(); got != 0 {
		t.Fatalf("provider calls = %d, want 0 when selector has no targets", got)
	}
}

func TestScenario_ApiKeyHeaderValueFailureIsAtomicUnderAllow(t *testing.T) {
	provider := credentialtest.NewAPIKeyProvider(t, "provider-token")
	payload := `{
		"failStrategy": "Allow",
		"credentialRef": {"credentialProvider": {"name": "provider"}},
		"apiKey": {
			"targetHeaders": {"names": ["x-first", "x-second"]},
			"value": {"template": "{{ if eq .Header.Name \"x-second\" }}{{ fail \"second header failed\" }}{{ else }}first{{ end }}"}
		}
	}`
	h := newInjectHarnessWithDeps(t, payload, tokentransform.Deps{Tokens: provider.Client()})
	verdict := h.Run(t, injectRequest().
		SandboxToken("request-1", "sandbox-access-token", "sandbox-client"))

	verdict.RequirePassthrough(t)
	if len(verdict.RequestHeaderOps) != 0 {
		t.Fatalf("mutations = %+v, want no partial x-first mutation", verdict.RequestHeaderOps)
	}
	if got := provider.Calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1 before value rendering fails", got)
	}
}

func TestScenario_ApiKeyDuplicateDynamicTargetFailsBeforeProviderFetch(t *testing.T) {
	for _, tc := range []struct {
		name         string
		failStrategy string
		blocked      bool
	}{
		{name: "Allow continues", failStrategy: "Allow"},
		{name: "Block stops", failStrategy: "Block", blocked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := credentialtest.NewAPIKeyProvider(t, "provider-token")
			payload := `{
				"failStrategy": "` + tc.failStrategy + `",
				"credentialRef": {"credentialProvider": {"name": "provider"}},
				"apiKey": {
					"targetHeaders": {"cel": "['x-token', 'X-Token']"},
					"value": {"value": "replacement"}
				}
			}`
			h := newInjectHarnessWithDeps(t, payload, tokentransform.Deps{Tokens: provider.Client()})
			verdict := h.Run(t, injectRequest().
				SandboxToken("request-1", "sandbox-access-token", "sandbox-client").
				Header("x-token", "caller"))

			if tc.blocked {
				verdict.RequireBlocked(t, 403)
			} else {
				verdict.RequirePassthrough(t)
			}
			if len(verdict.RequestHeaderOps) != 0 {
				t.Fatalf("mutations = %+v, want none", verdict.RequestHeaderOps)
			}
			if got := provider.Calls.Load(); got != 0 {
				t.Fatalf("provider calls = %d, want 0 before duplicate target failure", got)
			}
		})
	}
}
