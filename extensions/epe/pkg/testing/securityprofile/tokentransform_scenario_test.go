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

// Full-chain tokentransform scenarios for the built-in ApiKey signer,
// driven through the enginetest harness; see
// extensions/epe/pkg/testing/enginetest/doc.go for the test layering
// convention. They prove the CRD-to-header wiring, defaulting, and
// wire-level fail strategies. Signer internals stay in apikey_test.go.
package securityprofile

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"istio.io/istio/extensions/epe/pkg/credential/credentialtest"
	"istio.io/istio/extensions/epe/pkg/credential/tokencache"
	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
	"istio.io/istio/pkg/kube"
)

const injectionPath = "/token/inject"

func secretInjectionProfileYAML(extraTokenTransformationYAML string) string {
	return fmt.Sprintf(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: token-injection
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: inject
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: %s
    actions:
      tokenTransformation:
        credentialRef:
          kind: Secret
          name: api-cred
        apiKey:
          valueTemplate: 'Bearer {{ .Token }}'
%s`, injectionPath, extraTokenTransformationYAML)
}

func injectionRequest() *enginetest.RequestBuilder {
	return enginetest.NewRequest("GET", "server.example.com", injectionPath).
		Peer("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"})
}

// TestScenario_SecretAPIKeyInjectedIntoDefaultHeader proves the ApiKey
// Kind=Secret path end to end: the Secret is read from the pod namespace,
// the value template renders the token, and — via the EPE legacy fallback —
// the mutation lands on the Authorization header.
func TestScenario_SecretAPIKeyInjectedIntoDefaultHeader(t *testing.T) {
	kubeClient := kube.NewFakeClient(newAPIKeySecret("test-ns", "api-cred", "secret-token-123"))
	h := New(t, Options{Kube: kubeClient})
	h.Fixture.ApplyYAML(secretInjectionProfileYAML(""))

	verdict := h.Run(t, injectionRequest())
	verdict.RequireOutcome(t, "mutated")
	verdict.RequireHeader(t, "Authorization", "Bearer secret-token-123")

	// Near miss: a non-matching path must pass through untouched.
	h.Run(t, enginetest.NewRequest("GET", "server.example.com", "/token/other").
		Peer("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"})).
		RequirePassthrough(t)
}

// TestScenario_MissingSecretFailStrategy proves both wire-level fail
// strategies. The Block case omits failStrategy entirely, so it also
// proves the CRD default (Block) reaches the filter.
func TestScenario_MissingSecretFailStrategy(t *testing.T) {
	t.Run("default strategy blocks with 403", func(t *testing.T) {
		h := New(t, Options{Kube: kube.NewFakeClient()})
		h.Fixture.ApplyYAML(secretInjectionProfileYAML(""))

		verdict := h.Run(t, injectionRequest())
		verdict.RequireBlocked(t, 403)
		if !strings.Contains(verdict.ImmediateBody, "tokentransform:") {
			t.Errorf("block body = %q, want tokentransform failure text", verdict.ImmediateBody)
		}
	})

	t.Run("allow strategy passes through", func(t *testing.T) {
		h := New(t, Options{Kube: kube.NewFakeClient()})
		h.Fixture.ApplyYAML(secretInjectionProfileYAML("        failStrategy: Allow\n"))

		h.Run(t, injectionRequest()).RequirePassthrough(t)
	})
}

// TestScenario_NewAPIKeySelectorWithCredentialProvider proves the v0.6 ApiKey
// shape end to end: CEL selects every placeholder-valued request header, one
// provider credential rewrites all of them, and the cache absorbs the second
// request.
func TestScenario_NewAPIKeySelectorWithCredentialProvider(t *testing.T) {
	provider := credentialtest.NewAPIKeyProvider(t, "provider-token")
	client := provider.ClientWithCache(tokencache.NewCache(time.Hour, 16), nil)
	h := New(t, Options{CredentialClient: client})
	h.Fixture.ApplyYAML(fmt.Sprintf(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: token-provider
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: provider-inject
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: %s
    actions:
      tokenTransformation:
        credentialRef:
          kind: CredentialProvider
          name: my-provider
        apiKey:
          targetHeaders:
            cel: 'request.headers.filter(name, request.headers[name] == "${AGENTIO_TOKEN}")'
          value:
            template: 'Bearer {{ .Token }}'
`, injectionPath))

	request := func() *enginetest.RequestBuilder {
		return injectionRequest().
			SandboxToken("req-1", "sandbox-access-token", "sandbox-client-1").
			Header("authorization", "${AGENTIO_TOKEN}").
			Header("x-api-key", "${AGENTIO_TOKEN}")
	}

	verdict := h.Run(t, request())
	verdict.RequireHeader(t, "Authorization", "Bearer provider-token")
	verdict.RequireHeader(t, "X-API-Key", "Bearer provider-token")
	if got := provider.Calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
	if got := provider.LastAuthorization.Load(); got != "Bearer sandbox-access-token" {
		t.Errorf("provider Authorization = %v, want sandbox access token", got)
	}

	// Second request must be served from the token cache.
	verdict = h.Run(t, request())
	verdict.RequireHeader(t, "Authorization", "Bearer provider-token")
	verdict.RequireHeader(t, "X-API-Key", "Bearer provider-token")
	if got := provider.Calls.Load(); got != 1 {
		t.Errorf("provider calls after cache hit = %d, want 1", got)
	}
}

// TestScenario_LegacyApiKeyFieldsRemainAFullChainContract keeps the released
// API shape on the typed bridge: type, targetHeader, valueTemplate, and when
// are all legacy ApiKey fields. The provider counter proves that matching the
// condition still fetches exactly once, while a non-match does not fetch.
func TestScenario_LegacyApiKeyFieldsRemainAFullChainContract(t *testing.T) {
	provider := credentialtest.NewAPIKeyProvider(t, "provider-token")
	h := New(t, Options{CredentialClient: provider.Client()})
	h.Fixture.ApplyYAML(fmt.Sprintf(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: legacy-api-key
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: legacy-api-key
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: %s
    actions:
      tokenTransformation:
        type: ApiKey
        credentialRef:
          kind: CredentialProvider
          name: legacy-provider
        apiKey:
          targetHeader: X-Legacy-API-Key
          valueTemplate: 'Bearer {{ .Token }}'
          when:
            header: X-Legacy-Guard
            pattern: '^enabled$'
`, injectionPath))

	matching := injectionRequest().
		SandboxToken("request-1", "sandbox-access-token", "sandbox-client").
		Header("x-legacy-guard", "enabled")
	h.Run(t, matching).RequireHeader(t, "X-Legacy-API-Key", "Bearer provider-token")
	if got := provider.Calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1 after matching legacy ApiKey rule", got)
	}

	notMatching := injectionRequest().
		SandboxToken("request-2", "sandbox-access-token", "sandbox-client").
		Header("x-legacy-guard", "disabled")
	h.Run(t, notMatching).RequirePassthrough(t)
	if got := provider.Calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want no fetch when legacy when does not match", got)
	}
}

// TestScenario_WhenConditionGatesInjection proves the compiled When regex
// from the CRD gates injection on the incoming header value.
func TestScenario_WhenConditionGatesInjection(t *testing.T) {
	kubeClient := kube.NewFakeClient(newAPIKeySecret("test-ns", "api-cred", "rotated-token"))
	h := New(t, Options{Kube: kubeClient})
	h.Fixture.ApplyYAML(fmt.Sprintf(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: token-when
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: conditional-inject
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: %s
    actions:
      tokenTransformation:
        credentialRef:
          kind: Secret
          name: api-cred
        apiKey:
          when:
            header: Authorization
            pattern: '^Bearer legacy-.*$'
          valueTemplate: 'Bearer {{ .Token }}'
`, injectionPath))

	matched := h.Run(t, injectionRequest().Header("authorization", "Bearer legacy-abc"))
	matched.RequireHeader(t, "Authorization", "Bearer rotated-token")

	h.Run(t, injectionRequest().Header("authorization", "Bearer fresh-xyz")).
		RequirePassthrough(t)
}
