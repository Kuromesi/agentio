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
package securityprofiletest

import (
	"fmt"
	"strings"
	"testing"
	"time"

	k8sfake "k8s.io/client-go/kubernetes/fake"

	"istio.io/istio/extensions/epe/pkg/credential/credentialtest"
	"istio.io/istio/extensions/epe/pkg/credential/tokencache"
	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
	"istio.io/istio/extensions/epe/pkg/testing/filtertest"
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
// the value template renders the token, and — via CRD defaulting — the
// mutation lands on the default Authorization header.
func TestScenario_SecretAPIKeyInjectedIntoDefaultHeader(t *testing.T) {
	kube := k8sfake.NewClientset(filtertest.APIKeySecret("test-ns", "api-cred", "secret-token-123"))
	h := New(t, Options{Kube: kube})
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
		h := New(t, Options{Kube: k8sfake.NewClientset()})
		h.Fixture.ApplyYAML(secretInjectionProfileYAML(""))

		verdict := h.Run(t, injectionRequest())
		verdict.RequireBlocked(t, 403)
		if !strings.Contains(verdict.ImmediateBody, "tokentransform:") {
			t.Errorf("block body = %q, want tokentransform failure text", verdict.ImmediateBody)
		}
	})

	t.Run("allow strategy passes through", func(t *testing.T) {
		h := New(t, Options{Kube: k8sfake.NewClientset()})
		h.Fixture.ApplyYAML(secretInjectionProfileYAML("        failStrategy: Allow\n"))

		h.Run(t, injectionRequest()).RequirePassthrough(t)
	})
}

// TestScenario_CredentialProviderInjectsAndCaches proves the ApiKey
// Kind=CredentialProvider path end to end: the sandbox token from
// filter_state authenticates the provider call, the returned key lands in
// the header, and the token cache absorbs the second request.
func TestScenario_CredentialProviderInjectsAndCaches(t *testing.T) {
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
          valueTemplate: 'Bearer {{ .Token }}'
`, injectionPath))

	request := func() *enginetest.RequestBuilder {
		return injectionRequest().SandboxToken("req-1", "sandbox-access-token", "sandbox-client-1")
	}

	h.Run(t, request()).RequireHeader(t, "Authorization", "Bearer provider-token")
	if got := provider.Calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
	if got := provider.LastAuthorization.Load(); got != "Bearer sandbox-access-token" {
		t.Errorf("provider Authorization = %v, want sandbox access token", got)
	}

	// Second request must be served from the token cache.
	h.Run(t, request()).RequireHeader(t, "Authorization", "Bearer provider-token")
	if got := provider.Calls.Load(); got != 1 {
		t.Errorf("provider calls after cache hit = %d, want 1", got)
	}
}

// TestScenario_WhenConditionGatesInjection proves the compiled When regex
// from the CRD gates injection on the incoming header value.
func TestScenario_WhenConditionGatesInjection(t *testing.T) {
	kube := k8sfake.NewClientset(filtertest.APIKeySecret("test-ns", "api-cred", "rotated-token"))
	h := New(t, Options{Kube: kube})
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
