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

package securitypolicy

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/components/echo"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

const (
	terminatedHost = "example.com"
	wildcardHost   = "www.example.com"
	excludedHost   = "example.net"
)

// TestSniTrafficPolicyLifecycle exercises the complete Kubernetes-to-data-plane
// path. A production regression in policy conversion, selector binding, xDS
// delivery, the native policy store, the custom matcher decision, or listener
// routing changes the certificate boundary observed by curl and fails this test.
func TestSniTrafficPolicyLifecycle(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	applySNITrafficConfig(t, scope)

	selected := sniFixture.selected
	unselected := sniFixture.unselected
	global := sniFixture.global

	if !t.Run("without policy all workloads use TLS passthrough", func(t *testing.T) {
		assertTLSPassthrough(t, selected, terminatedHost)
		assertTLSPassthrough(t, unselected, terminatedHost)
		assertTLSPassthrough(t, global, terminatedHost)
	}) {
		return
	}

	namespacedPolicy := e2econfig.New(scope).Eval(sniFixture.localNamespace.Name(), map[string]any{
		"Namespace": sniFixture.localNamespace.Name(),
	}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: terminate-selected-sni
  namespace: {{ .Namespace }}
spec:
  priority: 10
  selector:
    matchLabels:
      `+sniPolicyLabel+`: selected
  rules:
  - name: tls-termination
    match:
    - domains:
      - "`+terminatedHost+`"
      - "`+excludedHost+`"
      schemes:
      - https
    actions:
      bypass: true
`)
	namespacedPolicy.ApplyOrFail(t, kube.CreateOnly)

	if !t.Run("namespaced selector terminates only the selected workload", func(t *testing.T) {
		assertTLSTerminated(t, selected, terminatedHost)
		assertTLSPassthrough(t, unselected, terminatedHost)
		assertTLSPassthrough(t, global, terminatedHost)
	}) {
		return
	}

	if !t.Run("excludeHosts wins over a matching policy", func(t *testing.T) {
		assertTLSPassthrough(t, selected, excludedHost)
	}) {
		return
	}

	globalPolicy := e2econfig.New(scope).Eval(sniFixture.globalNamespace.Name(), map[string]any{}, `
apiVersion: agents.kruise.io/v1alpha1
kind: GlobalSecurityProfile
metadata:
  name: terminate-global-sni
spec:
  priority: 20
  selector:
    matchLabels:
      `+sniPolicyLabel+`: global
  rules:
  - name: tls-termination
    match:
    - domains:
      - "`+terminatedHost+`"
      schemes:
      - https
    actions:
      bypass: true
`)
	globalPolicy.ApplyOrFail(t, kube.CreateOnly)

	if !t.Run("global profile selects a workload in another namespace", func(t *testing.T) {
		assertTLSTerminated(t, global, terminatedHost)
		assertTLSPassthrough(t, unselected, terminatedHost)
	}) {
		return
	}

	t.Run("deleting policies restores passthrough", func(t *testing.T) {
		namespacedPolicy.DeleteOrFail(t)
		globalPolicy.DeleteOrFail(t)
		assertTLSPassthrough(t, selected, terminatedHost)
		assertTLSPassthrough(t, global, terminatedHost)
	})
}

// TestSniTrafficPolicyWildcardAndHotUpdate verifies the matching boundary and
// cache invalidation contract of the native SNI policy matcher. A wildcard
// matches a subdomain but never the apex; updating the same policy must reverse
// both decisions for newly established connections without retaining a stale
// worker-local compiled policy.
func TestSniTrafficPolicyWildcardAndHotUpdate(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	applySNITrafficConfig(t, scope)

	selected := sniFixture.selected
	unselected := sniFixture.unselected

	wildcardPolicy := e2econfig.New(scope).Eval(sniFixture.localNamespace.Name(), map[string]any{
		"Namespace": sniFixture.localNamespace.Name(),
	}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: wildcard-hot-update
  namespace: {{ .Namespace }}
spec:
  priority: 10
  selector:
    matchLabels:
      `+sniPolicyLabel+`: selected
  rules:
  - name: wildcard
    match:
    - domains:
      - "*.`+terminatedHost+`"
      schemes:
      - https
    actions:
      bypass: true
`)
	wildcardPolicy.ApplyOrFail(t, kube.CreateOnly)

	if !t.Run("wildcard terminates a subdomain but not the apex", func(t *testing.T) {
		assertTLSTerminated(t, selected, wildcardHost)
		assertTLSPassthrough(t, selected, terminatedHost)
		assertTLSPassthrough(t, unselected, wildcardHost)
	}) {
		return
	}

	exactPolicy := e2econfig.New(scope).Eval(sniFixture.localNamespace.Name(), map[string]any{
		"Namespace": sniFixture.localNamespace.Name(),
	}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: wildcard-hot-update
  namespace: {{ .Namespace }}
spec:
  priority: 10
  selector:
    matchLabels:
      `+sniPolicyLabel+`: selected
  rules:
  - name: exact
    match:
    - domains:
      - "`+terminatedHost+`"
      schemes:
      - https
    actions:
      bypass: true
`)
	exactPolicy.ApplyOrFail(t, kube.ReconcileOwned)

	if !t.Run("hot update invalidates the previous wildcard decision", func(t *testing.T) {
		assertTLSTerminated(t, selected, terminatedHost)
		assertTLSPassthrough(t, selected, wildcardHost)
		assertRepeatedTLSTermination(t, selected, terminatedHost, 3)
		assertRepeatedTLSPassthrough(t, selected, wildcardHost, 3)
	}) {
		return
	}

	t.Run("deleting the updated policy restores passthrough", func(t *testing.T) {
		exactPolicy.DeleteOrFail(t)
		assertTLSPassthrough(t, selected, terminatedHost)
	})
}

func applySNITrafficConfig(t *testing.T, scope *kube.ResourceScope) {
	t.Helper()
	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      tlsTermination:
        # includeHosts remains the authorization boundary for on-demand SDS.
        # SecurityProfiles decide which matching workloads actually terminate.
        includeHosts:
        - "example.com"
        - "*.example.com"
        excludeHosts:
        - "example.net"
`)
}

func assertTLSPassthrough(t *testing.T, source echo.Instance, host string) {
	t.Helper()
	harness.RetryAssertion(t, 3*time.Minute, 5*time.Second, func() error {
		return checkTLSPassthrough(t, source, host)
	})
}

func assertTLSTerminated(t *testing.T, source echo.Instance, host string) {
	t.Helper()
	harness.RetryAssertion(t, 3*time.Minute, 5*time.Second, func() error {
		return checkTLSTerminated(t, source, host)
	})
}

func assertRepeatedTLSPassthrough(t *testing.T, source echo.Instance, host string, count int) {
	t.Helper()
	for connection := 1; connection <= count; connection++ {
		if err := checkTLSPassthrough(t, source, host); err != nil {
			t.Fatalf("passthrough connection %d/%d failed: %v", connection, count, err)
		}
	}
}

func assertRepeatedTLSTermination(t *testing.T, source echo.Instance, host string, count int) {
	t.Helper()
	for connection := 1; connection <= count; connection++ {
		if err := checkTLSTerminated(t, source, host); err != nil {
			t.Fatalf("TLS termination connection %d/%d failed: %v", connection, count, err)
		}
	}
}

func checkTLSPassthrough(t *testing.T, source echo.Instance, host string) error {
	t.Helper()
	stdout, stderr, err := curlExternalHTTPS(t, source, host, false)
	if err != nil {
		return fmt.Errorf("expected %s from %s to use the public certificate: %v\nstdout=%s\nstderr=%s",
			host, source.Name(), err, stdout, stderr)
	}
	if strings.TrimSpace(stdout) != "200" {
		return fmt.Errorf("expected HTTP 200 from %s through TLS passthrough, got %q; stderr=%s", host, stdout, stderr)
	}
	return nil
}

func checkTLSTerminated(t *testing.T, source echo.Instance, host string) error {
	t.Helper()
	stdout, stderr, err := curlExternalHTTPS(t, source, host, false)
	if err == nil {
		return fmt.Errorf("expected Sandbox CA trust failure for %s from %s, got HTTP %s",
			host, source.Name(), strings.TrimSpace(stdout))
	}
	if !isCertificateTrustError(stderr) {
		return fmt.Errorf("expected Sandbox CA trust failure for %s from %s: %v\nstderr=%s",
			host, source.Name(), err, stderr)
	}

	stdout, stderr, err = curlExternalHTTPS(t, source, host, true)
	if err != nil {
		return fmt.Errorf("TLS-terminated request to %s from %s failed with verification disabled: %v\nstdout=%s\nstderr=%s",
			host, source.Name(), err, stdout, stderr)
	}
	if strings.TrimSpace(stdout) != "200" {
		return fmt.Errorf("expected HTTP 200 after TLS termination for %s, got %q; stderr=%s", host, stdout, stderr)
	}
	return nil
}

func curlExternalHTTPS(t *testing.T, source echo.Instance, host string, insecure bool) (string, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	arguments := []string{"curl", "-sS"}
	if insecure {
		arguments = append(arguments, "-k")
	}
	arguments = append(arguments,
		"-o", "/dev/null", "-w", "%{http_code}",
		"--connect-timeout", "10", "--max-time", "20", "https://"+host+"/",
	)
	return source.Exec(ctx, arguments)
}

func isCertificateTrustError(stderr string) bool {
	return strings.Contains(stderr, "SSL certificate") ||
		strings.Contains(stderr, "self-signed") ||
		strings.Contains(stderr, "unable to get local issuer") ||
		strings.Contains(stderr, "certificate verify failed")
}
