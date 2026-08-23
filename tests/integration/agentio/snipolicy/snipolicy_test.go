//go:build integ

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

package snipolicy

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/util/retry"
)

const (
	terminatedHost = "example.com"
	wildcardHost   = "www.example.com"
	excludedHost   = "example.net"
)

// TestSniTrafficPolicyLifecycle exercises the complete Kubernetes-to-data-plane
// path. A production regression in policy conversion, selector binding, WDS or
// STPDS delivery, the native policy store, the custom matcher decision, or
// listener routing changes the certificate boundary observed by curl and fails
// this test.
func TestSniTrafficPolicyLifecycle(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			ctx.NewSubTest("without policy all workloads use TLS passthrough").
				Run(func(ctx framework.TestContext) {
					assertTLSPassthrough(ctx, selected, terminatedHost)
					assertTLSPassthrough(ctx, unselected, terminatedHost)
					assertTLSPassthrough(ctx, global, terminatedHost)
				})

			namespacedPolicy := ctx.ConfigIstio().Eval(localNS.Name(), map[string]any{
				"Namespace": localNS.Name(),
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
      `+policyLabelKey+`: selected
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
			namespacedPolicy.ApplyOrFail(ctx)

			ctx.NewSubTest("namespaced selector terminates only the selected workload").
				Run(func(ctx framework.TestContext) {
					assertTLSTerminated(ctx, selected, terminatedHost)
					assertTLSPassthrough(ctx, unselected, terminatedHost)
					assertTLSPassthrough(ctx, global, terminatedHost)
				})

			ctx.NewSubTest("excludeHosts wins over a matching policy").
				Run(func(ctx framework.TestContext) {
					assertTLSPassthrough(ctx, selected, excludedHost)
				})

			globalPolicy := ctx.ConfigIstio().Eval(globalNS.Name(), map[string]any{}, `
apiVersion: agents.kruise.io/v1alpha1
kind: GlobalSecurityProfile
metadata:
  name: terminate-global-sni
spec:
  priority: 20
  selector:
    matchLabels:
      `+policyLabelKey+`: global
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
			globalPolicy.ApplyOrFail(ctx)

			ctx.NewSubTest("global profile selects a workload in another namespace").
				Run(func(ctx framework.TestContext) {
					assertTLSTerminated(ctx, global, terminatedHost)
					assertTLSPassthrough(ctx, unselected, terminatedHost)
				})

			ctx.NewSubTest("deleting policies restores passthrough").
				Run(func(ctx framework.TestContext) {
					namespacedPolicy.DeleteOrFail(ctx)
					globalPolicy.DeleteOrFail(ctx)
					assertTLSPassthrough(ctx, selected, terminatedHost)
					assertTLSPassthrough(ctx, global, terminatedHost)
				})
		})
}

// TestSniTrafficPolicyWildcardAndHotUpdate verifies the matching boundary and
// cache invalidation contract of the native SNI policy matcher. A wildcard
// matches a subdomain but never the apex; updating the same policy must reverse
// both decisions for newly established connections without retaining a stale
// worker-local compiled policy.
func TestSniTrafficPolicyWildcardAndHotUpdate(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			wildcardPolicy := ctx.ConfigIstio().Eval(localNS.Name(), map[string]any{
				"Namespace": localNS.Name(),
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
      `+policyLabelKey+`: selected
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
			wildcardPolicy.ApplyOrFail(ctx)

			ctx.NewSubTest("wildcard terminates a subdomain but not the apex").
				Run(func(ctx framework.TestContext) {
					assertTLSTerminated(ctx, selected, wildcardHost)
					assertTLSPassthrough(ctx, selected, terminatedHost)
					assertTLSPassthrough(ctx, unselected, wildcardHost)
				})

			exactPolicy := ctx.ConfigIstio().Eval(localNS.Name(), map[string]any{
				"Namespace": localNS.Name(),
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
      `+policyLabelKey+`: selected
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
			exactPolicy.ApplyOrFail(ctx)

			ctx.NewSubTest("hot update invalidates the previous wildcard decision").
				Run(func(ctx framework.TestContext) {
					assertTLSTerminated(ctx, selected, terminatedHost)
					assertTLSPassthrough(ctx, selected, wildcardHost)
					assertRepeatedTLSTermination(ctx, selected, terminatedHost, 3)
					assertRepeatedTLSPassthrough(ctx, selected, wildcardHost, 3)
				})

			ctx.NewSubTest("deleting the updated policy restores passthrough").
				Run(func(ctx framework.TestContext) {
					exactPolicy.DeleteOrFail(ctx)
					assertTLSPassthrough(ctx, selected, terminatedHost)
				})
		})
}

func assertTLSPassthrough(ctx framework.TestContext, src echo.Instance, host string) {
	ctx.Helper()
	retry.UntilSuccessOrFail(ctx, func() error {
		return checkTLSPassthrough(ctx, src, host)
	}, retry.Timeout(3*time.Minute), retry.Delay(5*time.Second))
}

func assertTLSTerminated(ctx framework.TestContext, src echo.Instance, host string) {
	ctx.Helper()
	retry.UntilSuccessOrFail(ctx, func() error {
		return checkTLSTerminated(ctx, src, host)
	}, retry.Timeout(3*time.Minute), retry.Delay(5*time.Second))
}

func assertRepeatedTLSPassthrough(ctx framework.TestContext, src echo.Instance, host string, count int) {
	ctx.Helper()
	for connection := 1; connection <= count; connection++ {
		if err := checkTLSPassthrough(ctx, src, host); err != nil {
			ctx.Fatalf("passthrough connection %d/%d failed: %v", connection, count, err)
		}
	}
}

func assertRepeatedTLSTermination(ctx framework.TestContext, src echo.Instance, host string, count int) {
	ctx.Helper()
	for connection := 1; connection <= count; connection++ {
		if err := checkTLSTerminated(ctx, src, host); err != nil {
			ctx.Fatalf("TLS termination connection %d/%d failed: %v", connection, count, err)
		}
	}
}

func checkTLSPassthrough(ctx framework.TestContext, src echo.Instance, host string) error {
	ctx.Helper()
	stdout, stderr, err := curlExternalHTTPS(ctx, src, host, false)
	if err != nil {
		return fmt.Errorf("expected %s from %s to use the public certificate: %v\nstdout=%s\nstderr=%s",
			host, src.Config().Service, err, stdout, stderr)
	}
	if strings.TrimSpace(stdout) != "200" {
		return fmt.Errorf("expected HTTP 200 from %s through TLS passthrough, got %q; stderr=%s", host, stdout, stderr)
	}
	return nil
}

func checkTLSTerminated(ctx framework.TestContext, src echo.Instance, host string) error {
	ctx.Helper()
	stdout, stderr, err := curlExternalHTTPS(ctx, src, host, false)
	if err == nil {
		return fmt.Errorf("expected Sandbox CA trust failure for %s from %s, got HTTP %s",
			host, src.Config().Service, strings.TrimSpace(stdout))
	}
	if !isCertificateTrustError(stderr) {
		return fmt.Errorf("expected Sandbox CA trust failure for %s from %s: %v\nstderr=%s",
			host, src.Config().Service, err, stderr)
	}

	stdout, stderr, err = curlExternalHTTPS(ctx, src, host, true)
	if err != nil {
		return fmt.Errorf("TLS-terminated request to %s from %s failed with verification disabled: %v\nstdout=%s\nstderr=%s",
			host, src.Config().Service, err, stdout, stderr)
	}
	if strings.TrimSpace(stdout) != "200" {
		return fmt.Errorf("expected HTTP 200 after TLS termination for %s, got %q; stderr=%s", host, stdout, stderr)
	}
	return nil
}

func curlExternalHTTPS(ctx framework.TestContext, src echo.Instance, host string, insecure bool) (string, string, error) {
	ctx.Helper()
	workload := src.WorkloadsOrFail(ctx)[0]
	insecureFlag := ""
	if insecure {
		insecureFlag = "-k"
	}
	return ctx.Clusters().Default().PodExec(
		workload.PodName(), src.NamespaceName(), "app",
		fmt.Sprintf("curl -sS %s -o /dev/null -w %%{http_code} --connect-timeout 10 --max-time 20 https://%s/", insecureFlag, host),
	)
}

func isCertificateTrustError(stderr string) bool {
	return strings.Contains(stderr, "SSL certificate") ||
		strings.Contains(stderr, "self-signed") ||
		strings.Contains(stderr, "unable to get local issuer") ||
		strings.Contains(stderr, "certificate verify failed")
}
