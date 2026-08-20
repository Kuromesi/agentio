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
	excludedHost   = "example.net"
)

// TestSniTrafficPolicyLifecycle exercises the complete Kubernetes-to-data-plane
// path. A production regression in policy conversion, selector binding, PBDS or
// SPDS delivery, the native policy store, the Wasm decision, or listener routing
// changes the certificate boundary observed by curl and fails this test.
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

func assertTLSPassthrough(ctx framework.TestContext, src echo.Instance, host string) {
	ctx.Helper()
	retry.UntilSuccessOrFail(ctx, func() error {
		stdout, stderr, err := curlExternalHTTPS(ctx, src, host, false)
		if err != nil {
			return fmt.Errorf("expected %s from %s to use the public certificate: %v\nstdout=%s\nstderr=%s",
				host, src.Config().Service, err, stdout, stderr)
		}
		if strings.TrimSpace(stdout) != "200" {
			return fmt.Errorf("expected HTTP 200 from %s through TLS passthrough, got %q; stderr=%s", host, stdout, stderr)
		}
		return nil
	}, retry.Timeout(3*time.Minute), retry.Delay(5*time.Second))
}

func assertTLSTerminated(ctx framework.TestContext, src echo.Instance, host string) {
	ctx.Helper()
	retry.UntilSuccessOrFail(ctx, func() error {
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
	}, retry.Timeout(3*time.Minute), retry.Delay(5*time.Second))
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
