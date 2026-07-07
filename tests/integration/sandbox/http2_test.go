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

package sandbox

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/util/retry"
)

// TestSandboxEgressHTTP2 verifies that TLS-terminated egress traffic through
// the sandbox egress gateway works with both HTTP/2 and HTTP/1.1 downstream
// protocols. Uses curl with -w '%{http_version}' to assert the actual
// negotiated protocol version.
func TestSandboxEgressHTTP2(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			workload := src.WorkloadsOrFail(ctx)[0]
			podName := workload.PodName()
			podNS := src.NamespaceName()
			cluster := ctx.Clusters().Default()

			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]any{
				"Namespace": i.Settings().SystemNamespace,
			}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
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
        includeHosts:
        - "aliyun.com"
`).ApplyOrFail(ctx)

			curlVersion := func(httpFlag string) (string, error) {
				stdout, stderr, err := cluster.PodExec(podName, podNS, "app",
					fmt.Sprintf("curl -sS -k -o /dev/null -w '%%{http_version}' --max-time 10 %s https://aliyun.com", httpFlag))
				if err != nil {
					return "", fmt.Errorf("curl failed: %v, stderr: %s", err, stderr)
				}
				return strings.Trim(stdout, "' \n"), nil
			}

			ctx.NewSubTest("h2 through tls termination").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						ver, err := curlVersion("--http2")
						if err != nil {
							return err
						}
						if ver != "2" {
							return fmt.Errorf("expected HTTP version 2, got %s", ver)
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("http/1.1 through tls termination").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						ver, err := curlVersion("--http1.1")
						if err != nil {
							return err
						}
						if ver != "1.1" {
							return fmt.Errorf("expected HTTP version 1.1, got %s", ver)
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})
		})
}
