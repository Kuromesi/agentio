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

package agentio

import (
	"net"
	"net/http"
	"testing"
	"time"

	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/test/util/retry"
)

// TestSandboxHTTPDFPAuthorityRouting verifies that the sandbox catch-all HTTP
// path selects its upstream from :authority instead of the intercepted original
// destination. TEST-NET-1 is intentionally unreachable; both requests can
// succeed only when DFP uses the supplied hostname or IP literal.
func TestSandboxHTTPDFPAuthorityRouting(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			dst := all[1]
			dstPod := dst.WorkloadsOrFail(ctx)[0].PodName()

			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]any{
				"Namespace": i.Settings().SystemNamespace,
			}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
data:
  config: |
    sandboxExtProc:
      service: ext-proc.{{ .Namespace }}.svc.cluster.local
      port: 9002
      failureModeAllow: true
      request:
        headerMode: SEND
      response:
        headerMode: SEND
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
`).ApplyOrFail(ctx)

			callAuthority := func(authority string) error {
				headers := http.Header{}
				headers.Set("Host", authority)
				_, err := src.Call(echo.CallOptions{
					Address: "192.0.2.1",
					Port: echo.Port{
						Protocol:    protocol.HTTP,
						ServicePort: 80,
					},
					Scheme: scheme.HTTP,
					HTTP: echo.HTTP{
						Headers: headers,
					},
					Check: check.And(
						check.OK(),
						check.Hostname(dstPod),
						check.RequestHeader("X-Hello-To-Ext-Proc", "true"),
					),
				})
				return err
			}

			ctx.NewSubTest("hostname authority selects upstream").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						return callAuthority(dst.Config().ClusterLocalFQDN())
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("IP literal authority selects upstream").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						return callAuthority(net.JoinHostPort(dst.Address(), "80"))
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})
		})
}
