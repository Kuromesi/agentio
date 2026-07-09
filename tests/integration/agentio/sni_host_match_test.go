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

// TestSandboxEgressSNIHostMatch is a regression guard for the egress allowlist
// bypass where the outer ClientHello SNI satisfies tls_termination.include_hosts
// (so an on-demand cert is issued and the handshake succeeds) but the inner
// HTTP :authority points at a different host, letting the dynamic forward
// proxy resolve to the attacker-chosen destination. The waypoint inserts a
// network-layer set_filter_state filter that captures the outer SNI into
// shared filter state, and an HCM RBAC filter that denies any inner request
// whose Host header (port stripped, case-folded) does not match.
//
// agentio-config must enable tlsTermination.includeHosts for example.com —
// without it the request never enters the tls-terminate chain, the filter
// state is never written, and the test would vacuously pass for the wrong
// reason.
//
// TLS.ServerName is pinned explicitly: echo's forwarder defaults SNI to the
// Host header when ServerName is empty (pkg/test/echo/server/forwarder/http.go),
// which would tie SNI to the attacker-controlled Host and defeat the test.
// InsecureSkipVerify is acceptable here — we assert RBAC decisions, not cert
// trust (the waypoint terminates with a sandbox-CA leaf, not the real
// example.com cert).
func TestSandboxEgressSNIHostMatch(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]

			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]any{
				"Namespace": i.Settings().SystemNamespace,
			}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
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
        - "example.com"
`).ApplyOrFail(ctx)

			callOpts := func(hostHeader string) echo.CallOptions {
				headers := http.Header{}
				if hostHeader != "" {
					headers.Set("Host", hostHeader)
				}
				return echo.CallOptions{
					Address: "example.com",
					Port: echo.Port{
						Protocol:    protocol.HTTPS,
						ServicePort: 443,
					},
					Scheme: scheme.HTTPS,
					TLS: echo.TLS{
						ServerName:         "example.com",
						InsecureSkipVerify: true,
					},
					HTTP: echo.HTTP{
						Headers: headers,
					},
				}
			}

			// allowed asserts the request was NOT RBAC-denied. example.com
			// returns 200, but we only forbid 403 — the one symptom of the
			// RBAC filter firing — rather than insisting on a specific 2xx.
			allowed := check.And(check.NoError(), check.NotStatus(http.StatusForbidden))
			// denied asserts the RBAC filter rejected the request with 403.
			denied := check.Forbidden(protocol.HTTP)

			ctx.NewSubTest("sni matches host: allowed").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						opt := callOpts("")
						opt.Check = allowed
						_, err := src.Call(opt)
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("sni matches host with port suffix: allowed").
				Run(func(ctx framework.TestContext) {
					// request.host.split(':')[0] strips the port before
					// comparison, so Host: example.com:443 must still match.
					retry.UntilSuccessOrFail(ctx, func() error {
						opt := callOpts("example.com:443")
						opt.Check = allowed
						_, err := src.Call(opt)
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("sni matches host case insensitive: allowed").
				Run(func(ctx framework.TestContext) {
					// Both sides are lowerAscii'd before comparison.
					retry.UntilSuccessOrFail(ctx, func() error {
						opt := callOpts("EXAMPLE.COM")
						opt.Check = allowed
						_, err := src.Call(opt)
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("sni differs from host: denied with 403").
				Run(func(ctx framework.TestContext) {
					// The exact PoC: SNI=example.com (passes
					// tls_termination.include_hosts and gets a leaf cert),
					// Host=example.org (would route DFP to example.org without
					// the fix). With the fix, RBAC denies before DFP sees
					// the host → 403.
					retry.UntilSuccessOrFail(ctx, func() error {
						opt := callOpts("example.org")
						opt.Check = denied
						_, err := src.Call(opt)
						if err != nil {
							return fmt.Errorf("expected 403 for SNI=example.com Host=example.org — egress allowlist may be bypassed: %w", err)
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("sni differs from host different port: denied with 403").
				Run(func(ctx framework.TestContext) {
					// Port-stripping must not become a wildcard: Host
					// example.org:443 still differs from SNI example.com after
					// stripping the port.
					retry.UntilSuccessOrFail(ctx, func() error {
						opt := callOpts("example.org:443")
						opt.Check = denied
						_, err := src.Call(opt)
						if err != nil {
							return fmt.Errorf("expected 403 for SNI=example.com Host=example.org:443: %w", err)
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})
		})
}
