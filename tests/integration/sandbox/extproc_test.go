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

	"istio.io/istio/pkg/config/protocol"
	echoClient "istio.io/istio/pkg/test/echo"
	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/test/util/retry"
)

func TestSandboxExtProc(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			dst := all[1]

			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]any{
				"Namespace": i.Settings().SystemNamespace,
			}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
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

			retry.UntilSuccessOrFail(ctx, func() error {
				_, err := src.Call(echo.CallOptions{
					To: dst,
					Port: echo.Port{
						Name: "http",
					},
					Check: check.And(
						check.OK(),
						check.RequestHeader("X-Hello-To-Ext-Proc", "true"),
						check.ResponseHeader("X-Hello-From-Ext-Proc", "true"),
					),
				})
				return err
			}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
		})
}

func TestSandboxTraffic(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			dst := all[1]

			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]string{
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
`).ApplyOrFail(ctx)
			ctx.NewSubTest("http traffic").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To: dst,
							Port: echo.Port{
								Name: "http",
							},
							Check: check.OK(),
						})
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("tcp traffic").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To: dst,
							Port: echo.Port{
								Name:        "tcp",
								Protocol:    protocol.TCP,
								ServicePort: 9091,
							},
							Check: check.OK(),
						})
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("https traffic").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To: dst,
							Port: echo.Port{
								Protocol:    protocol.HTTPS,
								ServicePort: 443,
							},
							Scheme: scheme.HTTPS,
							TLS: echo.TLS{
								InsecureSkipVerify: true,
							},
							Check: check.OK(),
						})
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("grpc traffic").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To: dst,
							Port: echo.Port{
								Name:     "grpc",
								Protocol: protocol.GRPC,
							},
							Check: check.OK(),
						})
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			// h2c sits on a separate branch in waypoint's HTTPInspector path
			// from HTTP/1.1; without an explicit case the protocol matcher
			// could misroute upgraded connections into forward-tcp.
			ctx.NewSubTest("http2 (h2c) traffic").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To: dst,
							Port: echo.Port{
								Name: "http2",
							},
							HTTP: echo.HTTP{
								HTTP2: true,
							},
							Check: check.OK(),
						})
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})
		})
}

// TestSandboxMatchPorts verifies that EgressPolicy.match_ports gates which
// destination ports are routed through the egress gateway. Traffic to a
// matched port should hit the envoy egress gateway (response carries
// x-envoy-* headers like x-envoy-upstream-service-time added by envoy on
// the way back); traffic to an unmatched port should bypass the gateway
// and arrive without those headers.
func TestSandboxMatchPorts(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			dst := all[1]

			// Echo's "http" port → ServicePort 80 (matched).
			// Echo's "http2" port → ServicePort 85 (not matched, must bypass).
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
    - matchPorts:
      - "80"
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
`).ApplyOrFail(ctx)

			ctx.NewSubTest("matched port goes through envoy gateway").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To: dst,
							Port: echo.Port{
								Name: "http",
							},
							Check: check.And(
								check.OK(),
								hasEnvoyResponseHeader(),
							),
						})
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("unmatched port bypasses envoy gateway").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To: dst,
							Port: echo.Port{
								Name: "http2",
							},
							Check: check.And(
								check.OK(),
								noEnvoyResponseHeader(),
							),
						})
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})
		})
}

// hasEnvoyResponseHeader asserts at least one x-envoy-* header is present
// in the response the client received — envoy injects headers like
// x-envoy-upstream-service-time when it proxies the call back.
func hasEnvoyResponseHeader() echo.Checker {
	return check.Each(func(r echoClient.Response) error {
		for k := range r.ResponseHeaders {
			if strings.HasPrefix(strings.ToLower(k), "x-envoy-") {
				return nil
			}
		}
		return fmt.Errorf("expected an x-envoy-* response header (proxied via envoy gateway), got: %v", r.ResponseHeaders)
	})
}

// noEnvoyResponseHeader asserts no x-envoy-* header is present in the
// response — i.e. the connection bypassed any envoy proxy on the egress path.
func noEnvoyResponseHeader() echo.Checker {
	return check.Each(func(r echoClient.Response) error {
		for k := range r.ResponseHeaders {
			if strings.HasPrefix(strings.ToLower(k), "x-envoy-") {
				return fmt.Errorf("did not expect x-envoy-* response header (should bypass envoy gateway), got %s=%v", k, r.ResponseHeaders.Values(k))
			}
		}
		return nil
	})
}

// TestSandboxExternalHTTP exercises the forward-http catchall + DFP path for
// an external host that has no matcher rule (not a mesh service, not in any
// SNI list). Without DFP wired correctly into the HCM filter chain this would
// fail with NoHealthyUpstream or DNS resolution error rather than 200.
//
// The existing TestSandboxOnDemandCert covers the TLS-terminate / forward-tcp
// path; TestSandboxTraffic only hits in-mesh destinations and so never crosses
// the primary matcher's OnNoMatch branch. This test fills the HTTP catchall gap.
func TestSandboxExternalHTTP(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]

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
`).ApplyOrFail(ctx)

			// www.example.com is IANA-reserved and serves a stable response
			// over plain HTTP. FollowRedirects accepts the eventual 301→https
			// so the assertion is robust to upstream config changes.
			retry.UntilSuccessOrFail(ctx, func() error {
				_, err := src.Call(echo.CallOptions{
					Address: "www.example.com",
					Port: echo.Port{
						Protocol:    protocol.HTTP,
						ServicePort: 80,
					},
					Scheme: scheme.HTTP,
					HTTP: echo.HTTP{
						FollowRedirects: true,
					},
					Check: check.OK(),
				})
				return err
			}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
		})
}

func TestSandboxOnDemandCert(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			workload := src.WorkloadsOrFail(ctx)[0]
			podName := workload.PodName()
			podNS := src.NamespaceName()
			cluster := ctx.Clusters().Default()

			// echo's forwarder auto-enables InsecureSkipVerify whenever CaCert
			// is empty (pkg/test/echo/server/forwarder/config.go:292), so
			// `Check: check.Error()` against aliyun.com would silently get a
			// 301 instead of a TLS failure. curl in the client pod uses the
			// system trust store, which is what we actually want to assert.
			curl := func() (string, string, error) {
				return cluster.PodExec(podName, podNS, "app",
					"curl -sS -o /dev/null -w %{http_code} --max-time 10 https://aliyun.com")
			}
			curlInsecure := func() (string, string, error) {
				return cluster.PodExec(podName, podNS, "app",
					"curl -sS -k -o /dev/null -w %{http_code} --max-time 10 https://aliyun.com")
			}

			ctx.NewSubTest("https to aliyun.com without tls termination").
				Run(func(ctx framework.TestContext) {
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
`).ApplyOrFail(ctx)

					// Raw TCP forward; client validates the real aliyun.com cert
					// against the system trust store and curl exits 0.
					retry.UntilSuccessOrFail(ctx, func() error {
						stdout, stderr, err := curl()
						if err != nil {
							return fmt.Errorf("curl failed without termination: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("https to aliyun.com with tls termination requires insecure").
				Run(func(ctx framework.TestContext) {
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

					// SNI matches includeHosts → waypoint terminates with a leaf
					// signed by the sandbox CA (self-signed by default). curl
					// without -k must fail; the SSL cert error message ("unable
					// to get local issuer certificate" / exit 60) confirms it's
					// a trust failure, not connectivity.
					retry.UntilSuccessOrFail(ctx, func() error {
						stdout, stderr, err := curl()
						if err == nil {
							return fmt.Errorf("expected curl to fail with cert error, got success: stdout=%s", stdout)
						}
						if !strings.Contains(stderr, "SSL certificate") && !strings.Contains(stderr, "self-signed") && !strings.Contains(stderr, "unable to get local issuer") {
							return fmt.Errorf("expected SSL cert error, got: %v\nstderr=%s", err, stderr)
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))

					// With -k the same termination path succeeds, proving the
					// failure above was trust-only (not a misrouted request).
					retry.UntilSuccessOrFail(ctx, func() error {
						stdout, stderr, err := curlInsecure()
						if err != nil {
							return fmt.Errorf("curl -k failed under termination: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})
		})
}

// TestSandboxTLSExcludeHosts verifies the first arm of buildSandboxSNIMatcher:
// hosts in tlsTermination.excludeHosts must take the forward-tcp chain (raw
// TLS passthrough to the real upstream), NOT the tls-terminate chain. The
// observable signature is the upstream's real certificate validating against
// the system trust store (no -k needed). Without the exclude branch, the SNI
// would fall through to the include branch (or default termination) and the
// client would see the sandbox-CA leaf instead.
//
// A second subtest sanity-checks that includeHosts still terminates when both
// lists coexist — protects against a regression that drops the include arm.
func TestSandboxTLSExcludeHosts(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			workload := src.WorkloadsOrFail(ctx)[0]
			podName := workload.PodName()
			podNS := src.NamespaceName()
			cluster := ctx.Clusters().Default()

			curl := func(host string) (string, string, error) {
				return cluster.PodExec(podName, podNS, "app",
					fmt.Sprintf("curl -sS -o /dev/null -w %%{http_code} --max-time 15 https://%s", host))
			}

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
        excludeHosts:
        - "www.baidu.com"
`).ApplyOrFail(ctx)

			ctx.NewSubTest("excluded host bypasses termination").
				Run(func(ctx framework.TestContext) {
					// Real Baidu cert chains through the system trust store →
					// exit 0 without -k. Any SSL error here means the exclude
					// branch did not route to forward-tcp.
					retry.UntilSuccessOrFail(ctx, func() error {
						stdout, stderr, err := curl("www.baidu.com")
						if err != nil {
							return fmt.Errorf("excluded host should have used real cert, got: %v\nstderr=%s", err, stderr)
						}
						if stdout == "" {
							return fmt.Errorf("empty status from baidu, stderr=%s", stderr)
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("included host still terminates with sandbox CA").
				Run(func(ctx framework.TestContext) {
					// Sanity guard: with both lists present the include arm
					// must still route to tls-terminate. Symptom is the
					// untrusted sandbox-CA leaf — same assertion shape as
					// TestSandboxOnDemandCert.
					retry.UntilSuccessOrFail(ctx, func() error {
						stdout, stderr, err := curl("aliyun.com")
						if err == nil {
							return fmt.Errorf("expected SSL trust failure for included host, got success: stdout=%s", stdout)
						}
						if !strings.Contains(stderr, "SSL certificate") && !strings.Contains(stderr, "self-signed") && !strings.Contains(stderr, "unable to get local issuer") {
							return fmt.Errorf("expected SSL cert error, got: %v\nstderr=%s", err, stderr)
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})
		})
}
