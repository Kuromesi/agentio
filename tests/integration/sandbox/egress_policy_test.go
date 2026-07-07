//go:build integ

package sandbox

import (
	"testing"
	"time"

	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/test/util/retry"
)

func TestEgressPolicy(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			dst := all[1]

			dstAddr := dst.Address()
			dstFQDN := dst.Config().ClusterLocalFQDN()

			ctx.NewSubTest("deny all").
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
    - policy: DENY
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To: dst,
							Port: echo.Port{
								Name: "http",
							},
							Check: check.Error(),
						})
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("passthrough all").
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
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

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

			ctx.NewSubTest("match_cidrs deny").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]any{
						"Namespace": i.Settings().SystemNamespace,
						"DstCIDR":   dstAddr + "/32",
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
data:
  config: |
    egressPolicies:
    - matchCidrs:
      - "{{ .DstCIDR }}"
      policy: DENY
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To: dst,
							Port: echo.Port{
								Name: "http",
							},
							Check: check.Error(),
						})
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("match_ports deny").
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
    - matchPorts:
      - "80"
      policy: DENY
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

					ctx.NewSubTest("matched port is denied").
						Run(func(ctx framework.TestContext) {
							retry.UntilSuccessOrFail(ctx, func() error {
								_, err := src.Call(echo.CallOptions{
									To: dst,
									Port: echo.Port{
										Name: "http",
									},
									Check: check.Error(),
								})
								return err
							}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
						})

					ctx.NewSubTest("unmatched port passes through").
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
				})

			ctx.NewSubTest("match_hosts deny by hostname").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]any{
						"Namespace": i.Settings().SystemNamespace,
						"DstHost":   dstFQDN,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
data:
  config: |
    egressPolicies:
    - matchHosts:
      - "{{ .DstHost }}"
      policy: DENY
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To: dst,
							Port: echo.Port{
								Name: "http",
							},
							Check: check.Error(),
						})
						return err
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("match_hosts passthrough for unmatched host").
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
    - matchHosts:
      - "nonexistent.example.com"
      policy: DENY
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

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

			ctx.NewSubTest("match_hosts gateway by hostname").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]any{
						"Namespace": i.Settings().SystemNamespace,
						"DstHost":   dstFQDN,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
data:
  config: |
    egressPolicies:
    - matchHosts:
      - "{{ .DstHost }}"
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

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

			ctx.NewSubTest("match_hosts with external domain").
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
    - matchHosts:
      - "www.example.com"
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							Address: "www.example.com",
							Port: echo.Port{
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

			ctx.NewSubTest("match_hosts combined with match_ports").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]any{
						"Namespace": i.Settings().SystemNamespace,
						"DstHost":   dstFQDN,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
data:
  config: |
    egressPolicies:
    - matchHosts:
      - "{{ .DstHost }}"
      matchPorts:
      - "80"
      policy: DENY
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

					ctx.NewSubTest("matched host+port is denied").
						Run(func(ctx framework.TestContext) {
							retry.UntilSuccessOrFail(ctx, func() error {
								_, err := src.Call(echo.CallOptions{
									To: dst,
									Port: echo.Port{
										Name: "http",
									},
									Check: check.Error(),
								})
								return err
							}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
						})

					ctx.NewSubTest("matched host but unmatched port passes through").
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
				})

			ctx.NewSubTest("unresolvable match_hosts does not wildcard deny").
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
    - matchHosts:
      - "this-domain-does-not-exist.invalid"
      policy: DENY
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

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

			ctx.NewSubTest("policy ordering first match wins").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]any{
						"Namespace": i.Settings().SystemNamespace,
						"DstCIDR":   dstAddr + "/32",
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
data:
  config: |
    egressPolicies:
    - matchCidrs:
      - "{{ .DstCIDR }}"
      policy: PASSTHROUGH
    - policy: DENY
`).ApplyOrFail(ctx)

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

			ctx.NewSubTest("namespace scoped policy").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]any{
						"Namespace":   i.Settings().SystemNamespace,
						"SrcNamespace": src.NamespaceName(),
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
data:
  config: |
    egressPolicies:
    - namespaces:
      - "{{ .SrcNamespace }}"
      policy: DENY
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

					ctx.NewSubTest("traffic from matching namespace is denied").
						Run(func(ctx framework.TestContext) {
							retry.UntilSuccessOrFail(ctx, func() error {
								_, err := src.Call(echo.CallOptions{
									To: dst,
									Port: echo.Port{
										Name: "http",
									},
									Check: check.Error(),
								})
								return err
							}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
						})
				})
		})
}
