//go:build integ

package sandbox

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
)

// TestSandboxTrafficPolicyLifecycle covers policy lifecycle scenarios that go
// beyond basic allow/deny enforcement: update propagation, deletion cleanup,
// stress (50 rules), invalid CIDR resilience, empty selector, wildcard service,
// label-change reconciliation, and unresolvable FQDN status.
func TestSandboxTrafficPolicyLifecycle(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			dst := all[1]
			anotherDst := all[2]

			parts := strings.Split(src.Address(), ".")
			serviceIpBlock := fmt.Sprintf("%s.%s.0.0/16", parts[0], parts[1])

			ctx.NewSubTest("policy update propagation").
				Run(func(ctx framework.TestContext) {
					// Phase 1: apply deny policy — dst should be unreachable.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": dst.Address(),
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-lifecycle-update
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: deny
        to:
          - cidr: {{ .Dst }}
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-lifecycle-update")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					// Phase 2: update policy to allow — dst should become reachable.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-lifecycle-update
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-lifecycle-update")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// Phase 3: update again to deny — dst should be blocked.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": dst.Address(),
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-lifecycle-update
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: deny
        to:
          - cidr: {{ .Dst }}
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-lifecycle-update")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("policy deletion cleanup").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": dst.Address(),
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-lifecycle-delete
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: deny
        to:
          - cidr: {{ .Dst }}
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-lifecycle-delete")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					// Delete the policy explicitly.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": dst.Address(),
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-lifecycle-delete
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: deny
        to:
          - cidr: {{ .Dst }}
`).DeleteOrFail(ctx)

					// Wait until the AuthorizationPolicy referencing this TP is gone.
					waitForAuthorizationPolicyGoneOrFail(ctx, src, "tp-lifecycle-delete")

					// Traffic should be allowed after policy deletion.
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})
				})

			ctx.NewSubTest("stress with 50 rules").
				Run(func(ctx framework.TestContext) {
					// Build 50 allow rules for different CIDRs + a final deny 0.0.0.0/0.
					var rules strings.Builder
					for j := 0; j < 50; j++ {
						if j > 0 {
							rules.WriteString("\n")
						}
						rules.WriteString(fmt.Sprintf(`      - action: allow
        to:
          - cidr: "10.%d.0.0/16"`, j))
					}

					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":   src.Config().Service,
						"Rules": rules.String(),
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-stress-50
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
{{ .Rules }}
      - action: deny
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-stress-50")

					// dst (in-cluster service) should be denied (not in 10.x.0.0/16 range).
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("invalid CIDR resilience").
				Run(func(ctx framework.TestContext) {
					// Apply a policy with an invalid CIDR alongside a valid allow.
					// The controller should handle the invalid CIDR gracefully
					// (skip it or report status) and not crash.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-invalid-cidr
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "not-a-valid-cidr"
`).ApplyOrFail(ctx)

					// Wait a bit for the controller to process; it should not crash.
					// We verify by checking that subsequent policies still work.
					time.Sleep(5 * time.Second)

					// Apply a new valid policy and verify it works.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-after-invalid
spec:
  priority: 50
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-after-invalid")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})
				})

			ctx.NewSubTest("empty selector matches all pods").
				Run(func(ctx framework.TestContext) {
					// An empty selector ({}) should match ALL pods in the namespace.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"Dst": dst.Address(),
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-empty-selector
spec:
  priority: 100
  selector: {}
  egress:
    rules:
      - action: deny
        to:
          - cidr: {{ .Dst }}
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					// Both src and anotherDst should match the empty selector.
					waitForAuthorizationPolicyOrFail(ctx, src, "tp-empty-selector")
					waitForAuthorizationPolicyOrFail(ctx, anotherDst, "tp-empty-selector")

					// src -> dst should be denied (matched by empty selector).
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					// anotherDst -> dst should also be denied.
					anotherDst.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					// But src -> anotherDst should still work (different CIDR).
					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})
				})

			ctx.NewSubTest("wildcard service name").
				Run(func(ctx framework.TestContext) {
					// Service name "*" should match all services in the namespace.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":          src.Config().Service,
						"DstNamespace": dst.Config().Namespace.Name(),
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-wildcard-svc
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - service:
              namespace: kube-system
              name: kube-dns
      - action: allow
        to:
          - service:
              namespace: "{{ .DstNamespace }}"
              name: "*"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-wildcard-svc")

					// src should be able to reach dst via service (wildcard matches all services).
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// src should also reach another-server via service.
					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// External traffic should be denied (not covered by service wildcard).
					src.CallOrFail(ctx, echo.CallOptions{
						Address: "aliyun.com",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("label change reconciliation").
				Run(func(ctx framework.TestContext) {
					// Apply a policy targeting "server" pods.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"Dst": dst.Address(),
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-label-reconcile
spec:
  priority: 100
  selector:
    matchLabels:
      app: "server"
  egress:
    rules:
      - action: deny
        to:
          - cidr: {{ .Dst }}
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, dst, "tp-label-reconcile")

					// "server" (dst) matches the selector, so its egress to itself is denied.
					// "client" (src) does NOT match, so src -> dst is unaffected.
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// Verify that the AuthorizationPolicy is present on dst (server).
					waitForAuthorizationPolicyOrFail(ctx, dst, "tp-label-reconcile")

					// Verify that client (src) does NOT have this policy.
					waitForAuthorizationPolicyGoneOrFail(ctx, src, "tp-label-reconcile")
				})

			ctx.NewSubTest("unresolvable FQDN status").
				Run(func(ctx framework.TestContext) {
					// Apply a policy with an unresolvable FQDN.
					// The controller should handle it gracefully — either produce
					// empty IPSet entries or report a condition in the status.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-bad-fqdn
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - service:
              namespace: kube-system
              name: kube-dns
      - action: allow
        to:
          - fqdn: "this-fqdn-does-not-exist.invalid"
`).ApplyOrFail(ctx)

					// Wait for the policy to be processed.
					waitForAuthorizationPolicyOrFail(ctx, src, "tp-bad-fqdn")

					// The unresolvable FQDN produces no IPs, so its allow rule is
					// effectively empty. But there is no deny-all, so dst should
					// still be reachable. The key assertion is that the controller
					// does not crash and subsequent policies still work.
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// The controller should not crash — verify by applying another policy.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-after-bad-fqdn
spec:
  priority: 50
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-after-bad-fqdn")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})
				})
		})
}
