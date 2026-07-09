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

	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/test/util/retry"
)

func TestSandboxTrafficPolicy(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, nil, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
data:
  config: |
    egressPolicies:
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

			src := all[0]
			dst := all[1]
			anotherDst := all[2]

			parts := strings.Split(src.Address(), ".")
			serviceIpBlock := fmt.Sprintf("%s.%s.0.0/16", parts[0], parts[1])

			ctx.NewSubTest("egress allow with cidr").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-cidr
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

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-egress-cidr")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})
				})

			ctx.NewSubTest("egress deny with cidr").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": dst.Address(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-deny
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: {{ .Dst }}
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-egress-deny")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})
				})

			ctx.NewSubTest("ingress allow with service ref").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":             dst.Config().Service,
						"SrcApp":          src.Config().Service,
						"SrcAppNamespace": src.Config().Namespace.Name(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-ingress-svc
spec:
  priority: 200
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: allow
        from:
          - service:
              name: "{{ .SrcApp }}"
              namespace: "{{ .SrcAppNamespace }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, dst, "tp-ingress-svc")
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					anotherDst.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("ingress deny with cidr fallback").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":             dst.Config().Service,
						"SrcApp":          src.Config().Service,
						"SrcAppNamespace": src.Config().Namespace.Name(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-ingress-deny-fallback
spec:
  priority: 200
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: allow
        from:
          - service:
              name: "{{ .SrcApp }}"
              namespace: "{{ .SrcAppNamespace }}"
      - action: reject
        from:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, dst, "tp-ingress-deny-fallback")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					anotherDst.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("egress with port range").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-port-range
spec:
  priority: 50
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
          - cidr: "{{ .Dst }}"
        ports:
          - port: 80
            endPort: 81
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-port-range")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							Name:        "http",
							ServicePort: 80,
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 81,
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Protocol:    protocol.HTTPS,
							ServicePort: 9443,
						},
						Check: check.Error(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 82,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("egress with fqdn").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":          src.Config().Service,
						"Dst":          dst.Config().Service,
						"DstNamespace": dst.Config().Namespace.Name(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-fqdn
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
          - fqdn: "www.example.com"
          - fqdn: "example.com"
      - action: allow
        to:
          - service:
              namespace: {{ .DstNamespace }}
              name: {{ .Dst }}
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-egress-fqdn")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.com",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.NoError(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.com",
						Port: echo.Port{
							Protocol:    protocol.HTTPS,
							ServicePort: 443,
						},
						Check: check.NoError(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.org",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.org",
						Port: echo.Port{
							Protocol:    protocol.HTTPS,
							ServicePort: 443,
						},
						Check: check.Error(),
					})
				})
		})
}

func TestSandboxGlobalTrafficPolicy(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, nil, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
data:
  config: |
    egressPolicies:
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

			src := all[0]
			dst := all[1]
			anotherDst := all[2]

			parts := strings.Split(src.Address(), ".")
			serviceIpBlock := fmt.Sprintf("%s.%s.0.0/16", parts[0], parts[1])

			ctx.NewSubTest("global egress allow").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval("", map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: GlobalTrafficPolicy
metadata:
  name: gtp-egress
spec:
  priority: 10
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "gtp-egress")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.com",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("global ingress deny baseline").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval("", nil, `
apiVersion: agents.kruise.io/v1alpha1
kind: GlobalTrafficPolicy
metadata:
  name: gtp-egress-baseline
spec:
  priority: 1000
  selector: {}
  egress:
    rules:
      - action: reject
        to:
          - fqdn: "example.com"
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": anotherDst.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-example-org
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - fqdn: "example.org"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, dst, "gtp-egress-baseline")
					waitForAuthorizationPolicyOrFail(ctx, src, "gtp-egress-baseline")
					waitForAuthorizationPolicyOrFail(ctx, anotherDst, "gtp-egress-baseline")
					waitForAuthorizationPolicyOrFail(ctx, anotherDst, "tp-egress-example-org")

					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.com",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})

					dst.CallOrFail(ctx, echo.CallOptions{
						Address: "example.com",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})

					anotherDst.CallOrFail(ctx, echo.CallOptions{
						Address: "example.com",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.org",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.NoError(),
					})

					dst.CallOrFail(ctx, echo.CallOptions{
						Address: "example.org",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.NoError(),
					})

					anotherDst.CallOrFail(ctx, echo.CallOptions{
						Address: "example.org",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})

				})
		})
}

func TestSandboxPriorityMatching(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, nil, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
data:
  config: |
    egressPolicies:
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

			src := all[0]
			dst := all[1]
			anotherDst := all[2]

			parts := strings.Split(src.Address(), ".")
			serviceIpBlock := fmt.Sprintf("%s.%s.0.0/16", parts[0], parts[1])

			ctx.NewSubTest("high priority deny overrides low priority allow").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-high-priority-deny
spec:
  priority: 10
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(ctx)

					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-low-priority-allow
spec:
  priority: 500
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-high-priority-deny")
					waitForAuthorizationPolicyOrFail(ctx, src, "tp-low-priority-allow")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					// default deny
					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.com",
						Port: echo.Port{
							Name:        "http",
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("priority layering infra business internet").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-infra-policy
spec:
  priority: 10
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
`).ApplyOrFail(ctx)

					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":        src.Config().Service,
						"Dst":        dst.Address(),
						"AnotherDst": anotherDst.Address(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-business-policy
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
      - action: reject
        to:
          - cidr: "{{ .AnotherDst }}"
`).ApplyOrFail(ctx)

					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-internet-policy
spec:
  priority: 500
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-infra-policy")
					waitForAuthorizationPolicyOrFail(ctx, src, "tp-business-policy")
					waitForAuthorizationPolicyOrFail(ctx, src, "tp-internet-policy")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						Address: "kube-dns.kube-system",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 9153,
						},
						Check: check.NoError(),
					})

					// default deny
					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.com",
						Port: echo.Port{
							Name:        "http",
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.NoError(),
					})
				})

			ctx.NewSubTest("same priority rule order matching").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":        src.Config().Service,
						"Dst":        dst.Address(),
						"AnotherDst": anotherDst.Address(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-rule-order-test
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
      - action: reject
        to:
          - cidr: "{{ .AnotherDst }}"
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
      - action: allow
        to:
          - fqdn: "example.com"
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-rule-order-test")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.org",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})

					// default deny
					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.com",
						Port: echo.Port{
							Name:        "http",
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.NoError(),
					})
				})
		})
}

func TestSandboxTrafficPolicyMatchExpressions(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, nil, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
data:
  config: |
    egressPolicies:
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

			src := all[0]
			dst := all[1]
			anotherDst := all[2]

			ctx.NewSubTest("matchExpressions In").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-in
spec:
  priority: 100
  selector:
    matchExpressions:
      - key: app
        operator: In
        values:
          - "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-matchexpr-in")

					// client should match and be allowed
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})
				})

			ctx.NewSubTest("matchExpressions NotIn").
				Run(func(ctx framework.TestContext) {
					// Allow client to reach everything so we have a baseline
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-notin-allow
spec:
  priority: 100
  selector:
    matchExpressions:
      - key: app
        operator: In
        values:
          - "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					// Deny all egress for workloads whose app is NOT "client"
					// This matches server and another-server, but NOT client
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"SrcApp": src.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-notin-deny
spec:
  priority: 50
  selector:
    matchExpressions:
      - key: app
        operator: NotIn
        values:
          - "{{ .SrcApp }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-matchexpr-notin-allow")
					waitForAuthorizationPolicyOrFail(ctx, dst, "tp-matchexpr-notin-deny")

					// client does NOT match NotIn(client), so no deny policy applied
					// with its allow policy, client can reach anyone
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// server DOES match NotIn(client), so deny applies to it
					// server cannot reach anyone
					dst.CallOrFail(ctx, echo.CallOptions{
						To: src,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("matchExpressions Exists").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-exists
spec:
  priority: 100
  selector:
    matchExpressions:
      - key: app
        operator: Exists
  egress:
    rules:
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-matchexpr-exists")

					// all pods have "app" label, so all should be allowed
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					dst.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})
				})

			ctx.NewSubTest("matchExpressions DoesNotExist").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"SrcApp": src.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-doesnotexist
spec:
  priority: 100
  selector:
    matchExpressions:
      - key: app
        operator: DoesNotExist
  egress:
    rules:
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					// all pods in the sandbox namespace have "app" label,
					// so none should match this policy (DoesNotExist on "app")
					// they will get default deny

					// verify no authorization policy is generated for these pods
					waitForAuthorizationPolicyGoneOrFail(ctx, src, "tp-matchexpr-doesnotexist")

					// all pods should be denied since they don't match
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})
				})

			ctx.NewSubTest("matchExpressions multiple expressions").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"SrcApp":            src.Config().Service,
						"LabelSandboxProxy": agentio.LabelSandboxProxyType,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-multi
spec:
  priority: 100
  selector:
    matchExpressions:
      - key: app
        operator: In
        values:
          - "{{ .SrcApp }}"
      - key: "{{ .LabelSandboxProxy }}"
        operator: Exists
  egress:
    rules:
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-matchexpr-multi")

					// client has both labels: app=client AND LabelSandboxProxyType=ztunnel
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// server also has both labels, so also allowed
					dst.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})
				})

			ctx.NewSubTest("matchExpressions with ingress").
				Run(func(ctx framework.TestContext) {
					// Ingress policy on dst with matchExpressions In
					// Only allows traffic from src, blocks everything else
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"DstApp":          dst.Config().Service,
						"SrcApp":          src.Config().Service,
						"SrcAppNamespace": src.Config().Namespace.Name(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-ingress
spec:
  priority: 100
  selector:
    matchExpressions:
      - key: app
        operator: In
        values:
          - "{{ .DstApp }}"
  ingress:
    rules:
      - action: allow
        from:
          - service:
              name: "{{ .SrcApp }}"
              namespace: "{{ .SrcAppNamespace }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, dst, "tp-matchexpr-ingress")

					// dst matches the ingress selector, so src -> dst should be allowed
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// another-server doesn't have a matching ingress policy
					// but dst's ingress policy restricts incoming traffic to only src
					// so src -> another-server should be denied (dst's policy only allows src traffic)
					anotherDst.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})
				})
		})
}

func TestSandboxTrafficPolicyWorkloadPeer(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, nil, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
data:
  config: |
    egressPolicies:
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

			src := all[0]
			dst := all[1]
			anotherDst := all[2]

			ctx.NewSubTest("egress deny with workload peer").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":          src.Config().Service,
						"DstApp":       dst.Config().Service,
						"DstNamespace": dst.Config().Namespace.Name(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-deny-workload
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - workload:
              namespace: "{{ .DstNamespace }}"
              selector:
                app: "{{ .DstApp }}"
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-egress-deny-workload")

					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.Error(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: anotherDst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})
				})

			ctx.NewSubTest("egress allow with workload peer").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":          src.Config().Service,
						"DstApp":       dst.Config().Service,
						"DstNamespace": dst.Config().Namespace.Name(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-allow-workload
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - workload:
              namespace: "{{ .DstNamespace }}"
              selector:
                app: "{{ .DstApp }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-egress-allow-workload")

					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: anotherDst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("ingress allow with workload peer").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":          dst.Config().Service,
						"SrcApp":       src.Config().Service,
						"SrcNamespace": src.Config().Namespace.Name(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-ingress-allow-workload
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: allow
        from:
          - workload:
              namespace: "{{ .SrcNamespace }}"
              selector:
                app: "{{ .SrcApp }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, dst, "tp-ingress-allow-workload")

					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})

					anotherDst.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("egress allow workload with port restriction").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":          src.Config().Service,
						"DstApp":       dst.Config().Service,
						"DstNamespace": dst.Config().Namespace.Name(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-workload-port
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - workload:
              namespace: "{{ .DstNamespace }}"
              selector:
                app: "{{ .DstApp }}"
        ports:
          - port: 18080
            endPort: 18081
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-egress-workload-port")

					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTPS,
							WorkloadPort: 19443,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("ingress deny workload then allow all").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":           dst.Config().Service,
						"AnotherDstApp": anotherDst.Config().Service,
						"AnotherDstNs":  anotherDst.Config().Namespace.Name(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-ingress-deny-workload-allow-all
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: reject
        from:
          - workload:
              namespace: "{{ .AnotherDstNs }}"
              selector:
                app: "{{ .AnotherDstApp }}"
      - action: allow
        from:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, dst, "tp-ingress-deny-workload-allow-all")

					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})

					anotherDst.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.Error(),
					})
				})
		})
}

func TestSandboxTrafficPolicyProtocol(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, nil, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
data:
  config: |
    egressPolicies:
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

			src := all[0]
			dst := all[1]

			parts := strings.Split(src.Address(), ".")
			serviceIpBlock := fmt.Sprintf("%s.%s.0.0/16", parts[0], parts[1])

			ctx.NewSubTest("allow all TCP only").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-allow-all-tcp
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
          - cidr: "{{ .Dst }}"
        ports:
          - protocol: TCP
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-allow-all-tcp")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Protocol:    protocol.TCP,
							ServicePort: 9090,
						},
						Check: check.NoError(),
					})

					// External traffic (not in CIDR allow list) should be denied
					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.com",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("allow specific port with protocol").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-port-with-proto
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
          - cidr: "{{ .Dst }}"
        ports:
          - protocol: TCP
            port: 80
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-port-with-proto")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Protocol:    protocol.HTTPS,
							ServicePort: 9443,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("deny UDP blocks DNS").
				Run(func(ctx framework.TestContext) {
					if !enableFirewall {
						ctx.Skip("UDP traffic policy tests require ENABLE_FIREWALL=true")
					}
					// Skip this when iptables backend enabled
					if ambientMode && firewallBackend == "iptables" {
						ctx.Skip("when dns enabled in ambient mode for iptables backend, dns will always be captured by ztunnel")
					}
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-deny-udp-dns
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        ports:
          - protocol: UDP
            port: 53
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-deny-udp-dns")

					// DNS resolution fails because UDP:53 is denied
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					// Direct IP call bypasses DNS, TCP is allowed
					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})
				})

			ctx.NewSubTest("mixed protocol rules").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-mixed-proto
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
          - cidr: "{{ .Dst }}"
        ports:
          - protocol: TCP
            port: 80
          - protocol: TCP
            port: 9090
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-mixed-proto")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Protocol:    protocol.TCP,
							ServicePort: 9090,
						},
						Check: check.NoError(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Protocol:    protocol.HTTPS,
							ServicePort: 9443,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("ingress allow specific port with protocol").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": dst.Config().Service,
						"Src": src.WorkloadsOrFail(ctx)[0].Address(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-ingress-port-with-proto
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: allow
        from:
          - cidr: "{{ .Src }}"
        ports:
          - protocol: TCP
            port: 18080
      - action: reject
        from:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, dst, "tp-ingress-port-with-proto")

					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTPS,
							WorkloadPort: 19443,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("deny TCP does not block ICMP").
				Run(func(ctx framework.TestContext) {
					if !enableFirewall {
						ctx.Skip("ICMP traffic policy tests require ENABLE_FIREWALL=true")
					}
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":        src.Config().Service,
						"Namespace":  ns.Name(),
						"DstService": dst.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-deny-tcp-not-icmp
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        ports:
          - protocol: UDP
      - action: reject
        ports:
          - protocol: TCP
        to:
          - service:
              namespace: "{{ .Namespace }}"
              name: "{{ .DstService }}"
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-deny-tcp-not-icmp")

					// TCP to server should be denied
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					// ICMP (ping) to server should still work
					dstIP := dst.WorkloadsOrFail(ctx)[0].Address()
					srcWl := src.WorkloadsOrFail(ctx)[0]
					cluster := ctx.Clusters().Default()
					retry.UntilOrFail(ctx, func() bool {
						_, _, err := cluster.PodExec(srcWl.PodName(), ns.Name(), "app",
							fmt.Sprintf("ping -c 1 -W 3 %s", dstIP))
						return err == nil
					}, retry.Timeout(time.Minute*1), retry.Delay(time.Second*2))
				})

			ctx.NewSubTest("deny ICMP does not block TCP").
				Run(func(ctx framework.TestContext) {
					if !enableFirewall {
						ctx.Skip("ICMP traffic policy tests require ENABLE_FIREWALL=true")
					}
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":        src.Config().Service,
						"Namespace":  ns.Name(),
						"DstService": dst.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-deny-icmp-not-tcp
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        ports:
          - protocol: UDP
      - action: reject
        ports:
          - protocol: ICMP
        to:
          - service:
              namespace: "{{ .Namespace }}"
              name: "{{ .DstService }}"
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-deny-icmp-not-tcp")

					// TCP to server should still work
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// ICMP (ping) to server should be denied
					dstIP := dst.WorkloadsOrFail(ctx)[0].Address()
					srcWl := src.WorkloadsOrFail(ctx)[0]
					cluster := ctx.Clusters().Default()
					retry.UntilOrFail(ctx, func() bool {
						_, _, err := cluster.PodExec(srcWl.PodName(), ns.Name(), "app",
							fmt.Sprintf("ping -c 1 -W 3 %s", dstIP))
						return err != nil
					}, retry.Timeout(time.Minute*1), retry.Delay(time.Second*2))
				})
		})
}

// TestPolicyInteraction covers scenarios where multiple TrafficPolicies
// interact on the same pod: multi-policy coexistence, combined egress+ingress,
// and priority-based override by a newly added policy.
func TestPolicyInteraction(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, nil, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
data:
  config: |
    egressPolicies:
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

			src := all[0]
			dst := all[1]
			anotherDst := all[2]

			parts := strings.Split(src.Address(), ".")
			serviceIpBlock := fmt.Sprintf("%s.%s.0.0/16", parts[0], parts[1])

			// ------------------------------------------------------------------
			// SubTest 1: Multiple policies on same pod — rules are merged.
			// Policy A (label: app=client) allows egress to server's IP block.
			// Policy B (label: version=test) allows egress to another-server's IP.
			// The client pod matches BOTH labels, so both policies apply.
			// ------------------------------------------------------------------
			ctx.NewSubTest("multiple policies on same pod").
				Run(func(ctx framework.TestContext) {
					// Determine another-server's IP block.
					anotherIP := anotherDst.Instances()[0].WorkloadsOrFail(ctx)[0].Address()
					anotherParts := strings.Split(anotherIP, ".")
					anotherBlock := fmt.Sprintf("%s.%s.%s.0/24",
						anotherParts[0], anotherParts[1], anotherParts[2])

					// Policy A: allow egress to server's /16 block.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-multi-pol-a
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

					// Policy B: allow egress to another-server's /24 block.
					// Uses a different label (version=test) so the selector
					// differs, but the client pod has both labels.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":       src.Config().Service,
						"CidrBlock": anotherBlock,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-multi-pol-b
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .CidrBlock }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-multi-pol-a")
					waitForAuthorizationPolicyOrFail(ctx, src, "tp-multi-pol-b")

					// src -> dst should be reachable (covered by policy A).
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// src -> anotherDst should be reachable (covered by policy B).
					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// External traffic should be denied (not covered by either).
					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.com",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})
				})

			// ------------------------------------------------------------------
			// SubTest 2: Egress + Ingress in single policy — both directions.
			// A single TrafficPolicy targets dst with both egress (deny a CIDR)
			// and ingress (allow from src).
			// ------------------------------------------------------------------
			ctx.NewSubTest("egress and ingress in single policy").
				Run(func(ctx framework.TestContext) {
					// Deny dst's egress to external (example.com IP block),
					// and allow ingress from src's IP block.
					srcIP := src.Instances()[0].WorkloadsOrFail(ctx)[0].Address()
					srcParts := strings.Split(srcIP, ".")
					srcBlock := fmt.Sprintf("%s.%s.%s.0/24",
						srcParts[0], srcParts[1], srcParts[2])

					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"DstApp":   dst.Config().Service,
						"SrcBlock": srcBlock,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-combined-egress-ingress
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .DstApp }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: "198.51.100.0/24"
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
  ingress:
    rules:
      - action: allow
        from:
          - cidr: "{{ .SrcBlock }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, dst, "tp-combined-egress-ingress")

					// Ingress: src -> dst should be allowed (src IP in allowed CIDR).
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// Egress: dst -> src should also work (dst's egress allows
					// 0.0.0.0/0 except 198.51.100.0/24 which is unrelated).
					dst.CallOrFail(ctx, echo.CallOptions{
						To: src,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})
				})

			// ------------------------------------------------------------------
			// SubTest 3: New high-priority policy overrides existing allow.
			// Phase 1: allow policy (priority 100) — dst reachable.
			// Phase 2: add deny policy (priority 10, higher) — dst blocked.
			// Phase 3: delete deny policy — dst reachable again.
			// ------------------------------------------------------------------
			ctx.NewSubTest("new high-priority policy overrides existing").
				Run(func(ctx framework.TestContext) {
					// Phase 1: allow egress to dst's IP block.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": serviceIpBlock,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-override-allow
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

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-override-allow")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// Phase 2: add high-priority deny for dst's exact IP.
					dstIP := dst.Address()
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": dstIP,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-override-deny
spec:
  priority: 10
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: {{ .Dst }}
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-override-deny")

					// dst should now be blocked (high-priority deny wins).
					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})

					// But anotherDst (different IP) should still be reachable.
					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// Phase 3: delete the high-priority deny — dst should
					// become reachable again via the allow policy.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App": src.Config().Service,
						"Dst": dstIP,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-override-deny
spec:
  priority: 10
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: {{ .Dst }}
`).DeleteOrFail(ctx)

					// Wait until the deny policy is gone from config_dump.
					waitForAuthorizationPolicyGoneOrFail(ctx, src, "tp-override-deny")

					// dst should be reachable again.
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

func TestSandboxTrafficPolicyComplexRules(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, nil, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
data:
  config: |
    egressPolicies:
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

			src := all[0]
			dst := all[1]
			anotherDst := all[2]

			ctx.NewSubTest("egress multi service multi port cartesian").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":        src.Config().Service,
						"Namespace":  ns.Name(),
						"DstService": dst.Config().Service,
						"AltService": anotherDst.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-multi-svc-port
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
              namespace: "{{ .Namespace }}"
              name: "{{ .DstService }}"
          - service:
              namespace: "{{ .Namespace }}"
              name: "{{ .AltService }}"
        ports:
          - protocol: TCP
            port: 80
          - protocol: TCP
            port: 9090
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-egress-multi-svc-port")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Protocol:    protocol.TCP,
							ServicePort: 9090,
						},
						Check: check.NoError(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Protocol:    protocol.HTTPS,
							ServicePort: 9443,
						},
						Check: check.Error(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						Address: "example.com",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("ingress multi source port range cartesian").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":        dst.Config().Service,
						"Namespace":  ns.Name(),
						"SrcService": src.Config().Service,
						"AltService": anotherDst.Config().Service,
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-ingress-multi-src-port-range
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: allow
        from:
          - service:
              namespace: "{{ .Namespace }}"
              name: "{{ .SrcService }}"
          - service:
              namespace: "{{ .Namespace }}"
              name: "{{ .AltService }}"
        ports:
          - protocol: TCP
            port: 18080
            endPort: 18081
      - action: reject
        from:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, dst, "tp-ingress-multi-src-port-range")

					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})

					anotherDst.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})

					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTPS,
							WorkloadPort: 19443,
						},
						Check: check.Error(),
					})
				})
		})
}

func TestSandboxTrafficPolicyManualEndpoints(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, nil, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
data:
  config: |
    egressPolicies:
    - policy: PASSTHROUGH
`).ApplyOrFail(ctx)

			src := all[0]
			dst := all[1]

			ctx.NewSubTest("egress allow with selectorless service and manual endpointslice").
				Run(func(ctx framework.TestContext) {
					dstIP := dst.WorkloadsOrFail(ctx)[0].Address()

					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"DstIP": dstIP,
					}, `
apiVersion: v1
kind: Service
metadata:
  name: manual-svc
spec:
  clusterIP: None
  ports:
    - name: http
      port: 80
      targetPort: 18080
      protocol: TCP
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: manual-svc-slice
  labels:
    kubernetes.io/service-name: manual-svc
addressType: IPv4
ports:
  - name: http
    port: 18080
    protocol: TCP
endpoints:
  - addresses:
      - "{{ .DstIP }}"
`).ApplyOrFail(ctx)

					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":       src.Config().Service,
						"Namespace": ns.Name(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-manual-ep
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
              namespace: "{{ .Namespace }}"
              name: manual-svc
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-manual-ep")

					// dst's pod IP is in the manual EndpointSlice, so traffic should be allowed
					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})

					// anotherDst is not in the manual EndpointSlice, should be denied
					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: all[2].Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("ingress allow with selectorless service and manual endpointslice").
				Run(func(ctx framework.TestContext) {
					srcWorkload := src.WorkloadsOrFail(ctx)[0]
					srcIP := srcWorkload.Address()

					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"SrcIP": srcIP,
					}, `
apiVersion: v1
kind: Service
metadata:
  name: manual-src-svc
spec:
  clusterIP: None
  ports:
    - name: http
      port: 80
      targetPort: 18080
      protocol: TCP
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: manual-src-svc-slice
  labels:
    kubernetes.io/service-name: manual-src-svc
addressType: IPv4
ports:
  - name: http
    port: 18080
    protocol: TCP
endpoints:
  - addresses:
      - "{{ .SrcIP }}"
`).ApplyOrFail(ctx)

					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":       dst.Config().Service,
						"Namespace": ns.Name(),
					}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-manual-ep-ingress
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: allow
        from:
          - service:
              namespace: "{{ .Namespace }}"
              name: manual-src-svc
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, dst, "tp-manual-ep-ingress")

					src.CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					all[2].CallOrFail(ctx, echo.CallOptions{
						To: dst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.Error(),
					})
				})
		})
}

func waitForAuthorizationPolicyOrFail(ctx framework.TestContext, instance echo.Instance, policy string) {
	if ambientMode {
		return
	}
	retry.UntilOrFail(ctx, func() bool {
		res := instance.CallOrFail(ctx, echo.CallOptions{
			Address: "localhost",
			Port: echo.Port{
				ServicePort: 15000,
				Protocol:    protocol.HTTP,
			},
			HTTP: echo.HTTP{
				Path: "/config_dump",
			},
		})
		return strings.Contains(res.Responses.String(), policy)
	}, retry.Timeout(time.Minute*2), retry.Delay(time.Millisecond*200))
}

func waitForAuthorizationPolicyGoneOrFail(ctx framework.TestContext, instance echo.Instance, policy string) {
	if ambientMode {
		return
	}
	retry.UntilOrFail(ctx, func() bool {
		res := instance.CallOrFail(ctx, echo.CallOptions{
			Address: "localhost",
			Port: echo.Port{
				ServicePort: 15000,
				Protocol:    protocol.HTTP,
			},
			HTTP: echo.HTTP{
				Path: "/config_dump",
			},
		})
		return !strings.Contains(res.Responses.String(), policy)
	}, retry.Timeout(time.Minute*2), retry.Delay(time.Millisecond*200))
}
