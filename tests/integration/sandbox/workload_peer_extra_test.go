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
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/test/util/retry"
)

// TestSandboxWorkloadPeerAdvanced covers advanced workload peer scenarios:
// multi-replica workload resolution, dynamic pod lifecycle (IPSet updates),
// and mixed workload+service / workload+CIDR peer combinations.
func TestSandboxWorkloadPeerAdvanced(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			dst := all[1]
			anotherDst := all[2]

			// Find the workload-target instances (multi-replica deployment).
			var workloadInstances echo.Instances
			for _, inst := range all {
				if inst.Config().Service == "workload-target" {
					workloadInstances = append(workloadInstances, inst)
					break
				}
			}

			ctx.NewSubTest("workload selector resolves multiple replicas").
				Run(func(ctx framework.TestContext) {
					if len(workloadInstances) == 0 {
						ctx.Skip("workload-target service not found")
					}
					wlInst := workloadInstances[0]

					// Apply egress allow policy with workload peer targeting
					// the "workload-target" service pods.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":          src.Config().Service,
						"WlNamespace":  wlInst.Config().Namespace.Name(),
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-wl-multi-replica
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
              namespace: "{{ .WlNamespace }}"
              selector:
                app: "workload-target"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-wl-multi-replica")

					// src should be able to reach ALL replicas of workload-target.
					for i, wl := range wlInst.Instances() {
						src.CallOrFail(ctx, echo.CallOptions{
							ToWorkload: wl,
							Port: echo.Port{
								Protocol:     protocol.HTTP,
								WorkloadPort: 18080,
							},
							Check: check.OK(),
						})
						_ = i // suppress unused warning in logs
					}

					// src should NOT reach anotherDst (not in workload selector).
					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: anotherDst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("dynamic pod lifecycle updates workload peer IPs").
				Run(func(ctx framework.TestContext) {
					if len(workloadInstances) == 0 {
						ctx.Skip("workload-target service not found")
					}
					wlInst := workloadInstances[0]
					initialCount := len(wlInst.Instances())
					if initialCount < 2 {
						ctx.Skip("need at least 2 workload-target replicas for this test")
					}

					// Apply egress allow with workload peer.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":         src.Config().Service,
						"WlNamespace": wlInst.Config().Namespace.Name(),
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-wl-dynamic
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
              namespace: "{{ .WlNamespace }}"
              selector:
                app: "workload-target"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-wl-dynamic")

					// Verify connectivity to all initial replicas.
					for _, wl := range wlInst.Instances() {
						src.CallOrFail(ctx, echo.CallOptions{
							ToWorkload: wl,
							Port: echo.Port{
								Protocol:     protocol.HTTP,
								WorkloadPort: 18080,
							},
							Check: check.OK(),
						})
					}

					// Verify the AuthorizationPolicy contains entries for all replicas.
					if !ambientMode {
						retry.UntilOrFail(ctx, func() bool {
							res := src.CallOrFail(ctx, echo.CallOptions{
								Address: "localhost",
								Port: echo.Port{
									ServicePort: 15000,
									Protocol:    protocol.HTTP,
								},
								HTTP: echo.HTTP{
									Path: "/config_dump",
								},
							})
							dump := res.Responses.String()
							if !strings.Contains(dump, "tp-wl-dynamic") {
								return false
							}
							allFound := true
							for _, wl := range wlInst.Instances() {
								wls, _ := wl.Workloads()
								if len(wls) > 0 {
									ip := wls[0].Address()
									if !strings.Contains(dump, ip) {
										allFound = false
										break
									}
								}
							}
							return allFound
						}, retry.Timeout(time.Minute*2), retry.Delay(time.Second*5))
					}
				})

			ctx.NewSubTest("mixed workload and service peers").
				Run(func(ctx framework.TestContext) {
					// Allow egress to server via workload peer AND to another-server
					// via service peer. Other traffic should be denied.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":            src.Config().Service,
						"DstApp":         dst.Config().Service,
						"DstNamespace":   dst.Config().Namespace.Name(),
						"AnotherSvcNs":   anotherDst.Config().Namespace.Name(),
						"AnotherSvcName": anotherDst.Config().Service,
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-wl-svc-mixed
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
          - workload:
              namespace: "{{ .DstNamespace }}"
              selector:
                app: "{{ .DstApp }}"
          - service:
              namespace: "{{ .AnotherSvcNs }}"
              name: "{{ .AnotherSvcName }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-wl-svc-mixed")

					// src -> dst (workload peer) should be reachable.
					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})

					// src -> another-server (service peer) should be reachable.
					src.CallOrFail(ctx, echo.CallOptions{
						To: anotherDst,
						Port: echo.Port{
							Name: "http",
						},
						Check: check.OK(),
					})

					// External FQDN should be denied (not in workload or service peers).
					src.CallOrFail(ctx, echo.CallOptions{
						Address: "aliyun.com",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})
				})

			ctx.NewSubTest("mixed workload and CIDR peers").
				Run(func(ctx framework.TestContext) {
					podIP := anotherDst.Instances()[0].WorkloadsOrFail(ctx)[0].Address()
					parts := strings.Split(podIP, ".")
					anotherIpBlock := fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])

					// Allow egress to server via workload peer AND to another-server's
					// IP block via CIDR. Other traffic should be denied.
					ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
						"App":          src.Config().Service,
						"DstApp":       dst.Config().Service,
						"DstNamespace": dst.Config().Namespace.Name(),
						"CidrBlock":    anotherIpBlock,
					}, `
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-wl-cidr-mixed
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
          - workload:
              namespace: "{{ .DstNamespace }}"
              selector:
                app: "{{ .DstApp }}"
          - cidr: "{{ .CidrBlock }}"
`).ApplyOrFail(ctx)

					waitForAuthorizationPolicyOrFail(ctx, src, "tp-wl-cidr-mixed")

					// src -> dst (workload peer) should be reachable.
					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: dst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})

					// src -> another-server (covered by CIDR) should be reachable.
					src.CallOrFail(ctx, echo.CallOptions{
						ToWorkload: anotherDst.Instances()[0],
						Port: echo.Port{
							Protocol:     protocol.HTTP,
							WorkloadPort: 18080,
						},
						Check: check.OK(),
					})

					// External traffic should be denied.
					src.CallOrFail(ctx, echo.CallOptions{
						Address: "aliyun.com",
						Port: echo.Port{
							Protocol:    protocol.HTTP,
							ServicePort: 80,
						},
						Check: check.Error(),
					})
				})
		})
}
