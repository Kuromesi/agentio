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

package epe

import (
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	"istio.io/istio/pkg/test/util/retry"
)

const (
	statusGlobalBlock       = 455
	statusPriorityGlobal    = 456
	statusPriorityNamespace = 457
)

// TestGlobalSecurityProfileEnforcedAndRevoked is the only end-to-end coverage
// GlobalSecurityProfile has anywhere. In this repository it appears in
// profilestore's unit tests against a fake clientset; the cloud e2e suite tests
// namespaced SecurityProfiles exclusively. That matters because the cluster-scoped
// resource travels a different path from the namespaced one at every layer: its
// own CRD, its own informer registration
// (extensions/epe/pkg/policy/profilestore/collection.go:78-83), its own RBAC rule,
// and a separate branch in store.Matches that ignores the pod's namespace
// (profilestore/store.go:170-189).
//
// The revoke half also covers krt watch propagation against a real apiserver:
// deleting the CR must reach the running process and restore traffic.
func TestGlobalSecurityProfileEnforcedAndRevoked(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			dst := all[1]

			// GlobalSecurityProfile is cluster-scoped, so the namespace passed
			// here only picks the kubectl context; the object carries none.
			plan := ctx.ConfigIstio().Eval(ns.Name(), map[string]any{}, `
apiVersion: agents.kruise.io/v1alpha1
kind: GlobalSecurityProfile
metadata:
  name: epe-global
spec:
  selector: {}
  rules:
  - name: block-global-path
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /epe-global
    actions:
      block:
        statusCode: 455
        body: epe-global-block
`)

			ctx.Cleanup(func() {
				if ctx.Failed() {
					ctx.Logf("EPE container log follows:\n%s", epeLogs(ctx))
				}
			})

			plan.ApplyOrFail(ctx)

			ctx.NewSubTest("global profile blocks").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To:   dst,
							Port: echo.Port{Name: "http"},
							HTTP: echo.HTTP{Path: "/epe-global"},
							Check: check.And(
								check.Status(statusGlobalBlock),
								check.BodyContains("epe-global-block"),
							),
						})
						return err
					}, retry.Timeout(3*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("deleting the global profile restores traffic").
				Run(func(ctx framework.TestContext) {
					// ApplyOrFail already registered a cleanup delete for this
					// plan; deleting here as well leaves that one to find the
					// object gone, which applyYAML's cleanup only logs.
					plan.DeleteOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To:    dst,
							Port:  echo.Port{Name: "http"},
							HTTP:  echo.HTTP{Path: "/epe-global"},
							Check: check.OK(),
						})
						return err
					}, retry.Timeout(3*time.Minute), retry.Delay(5*time.Second))
				})
		})
}

// TestProfilePriorityOrdering pins spec.priority as the first sort key across the
// cluster-scoped/namespaced boundary. SortProfiles orders by priority, then
// creationTimestamp, then name, then namespace — with the empty namespace of a
// global profile sorting first on an exact tie
// (extensions/epe/pkg/policy/securityprofile/profile.go:456-484). Nothing
// end-to-end has ever exercised that ordering, and a global-wins-by-scope
// regression would be invisible to a test that only ever ties.
//
// The two subtests are the same scenario with the priorities swapped, which is
// what makes them evidence: if scope rather than priority decided, the global
// profile would win both times and the second subtest would fail.
func TestProfilePriorityOrdering(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			dst := all[1]

			ctx.Cleanup(func() {
				if ctx.Failed() {
					ctx.Logf("EPE container log follows:\n%s", epeLogs(ctx))
				}
			})

			cases := []struct {
				name           string
				path           string
				globalPriority int
				nsPriority     int
				wantStatus     int
				wantBody       string
			}{
				{
					name:           "lower priority on the global profile wins",
					path:           "/epe-priority-global",
					globalPriority: 100,
					nsPriority:     200,
					wantStatus:     statusPriorityGlobal,
					wantBody:       "epe-priority-global",
				},
				{
					name:           "lower priority on the namespaced profile wins",
					path:           "/epe-priority-namespaced",
					globalPriority: 200,
					nsPriority:     100,
					wantStatus:     statusPriorityNamespace,
					wantBody:       "epe-priority-namespaced",
				},
			}

			for _, c := range cases {
				ctx.NewSubTest(c.name).
					Run(func(ctx framework.TestContext) {
						// Both profiles block the same path with different status
						// codes, so the observed code names the winner.
						ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
							"Namespace":       ns.Name(),
							"Path":            c.path,
							"GlobalPriority":  c.globalPriority,
							"NsPriority":      c.nsPriority,
							"GlobalStatus":    statusPriorityGlobal,
							"NamespaceStatus": statusPriorityNamespace,
						}, `
apiVersion: agents.kruise.io/v1alpha1
kind: GlobalSecurityProfile
metadata:
  name: epe-priority-global
spec:
  selector: {}
  priority: {{ .GlobalPriority }}
  rules:
  - name: block-from-global
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: {{ .Path }}
    actions:
      block:
        statusCode: {{ .GlobalStatus }}
        body: epe-priority-global
---
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-priority-namespaced
  namespace: {{ .Namespace }}
spec:
  selector: {}
  priority: {{ .NsPriority }}
  rules:
  - name: block-from-namespaced
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: {{ .Path }}
    actions:
      block:
        statusCode: {{ .NamespaceStatus }}
        body: epe-priority-namespaced
`).ApplyOrFail(ctx)

						retry.UntilSuccessOrFail(ctx, func() error {
							_, err := src.Call(echo.CallOptions{
								To:   dst,
								Port: echo.Port{Name: "http"},
								HTTP: echo.HTTP{Path: c.path},
								Check: check.And(
									check.Status(c.wantStatus),
									check.BodyContains(c.wantBody),
								),
							})
							return err
						}, retry.Timeout(3*time.Minute), retry.Delay(5*time.Second))
					})
			}
		})
}
