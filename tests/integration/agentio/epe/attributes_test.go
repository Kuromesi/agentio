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

// Distinct status codes per assertion, so a block can never be confused with a
// mesh-generated 403/503 or with another rule in this file firing.
const (
	statusIdentityBlock = 452
	statusSelectorMatch = 453
	statusSelectorMiss  = 454
)

// TestPodIdentityReachesEPE is the load-bearing test of this suite.
//
// SecurityProfile selection needs the caller's pod namespace, which EPE reads
// only from filter_state['downstream_peer'].namespace / .name
// (extensions/epe/pkg/extproc/attributes/extract.go:41-43). Those attributes
// exist in the request only because the chart lists them under
// sandboxExtProc.request.attributes (templates/agentio-config.yaml), pilot copies
// that list verbatim into the ext_proc filter's request_attributes
// (pilot/.../agentio/ext_proc.go:177-201), and the sandbox data plane populates
// them. There is no default and no validation anywhere on that path.
//
// When any link breaks, extract.go:76-85 logs and returns a partial peer, and the
// request is passed through unmodified — the component fails open, every profile
// silently stops applying, and no existing test notices. enginetest cannot cover
// this because it constructs the attribute map itself.
//
// A namespaced SecurityProfile with an empty selector matches every pod in its
// own namespace and nothing else, so blocking through one proves the namespace
// and name arrived.
func TestPodIdentityReachesEPE(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			dst := all[1]

			ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
				"Namespace": ns.Name(),
			}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-identity
  namespace: {{ .Namespace }}
spec:
  selector: {}
  rules:
  - name: block-identity-path
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /epe-identity
    actions:
      block:
        statusCode: 452
        body: epe-identity-block
`).ApplyOrFail(ctx)

			// Registered before the assertion: retry.UntilSuccessOrFail calls
			// Fatalf, which ends this goroutine, so a Cleanup registered after it
			// would never be reached on the failure path this diagnostic exists
			// for. The fail-open case logs "Pod identity missing from
			// filter_state"; its absence points at EPE never being called at all.
			ctx.Cleanup(func() {
				if ctx.Failed() {
					ctx.Logf("EPE container log follows; look for "+
						"'Pod identity missing from filter_state', which means the "+
						"downstream_peer attributes did not reach EPE:\n%s", epeLogs(ctx))
				}
			})

			retry.UntilSuccessOrFail(ctx, func() error {
				_, err := src.Call(echo.CallOptions{
					To:   dst,
					Port: echo.Port{Name: "http"},
					HTTP: echo.HTTP{Path: "/epe-identity"},
					Check: check.And(
						check.Status(statusIdentityBlock),
						check.BodyContains("epe-identity-block"),
					),
				})
				return err
			}, retry.Timeout(3*time.Minute), retry.Delay(5*time.Second))
		})
}

// TestSandboxLabelsReachEPE covers the second half of the attribute contract.
// Selection by spec.selector needs the caller's pod labels, which EPE decodes
// from the base64 "k1=v1,k2=v2" blob in filter_state['sandbox.labels']
// (extract.go:87-100) — a different attribute, populated by a different
// component, than the pod identity above.
//
// Both profiles are applied in a single Apply, and the matching one doubles as a
// propagation barrier: the store rebuilds one atomic snapshot, so once the
// matching profile blocks, the non-matching profile is loaded too. Without that
// barrier the negative assertion would pass merely by racing ahead of policy
// propagation.
func TestSandboxLabelsReachEPE(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			dst := all[1]

			ctx.ConfigIstio().Eval(ns.Name(), map[string]any{
				"Namespace": ns.Name(),
			}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-selector-match
  namespace: {{ .Namespace }}
spec:
  selector:
    matchLabels:
      app: client
  rules:
  - name: block-matching-selector
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /epe-selector-match
    actions:
      block:
        statusCode: 453
        body: epe-selector-match-block
---
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-selector-miss
  namespace: {{ .Namespace }}
spec:
  selector:
    matchLabels:
      app: not-the-calling-workload
  rules:
  - name: block-non-matching-selector
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /epe-selector-miss
    actions:
      block:
        statusCode: 454
        body: epe-selector-miss-block
`).ApplyOrFail(ctx)

			ctx.NewSubTest("matching selector blocks").
				Run(func(ctx framework.TestContext) {
					// Registered before the assertion; see TestPodIdentityReachesEPE.
					ctx.Cleanup(func() {
						if ctx.Failed() {
							ctx.Logf("The caller's pod labels did not reach EPE, or did not decode. "+
								"Either sandbox.labels is missing from the ext_proc request_attributes "+
								"(templates/agentio-config.yaml) or the sandbox data plane did not populate "+
								"it for this workload type. EPE log:\n%s", epeLogs(ctx))
						}
					})

					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							To:   dst,
							Port: echo.Port{Name: "http"},
							HTTP: echo.HTTP{Path: "/epe-selector-match"},
							Check: check.And(
								check.Status(statusSelectorMatch),
								check.BodyContains("epe-selector-match-block"),
							),
						})
						return err
					}, retry.Timeout(3*time.Minute), retry.Delay(5*time.Second))
				})

			ctx.NewSubTest("non-matching selector does not block").
				Run(func(ctx framework.TestContext) {
					// No retry loop: the sibling subtest already proved this
					// snapshot is live, so a single call is conclusive and a
					// retry could only mask a late block.
					_, err := src.Call(echo.CallOptions{
						To:    dst,
						Port:  echo.Port{Name: "http"},
						HTTP:  echo.HTTP{Path: "/epe-selector-miss"},
						Check: check.OK(),
					})
					if err != nil {
						ctx.Fatalf("a SecurityProfile whose selector does not match the caller "+
							"still affected the request, so selector evaluation is not using the "+
							"caller's real labels: %v", err)
					}
				})
		})
}
