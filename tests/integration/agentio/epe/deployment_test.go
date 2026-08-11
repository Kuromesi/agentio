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
	"context"
	"fmt"
	"strings"
	"testing"

	"istio.io/istio/pkg/test/framework"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestEPEServiceAccountCanWatchItsInputs pins EPE's RBAC to the set of
// resources its informers actually open. Every EPE unit test builds its client
// with k8sfake.NewClientset, which serves every request regardless of RBAC, so a
// missing ClusterRole rule cannot fail anywhere except in a real cluster.
//
// The required set is not a guess; each entry has a call site:
//
//   - securityprofiles and globalsecurityprofiles: both are registered as typed
//     List/Watch informers in
//     extensions/epe/pkg/policy/profilestore/collection.go.
//   - customresourcedefinitions: the profile collections are delayed informers,
//     and kclient.NewDelayedInformer calls log.Fatal when no CrdWatcher is
//     enabled (pkg/kube/kclient/client.go:329-332). cmd/epe/main.go enables one
//     with kube.EnableCrdWatcher, and that watcher lists and watches CRDs. Deny
//     it and EPE never learns the profile CRDs exist, so no profile ever loads.
func TestEPEServiceAccountCanWatchItsInputs(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			systemNS := i.Settings().SystemNamespace
			// A ServiceAccount authenticates under this username, so a
			// SubjectAccessReview for it answers exactly the question "will the
			// EPE pod's own API calls be allowed".
			user := fmt.Sprintf("system:serviceaccount:%s:%s", systemNS, epeName)

			cases := []struct {
				group    string
				resource string
				why      string
			}{
				{"agents.kruise.io", "securityprofiles", "namespaced profile informer"},
				{"agents.kruise.io", "globalsecurityprofiles", "cluster-scoped profile informer"},
				{"apiextensions.k8s.io", "customresourcedefinitions", "CrdWatcher backing the delayed informers"},
			}

			for _, c := range cases {
				for _, verb := range []string{"list", "watch"} {
					ctx.NewSubTest(fmt.Sprintf("%s/%s", c.resource, verb)).
						Run(func(ctx framework.TestContext) {
							review := &authzv1.SubjectAccessReview{
								Spec: authzv1.SubjectAccessReviewSpec{
									User: user,
									ResourceAttributes: &authzv1.ResourceAttributes{
										Group:    c.group,
										Resource: c.resource,
										Verb:     verb,
										// Namespace is intentionally empty: the
										// informers watch at cluster scope.
									},
								},
							}
							got, err := ctx.Clusters().Default().Kube().AuthorizationV1().
								SubjectAccessReviews().Create(context.Background(), review, metav1.CreateOptions{})
							if err != nil {
								ctx.Fatalf("create SubjectAccessReview for %s %s: %v", verb, c.resource, err)
							}
							if !got.Status.Allowed {
								ctx.Fatalf(
									"EPE ServiceAccount %s may not %s %s.%s at cluster scope (needed for the %s); "+
										"reason=%q evaluationError=%q. Add the rule to "+
										"manifests/charts/agentio/templates/epe.yaml.",
									user, verb, c.resource, c.group, c.why,
									got.Status.Reason, got.Status.EvaluationError)
							}
						})
				}
			}
		})
}

// TestEPEMetricsEndpointServes asserts the Prometheus endpoint the chart
// advertises through prometheus.io/scrape annotations is actually served on the
// port the annotations name. The gRPC health port is already proven by the pod
// being Ready (both probes are gRPC probes), but nothing else checks 9090, and a
// port mismatch between the flag and the annotation would silently produce a
// pod that scrapes empty forever.
func TestEPEMetricsEndpointServes(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			pod := epePodName(ctx)
			// curl ships in the Istio base image the EPE image builds on
			// (docker/Dockerfile.base). Probing from inside the pod keeps this
			// off the mesh data path, so a failure means "EPE is not serving
			// metrics" rather than "some sidecar dropped the request".
			stdout, stderr, err := ctx.Clusters().Default().PodExec(pod, i.Settings().SystemNamespace, epeName,
				fmt.Sprintf("curl -sS --max-time 10 http://127.0.0.1:%d/metrics", epeMetricsPort))
			if err != nil {
				ctx.Fatalf("curl EPE metrics on port %d: %v (stderr: %s)", epeMetricsPort, err, stderr)
			}
			// Any Prometheus exposition output starts its series with these
			// comment lines; asserting on a specific EPE metric name would couple
			// this test to whichever metrics happen to be registered.
			if !strings.Contains(stdout, "# HELP") && !strings.Contains(stdout, "# TYPE") {
				ctx.Fatalf("EPE metrics endpoint on port %d returned no Prometheus exposition output; got:\n%s",
					epeMetricsPort, stdout)
			}
		})
}
