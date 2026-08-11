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

// Package epe holds the KinD end-to-end tests for the Egress Policy Enforcer,
// the only suite that runs the real agentio-epe image in a cluster.
//
// # Scope
//
// This suite covers only what cannot exist in-process. The enginetest harness
// (extensions/epe/pkg/testing/enginetest/doc.go) already drives the real
// ext_proc server and the production filter chain over a fake Envoy stream, so
// policy semantics — matchers, actions, rule ordering within a profile, audit
// rendering, token transformation — are covered there and are deliberately not
// repeated here. What enginetest cannot reach, and what this suite asserts:
//
//   - The deployment contract: EPE's ServiceAccount can actually list and watch
//     the resources its informers open. Unit tests use a fake clientset, which
//     never enforces RBAC.
//   - The Envoy-to-EPE attribute contract: the attributes EPE reads out of
//     filter_state are the attributes the chart asks Envoy to send and the
//     sandbox data plane actually populates. enginetest hands these attributes
//     to the engine directly, so a break in that chain is invisible to it — and
//     the failure mode is fail-open (attributes/extract.go:76-85), meaning every
//     SecurityProfile silently stops applying.
//   - GlobalSecurityProfile, which no other test in this repository or in the
//     cloud e2e suite exercises end to end.
package epe

import (
	"context"
	"fmt"
	"testing"
	"time"

	"istio.io/api/label"
	controlleragentio "istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/test/framework"
	agentiocomp "istio.io/istio/pkg/test/framework/components/agentio"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/common/ports"
	"istio.io/istio/pkg/test/framework/components/echo/deployment"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/framework/resource"
	testKube "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/util/retry"
)

const (
	// agentioConfigMapName is the primary (user-managed) config source. It is
	// merged on top of the chart-managed agentio-config, which is where
	// epe.enabled=true writes sandboxExtProc
	// (manifests/charts/agentio/templates/agentio-config.yaml). Tests must
	// therefore never set sandboxExtProc here, or they would replace the EPE
	// wiring they are trying to exercise.
	agentioConfigMapName = "agentio-config-primary"

	// epeName matches the chart default for .Values.epe.name and is
	// simultaneously the Deployment, Service, ServiceAccount and container name
	// (manifests/charts/agentio/templates/epe.yaml).
	epeName = "agentio-epe"

	// epeMetricsPort is the Prometheus port the chart advertises via
	// prometheus.io/port annotations (epe.yaml).
	epeMetricsPort = 9090
)

var (
	i   istio.Instance
	ai  agentiocomp.Instance
	ns  namespace.Instance
	all echo.Instances
)

var (
	deployAsSandbox = env.Register("DEPLOY_AS_SANDBOX", false, "Whether to deploy echo instances as sandbox workloads").Get()
	ambientMode     = env.Register("AMBIENT_MODE", false, "Whether to use ambient mode (node-level ztunnel) instead of sidecar ztunnel").Get()
	firewallBackend = env.Register("FIREWALL_BACKEND", "auto", "Ztunnel firewall backend: auto or iptables").Get()
	enableFirewall  = env.Register("ENABLE_FIREWALL", false, "Whether to enable firewall rules").Get()
)

func TestMain(m *testing.M) {
	nsPrefix := "epe"
	if ambientMode {
		nsPrefix += "-ambient"
	}
	nsCfg := namespace.Config{Prefix: nsPrefix, Inject: !ambientMode}
	if ambientMode {
		nsCfg.Inject = false
		nsCfg.Labels = map[string]string{
			label.IoIstioDataplaneMode.Name: "ambient",
		}
	}
	suite := framework.NewSuite(m)
	if ambientMode || deployAsSandbox {
		suite = suite.Setup(func(ctx resource.Context) error {
			ctx.Settings().Ambient = true
			return nil
		})
	}
	suite.
		Setup(istio.Setup(&i, func(_ resource.Context, cfg *istio.Config) {
			cfg.DeployIstio = false
			cfg.SystemNamespace = agentiocomp.DefaultNamespace
		})).
		Setup(agentiocomp.Setup(&ai, func(ctx resource.Context, cfg *agentiocomp.Config) {
			image := ctx.Settings().Image
			cfg.Values = map[string]string{
				"ambient.enabled":                         fmt.Sprintf("%t", ambientMode),
				"ambient.ztunnel.env.FIREWALL_BACKEND":    firewallBackend,
				"sidecarInjector.ztunnel.firewallBackend": firewallBackend,
				"global.enableFirewallRules":              fmt.Sprintf("%t", enableFirewall),
				"agentiod.resources.requests.cpu":         "1",
				"agentiod.resources.requests.memory":      "1Gi",
				"agentiod.resources.limits.cpu":           "1",
				"agentiod.resources.limits.memory":        "1Gi",
				"egressGateway.gateways[0].name":          "egress-gateway",
				"egressGateway.autoscaling.enabled":       "false",
				"egressGateway.replicas":                  "1",
				"egressGateway.resources.requests.cpu":    "100m",
				"egressGateway.resources.requests.memory": "128Mi",
				"egressGateway.resources.limits.cpu":      "1",
				"egressGateway.resources.limits.memory":   "512Mi",

				// The chart pins EPE to docker.io/openkruise:latest by default;
				// point it at the registry this run built into. Unlike the mesh
				// images, agentio.writeValues does not template epe.image.
				"epe.enabled":             "true",
				"epe.image.hub":           image.Hub,
				"epe.image.tag":           image.Tag,
				"epe.replicas":            "1",
				"epe.autoscaling.enabled": "false",
				// Chart defaults request 2 CPU / 2Gi, which will not schedule
				// alongside agentiod and the gateway on a single KinD node.
				"epe.resources.requests.cpu":    "100m",
				"epe.resources.requests.memory": "256Mi",
				"epe.resources.limits.cpu":      "1",
				"epe.resources.limits.memory":   "512Mi",
			}
		})).
		Setup(namespace.Setup(&ns, nsCfg)).
		Setup(deployEchoes).
		Setup(waitForEPE).
		Setup(routeEgressThroughGateway).
		Run()
}

func deployEchoes(ctx resource.Context) error {
	var err error
	annotations := map[string]string{}
	labels := map[string]string{}
	if !ambientMode {
		labels[controlleragentio.LabelSandboxProxyType] = "ztunnel"
		if !deployAsSandbox {
			annotations["inject.istio.io/templates"] = "ztunnel"
		}
	}

	all, err = deployment.New(ctx).
		WithConfig(echo.Config{
			Service:        "client",
			Namespace:      ns,
			Ports:          ports.All(),
			ServiceAccount: true,
			Subsets: []echo.SubsetConfig{{
				Annotations: annotations,
				Labels:      labels,
			}},
			DeployAsSandbox: deployAsSandbox,
			Capabilities:    []string{"NET_ADMIN", "NET_RAW"},
		}).
		WithConfig(echo.Config{
			Service:        "server",
			Namespace:      ns,
			Ports:          ports.All(),
			ServiceAccount: true,
			Subsets: []echo.SubsetConfig{{
				Annotations: annotations,
				Labels:      labels,
			}},
			DeployAsSandbox: deployAsSandbox,
		}).
		Build()
	return err
}

// waitForEPE blocks until the chart-deployed EPE Deployment is Ready. Both
// probes are gRPC probes against the health port (epe.yaml), so readiness here
// already proves the process came up and serves gRPC health.
func waitForEPE(ctx resource.Context) error {
	fetchFn := testKube.NewPodFetch(ctx.Clusters().Default(), i.Settings().SystemNamespace,
		"app.kubernetes.io/name="+epeName)
	if _, err := testKube.WaitUntilPodsAreReady(fetchFn,
		retry.Timeout(3*time.Minute), retry.Delay(5*time.Second)); err != nil {
		return fmt.Errorf("EPE deployment not ready: %v", err)
	}
	return nil
}

// routeEgressThroughGateway sends sandbox egress via the chart's egress gateway,
// which is the listener carrying the ext_proc filter that calls EPE. Only
// egressPolicies is set: sandboxExtProc is left to the chart-managed base
// ConfigMap so the merge keeps pointing at EPE.
func routeEgressThroughGateway(ctx resource.Context) error {
	return ctx.ConfigIstio().Eval(i.Settings().SystemNamespace, map[string]string{
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
`).Apply()
}

// epePodName returns the name of one EPE pod, for exec-based assertions.
func epePodName(ctx framework.TestContext) string {
	ctx.Helper()
	name, err := findEPEPod(ctx)
	if err != nil {
		ctx.Fatalf("%v", err)
	}
	return name
}

func findEPEPod(ctx framework.TestContext) (string, error) {
	pods, err := testKube.NewPodFetch(ctx.Clusters().Default(), i.Settings().SystemNamespace,
		"app.kubernetes.io/name="+epeName)()
	if err != nil {
		return "", fmt.Errorf("fetch EPE pods: %w", err)
	}
	if len(pods) == 0 {
		return "", fmt.Errorf("no EPE pods found in %s", i.Settings().SystemNamespace)
	}
	return pods[0].Name, nil
}

// epeLogs returns the current EPE container log, used to turn a fail-open into a
// readable diagnosis rather than a bare "request was not blocked". It never
// fails the test: it is only ever called from cleanup paths that are already
// reporting a different failure, and swallowing its own errors keeps the
// original one on screen.
func epeLogs(ctx framework.TestContext) string {
	pod, err := findEPEPod(ctx)
	if err != nil {
		return fmt.Sprintf("<could not locate EPE pod: %v>", err)
	}
	logs, err := ctx.Clusters().Default().PodLogs(context.Background(), pod,
		i.Settings().SystemNamespace, epeName, false)
	if err != nil {
		return fmt.Sprintf("<could not read EPE logs: %v>", err)
	}
	return logs
}
