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

package agentio

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/test/framework"
	testKube "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/util/retry"
)

const staticServiceEntryHost = "static-service-entry.test"

// TestSandboxStaticServiceEntry verifies that one host can use multiple static
// endpoints on both the plaintext forward-http path and the TLS-terminated
// main_forward path. The client connects to an unreachable TEST-NET address;
// success therefore requires the gateway to select one of the configured
// endpoint IPs while retaining the original request port.
func TestSandboxStaticServiceEntry(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			serverKey, serverCertChain, serverCA := generateConnectProxyCertificate(ctx, staticServiceEntryHost)
			systemNamespace := i.Settings().SystemNamespace
			ctx.ConfigIstio().EvalFile(systemNamespace, map[string]any{
				"Namespace":       systemNamespace,
				"ServerKey":       serverKey,
				"ServerCertChain": serverCertChain,
				"ServerCA":        serverCA,
			}, "testdata/static-service-entry-upstream.yaml").ApplyOrFail(ctx)

			cluster := ctx.Clusters().Default()
			fetchUpstream := testKube.NewPodFetch(cluster, systemNamespace, "app=static-service-entry-upstream")
			if _, err := testKube.WaitUntilPodsAreReady(fetchUpstream,
				retry.Timeout(2*time.Minute), retry.Delay(5*time.Second)); err != nil {
				ctx.Fatalf("static service-entry upstream not ready: %v", err)
			}

			endpointOne := serviceClusterIP(ctx, systemNamespace, "static-service-entry-upstream-1")
			endpointTwo := serviceClusterIP(ctx, systemNamespace, "static-service-entry-upstream-2")
			ctx.ConfigIstio().Eval(systemNamespace, map[string]any{
				"Namespace":   systemNamespace,
				"EndpointOne": endpointOne,
				"EndpointTwo": endpointTwo,
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
        - "`+staticServiceEntryHost+`"
      serviceEntries:
      - hosts:
        - "`+staticServiceEntryHost+`"
        endpoints:
        - address: "{{ .EndpointOne }}"
        - address: "{{ .EndpointTwo }}"
`).ApplyOrFail(ctx)

			src := all[0]
			workload := src.WorkloadsOrFail(ctx)[0]
			callUntilBothEndpointsSeen := func(scheme string, port int, insecure bool) error {
				seen := make(map[string]struct{}, 2)
				insecureFlag := ""
				if insecure {
					insecureFlag = "-k"
				}
				for request := 0; request < 20 && len(seen) < 2; request++ {
					command := fmt.Sprintf(
						"curl -sS %s --noproxy '*' --resolve %s:%d:192.0.2.1 --connect-timeout 5 --max-time 15 %s://%s:%d/",
						insecureFlag, staticServiceEntryHost, port, scheme, staticServiceEntryHost, port)
					stdout, stderr, err := cluster.PodExec(workload.PodName(), src.NamespaceName(), "app", command)
					if err != nil {
						return fmt.Errorf("%s request failed: %w; stdout=%q stderr=%q", scheme, err, stdout, stderr)
					}
					endpoint := strings.TrimSpace(stdout)
					if endpoint != "endpoint-1" && endpoint != "endpoint-2" {
						return fmt.Errorf("%s response = %q, want endpoint-1 or endpoint-2", scheme, endpoint)
					}
					seen[endpoint] = struct{}{}
				}
				if len(seen) != 2 {
					return fmt.Errorf("%s requests reached %v, want both configured endpoints", scheme, seen)
				}
				return nil
			}

			ctx.NewSubTest("HTTP forward-http").Run(func(ctx framework.TestContext) {
				retry.UntilSuccessOrFail(ctx, func() error {
					return callUntilBothEndpointsSeen("http", 80, false)
				}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
			})

			ctx.NewSubTest("HTTPS main_forward").Run(func(ctx framework.TestContext) {
				retry.UntilSuccessOrFail(ctx, func() error {
					return callUntilBothEndpointsSeen("https", 443, true)
				}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
			})
		})
}

func serviceClusterIP(ctx framework.TestContext, namespace, name string) string {
	service, err := ctx.Clusters().Default().Kube().CoreV1().Services(namespace).Get(
		context.Background(), name, metav1.GetOptions{})
	if err != nil {
		ctx.Fatalf("get service %s/%s: %v", namespace, name, err)
	}
	if service.Spec.ClusterIP == "" || service.Spec.ClusterIP == "None" {
		ctx.Fatalf("service %s/%s has no routable ClusterIP", namespace, name)
	}
	return service.Spec.ClusterIP
}
