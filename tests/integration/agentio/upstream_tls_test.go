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
	"fmt"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework"
	testKube "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/util/retry"
)

// TestSandboxUpstreamTLS uses isolated server listeners so successful HTTP
// responses prove a compatible upstream handshake, not merely accepted xDS.
// Every curl call starts a fresh downstream connection. TEST-NET resolution forces the
// gateway to resolve the actual upstream rather than letting curl bypass it.
func TestSandboxUpstreamTLS(t *testing.T) {
	framework.NewTest(t).Run(func(ctx framework.TestContext) {
		namespace := i.Settings().SystemNamespace
		host := fmt.Sprintf("upstream-tls.%s.svc.cluster.local", namespace)
		badHost := fmt.Sprintf("upstream-tls-wrong-san.%s.svc.cluster.local", namespace)
		key, chain, ca := generateConnectProxyCertificate(ctx, host)
		ctx.ConfigIstio().EvalFile(namespace, map[string]any{
			"Namespace": namespace, "ServerKey": key, "ServerCertChain": chain, "ServerCA": ca,
		}, "testdata/upstream-tls.yaml").ApplyOrFail(ctx)
		cluster := ctx.Clusters().Default()
		if _, err := testKube.WaitUntilPodsAreReady(testKube.NewPodFetch(cluster, namespace, "app=upstream-tls"),
			retry.Timeout(2*time.Minute), retry.Delay(5*time.Second)); err != nil {
			ctx.Fatalf("TLS upstream not ready: %v", err)
		}
		src := all[0]
		workload := src.WorkloadsOrFail(ctx)[0]
		applySettings := func(ctx framework.TestContext, settings string) {
			ctx.ConfigIstio().Eval(namespace, map[string]any{"Namespace": namespace, "Host": host, "BadHost": badHost, "Settings": settings}, `
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
        - "{{ .Host }}"
        - "{{ .BadHost }}"
{{ .Settings | indent 6 }}
`).ApplyOrFail(ctx)
		}
		call := func(host string, port int, want string) error {
			// -k trusts only the gateway's on-demand downstream certificate. The
			// gateway still validates the upstream against the fixture CA and SAN.
			stdout, stderr, err := cluster.PodExecCommands(workload.PodName(), src.NamespaceName(), "app", []string{
				"curl", "-sS", "-k", "--http1.1", "--noproxy", "*", "--connect-timeout", "5", "--max-time", "15",
				"--resolve", fmt.Sprintf("%s:%d:192.0.2.1", host, port),
				"-H", "Connection: close", "-w", "\n%{http_code}", fmt.Sprintf("https://%s:%d/", host, port),
			})
			if err != nil {
				return fmt.Errorf("TLS request to %s:%d: %v; stdout=%q stderr=%q", host, port, err, stdout, stderr)
			}
			if want == "503" {
				if !strings.HasSuffix(strings.TrimSpace(stdout), "\n503") || !strings.Contains(stdout, "upstream connect error") {
					return fmt.Errorf("response = %q, want gateway upstream-connect 503", stdout)
				}
			} else if strings.TrimSpace(stdout) != want+"\n200" {
				return fmt.Errorf("response = %q, want %q and HTTP 200", stdout, want)
			}
			return nil
		}
		for _, tt := range []struct {
			name, settings               string
			tls13, ecdhe, rsa128, rsa256 string
		}{
			{"compatible defaults", "", "tls13", "ecdhe", "rsa128", "rsa256"},
			{"maximum TLS 1.2", "upstreamTls: {maxProtocolVersion: TLSV1_2}", "503", "ecdhe", "rsa128", "rsa256"},
			{"ECDHE list replaces defaults", "upstreamTls: {cipherSuites: [ECDHE-RSA-AES128-GCM-SHA256]}", "tls13", "ecdhe", "503", "503"},
			{"minimum TLS 1.3", "upstreamTls: {minProtocolVersion: TLSV1_3}", "tls13", "503", "503", "503"},
			{"empty list restores defaults", "upstreamTls: {cipherSuites: []}", "tls13", "ecdhe", "rsa128", "rsa256"},
			{"omitted settings restore defaults", "", "tls13", "ecdhe", "rsa128", "rsa256"},
		} {
			ctx.NewSubTest(tt.name).Run(func(ctx framework.TestContext) {
				applySettings(ctx, tt.settings)
				// Check the complete matrix together on each retry so propagation errors
				// cannot satisfy a negative assertion while all destinations are broken.
				retry.UntilSuccessOrFail(ctx, func() error {
					for _, endpoint := range []struct {
						port int
						want string
					}{
						{18443, tt.tls13}, {18444, tt.ecdhe}, {18445, tt.rsa128}, {18446, tt.rsa256},
					} {
						if err := call(host, endpoint.port, endpoint.want); err != nil {
							return err
						}
					}
					return call(badHost, 18443, "503")
				}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
			})
		}
	})
}
