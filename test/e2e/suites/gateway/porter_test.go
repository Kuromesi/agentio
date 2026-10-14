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

package gateway

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// TestPorterConnectProcessing uses an unreachable intercepted destination so
// successful requests must traverse the gateway. The application ext_proc only
// mutates HTTP headers; it does not implement Agentio's CONNECT policy contract.
func TestPorterConnectProcessing(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	namespace := resolvedAgentioConfig.Namespace
	host := fmt.Sprintf("upstream-tls.%s.svc.cluster.local", namespace)
	key, chain, ca := generateConnectProxyCertificate(t, host)
	e2econfig.New(scope).EvalFile(namespace, map[string]any{
		"Namespace":         namespace,
		"ServerKey":         key,
		"ServerCertChain":   chain,
		"ServerCA":          ca,
		"ForwardProxyImage": resolvedAgentioConfig.ForwardProxyImage,
	}, "testdata/upstream-tls.yaml").ApplyOrFail(t, kube.CreateOnly)
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	if _, err := environment.Kube.WaitReadyPods(ctx, namespace, "app=upstream-tls", 1); err != nil {
		t.Fatalf("TLS upstream not ready: %v", err)
	}
	applyGatewayTLSTerminationProfile(t, scope, host)
	rig.ApplyConfig(t, scope, map[string]any{"Namespace": namespace, "Host": host}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    sandboxExtProc:
      service: ext-proc.{{ .Namespace }}.svc.cluster.local
      port: 9002
      failureModeAllow: false
      request:
        headerMode: SEND
      response:
        headerMode: SEND
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
`)
	waitForGatewayConfig(t, environment, time.Second, func(dump string) error {
		for _, want := range []string{"agentio-porter", "ext-proc." + namespace, host} {
			if !strings.Contains(dump, want) {
				return fmt.Errorf("gateway config does not contain %q", want)
			}
		}
		return nil
	})

	if !t.Run("HTTP without SNI still reaches the application processor", func(t *testing.T) {
		before := porterRequestCount(t, environment)
		trafficFixture.Client.CallOrFail(t, echo.CallOptions{
			Protocol: echo.HTTP,
			Address:  "192.0.2.1",
			Port:     80,
			Count:    1,
			Headers:  map[string]string{"Host": trafficFixture.Server.Address()},
			Check: check.And(check.OK(),
				check.RequestHeader("X-Hello-To-Ext-Proc", "true"),
				check.ResponseHeader("X-Hello-From-Ext-Proc", "true")),
			Retry: harness.FixedRetry(2*time.Minute, 5*time.Second),
		})
		if after := porterRequestCount(t, environment); after <= before {
			t.Fatalf("HTTP succeeded without invoking Porter: requests before=%d after=%d", before, after)
		}
	}) {
		return
	}

	t.Run("SNI termination and custom ext_proc both execute", func(t *testing.T) {
		before := porterRequestCount(t, environment)
		harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
			ctx, cancel := e2e.Context(t, 20*time.Second)
			defer cancel()
			stdout, stderr, err := externalCurl(ctx,
				"-k", "--raw", "--http1.1", "--noproxy", "*", "--connect-timeout", "5", "--max-time", "15",
				"--resolve", host+":18443:192.0.2.1", "-H", "Connection: close",
				"-D", "-", fmt.Sprintf("https://%s:18443/", host),
			)
			if err != nil {
				return fmt.Errorf("TLS through Porter: %w; stdout=%q stderr=%q", err, stdout, stderr)
			}
			response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(stdout)), nil)
			if err != nil {
				return fmt.Errorf("parse TLS response: %w; stdout=%q", err, stdout)
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				return err
			}
			if response.StatusCode != http.StatusOK || string(body) != "tls13" {
				return fmt.Errorf("TLS response status=%d body=%q, want 200/tls13", response.StatusCode, body)
			}
			if got := response.Header.Get("X-Hello-From-Ext-Proc"); got != "true" {
				return fmt.Errorf("custom ext_proc response header=%q, want true", got)
			}
			return nil
		})
		if after := porterRequestCount(t, environment); after <= before {
			t.Fatalf("TLS succeeded without invoking Porter: requests before=%d after=%d", before, after)
		}
	})
}

// The cluster request counter proves a real ext_proc stream was opened to the
// sidecar, including when the CONNECT carries no x-agentio-sni header.
func porterRequestCount(t *testing.T, environment *e2e.Environment) uint64 {
	t.Helper()
	ctx, cancel := e2e.Context(t, 10*time.Second)
	defer cancel()
	stdout, stderr, err := execFirstReadyPod(ctx, environment, resolvedAgentioConfig.Namespace,
		harness.GatewayPodSelector, "agentio-proxy",
		[]string{"curl", "-fsS", "localhost:15000/stats?format=json&filter=agentio-porter.*upstream_rq_total"})
	if err != nil {
		t.Fatalf("read Porter request count: %v; stderr=%s", err, stderr)
	}
	var result struct {
		Stats []struct {
			Name  string `json:"name"`
			Value uint64 `json:"value"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("parse Porter request count: %v; stdout=%s", err, stdout)
	}
	for _, stat := range result.Stats {
		if stat.Name == "cluster.agentio-porter;.upstream_rq_total" {
			return stat.Value
		}
	}
	t.Fatalf("Porter request counter missing: %s", stdout)
	return 0
}
