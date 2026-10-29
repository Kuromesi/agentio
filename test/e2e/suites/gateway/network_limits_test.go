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
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func applyNetworkLimits(
	t *testing.T,
	environment *e2e.Environment,
	scope *kube.ResourceScope,
	concurrency, bandwidth int,
) {
	t.Helper()
	rig.ApplyConfig(
		t,
		scope,
		map[string]any{
			"Namespace":   resolvedAgentioConfig.Namespace,
			"Concurrency": concurrency,
			"Bandwidth":   bandwidth,
		},
		`
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      connectRateLimit:
        tokenBucket:
          maxTokens: 1000
          tokensPerFill: 1000
          fillInterval: 1s
      connectConcurrencyLimit:
        rateLimits:
        - actions:
          - filterState: {key: agentio.workload.namespace, descriptorKey: namespace}
          - filterState: {key: agentio.workload.name, descriptorKey: workload}
        descriptors:
        - entries: [{key: namespace}, {key: workload}]
          maxConcurrentStreams: {{ .Concurrency }}
      bandwidthLimit:
        rateLimits:
        - actions:
          - filterState: {key: agentio.workload.namespace, descriptorKey: namespace}
          - filterState: {key: agentio.workload.name, descriptorKey: workload}
        descriptors:
        - entries: [{key: namespace}, {key: workload}]
          bandwidthLimit:
            downloadBytesPerSecond: {{ .Bandwidth }}
`,
	)
	waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
		var value any
		if err := json.Unmarshal([]byte(dump), &value); err != nil {
			return err
		}
		compact, err := json.Marshal(value)
		if err != nil {
			return err
		}
		for _, needle := range []string{"libenvoy_agentio_network_limits.so", "envoy_agentio_connect_concurrency", "envoy_agentio_bandwidth", "envoy.filters.http.local_ratelimit", fmt.Sprintf(`"max_concurrent_streams":%d`, concurrency), fmt.Sprintf(`"download_bytes_per_second":"%d"`, bandwidth)} {
			if !strings.Contains(string(compact), needle) {
				return fmt.Errorf("network limit config missing %s", needle)
			}
		}
		return nil
	})
}

func gatewayStat(ctx context.Context, environment *e2e.Environment, name string) (int, error) {
	stdout, stderr, err := execFirstReadyPod(
		ctx,
		environment,
		resolvedAgentioConfig.Namespace,
		harness.GatewayPodSelector,
		"agentio-proxy",
		[]string{
			"curl",
			"-fsS",
			"--max-time",
			"5",
			"http://localhost:15000/stats?format=json&filter=" + name,
		},
	)
	if err != nil {
		return 0, fmt.Errorf("gateway stats: %w: %s", err, stderr)
	}
	var result struct{ Stats []struct{ Value int } }
	if err = json.Unmarshal([]byte(stdout), &result); err != nil {
		return 0, err
	}
	if len(result.Stats) == 0 {
		return 0, fmt.Errorf("gateway stat %q is missing", name)
	}
	total := 0
	for _, s := range result.Stats {
		total += s.Value
	}
	return total, nil
}

func waitForNetworkLimitsDrain(t *testing.T, ctx context.Context, environment *e2e.Environment) {
	t.Helper()
	// Initial filter installation cannot retrofit the previous scenarios' pooled HBONE connections.
	harness.RetryAssertion(t, time.Minute, 200*time.Millisecond, func() error {
		for _, name := range []string{"total_filter_chains_draining", "total_listeners_draining"} {
			n, err := gatewayStat(ctx, environment, "listener_manager."+name)
			if err != nil {
				return err
			}
			if n != 0 {
				return fmt.Errorf("%s=%d, waiting for the old filter chains to drain", name, n)
			}
		}
		return nil
	})
}

func TestSandboxNetworkConcurrency(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	pods, err := environment.Kube.ReadyPods(ctx, resolvedAgentioConfig.Namespace, harness.GatewayPodSelector)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) != 1 {
		t.Fatal("per-process concurrency scenario requires the default single gateway replica")
	}
	applyNetworkLimits(t, environment, scope, 1, 16*1024*1024)
	waitForNetworkLimitsDrain(t, ctx, environment)
	target := trafficFixture.AnotherServer.Address()
	done := make(chan error, 1)
	go func() {
		_, _, err := externalCurl(ctx, "-f", "--max-time", "35", "http://"+target+"/?delay=20s")
		done <- err
	}()
	harness.RetryAssertion(t, 10*time.Second, 100*time.Millisecond, func() error {
		n, err := gatewayStat(ctx, environment, "http.connect_terminate.downstream_rq_active")
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("active CONNECTs=%d, want 1", n)
		}
		return nil
	})
	if _, _, err = externalCurl(ctx, "-f", "--max-time", "5", "http://"+target+"/"); err == nil {
		t.Fatal("second connection from the same workload was admitted")
	}
	harness.RetryAssertion(t, 5*time.Second, 100*time.Millisecond, func() error {
		lines := int64(50)
		logs, err := logsFirstReadyPod(
			ctx,
			environment,
			resolvedAgentioConfig.Namespace,
			harness.GatewayPodSelector,
			"agentio-proxy",
			&lines,
		)
		if err != nil {
			return err
		}
		if !strings.Contains(logs, `"response_code_details":"concurrency_limit_exceeded"`) {
			return fmt.Errorf("gateway has not logged concurrency_limit_exceeded")
		}
		return nil
	})

	// The second workload has a separate descriptor even in the same namespace.
	stdout, stderr, err := trafficFixture.Server.Exec(
		ctx,
		[]string{"curl", "-fsS", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", "http://" + target + "/"},
	)
	if err != nil || stdout != "200" {
		t.Fatalf("independent workload: %s %s %v", stdout, stderr, err)
	}
	applyNetworkLimits(t, environment, scope, 2, 16*1024*1024)
	if _, _, err = externalCurl(ctx, "-f", "--max-time", "5", "http://"+target+"/"); err != nil {
		t.Fatalf("raised concurrency limit not applied: %v", err)
	}
	if err = <-done; err != nil {
		t.Fatalf("existing stream interrupted by update: %v", err)
	}
	if _, _, err = externalCurl(ctx, "-f", "--max-time", "5", "http://"+target+"/"); err != nil {
		t.Fatalf("completed stream did not release admission: %v", err)
	}
	current, err := firstReadyPod(ctx, environment, resolvedAgentioConfig.Namespace, harness.GatewayPodSelector)
	if err != nil {
		t.Fatal(err)
	}
	if current.UID != pods[0].UID {
		t.Fatal("gateway was replaced during the live limit update")
	}
}

func TestSandboxNetworkBandwidth(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	applyNetworkLimits(t, environment, scope, 8, 8192)
	waitForNetworkLimitsDrain(t, ctx, environment)
	target := trafficFixture.AnotherServer.Address()
	// Echo includes the URI in its response. Two fresh tunnels must pay shared
	// byte debt even when each individual response fits in the initial batch.
	uri := "/?payload=" + strings.Repeat("x", 16*1024)
	measure := func(scheme string) float64 {
		t.Helper()
		total := 0.0
		for range 2 {
			stdout, stderr, err := externalCurl(
				ctx,
				"-fk",
				"--http1.1",
				"--max-time",
				"30",
				"-o",
				"/dev/null",
				"-w",
				"%{http_code} %{time_total}",
				scheme+"://"+target+uri,
			)
			if err != nil {
				t.Fatalf("%s transfer: %v: %s", scheme, err, stderr)
			}
			fields := strings.Fields(stdout)
			if len(fields) != 2 || fields[0] != "200" {
				t.Fatalf("curl result: %q", stdout)
			}
			elapsed, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				t.Fatal(err)
			}
			total += elapsed
		}
		return total
	}
	for _, scheme := range []string{"http", "https"} {
		if elapsed := measure(scheme); elapsed < 1.5 {
			t.Fatalf("%s bypassed shared bandwidth budget: %gs", scheme, elapsed)
		}
	}
	applyNetworkLimits(t, environment, scope, 8, 16*1024*1024)
	if elapsed := measure("http"); elapsed >= 1.5 {
		t.Fatalf("updated bandwidth rate not applied: %gs", elapsed)
	}
}
