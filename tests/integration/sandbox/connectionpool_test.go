//go:build integ

package sandbox

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/cluster"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	testKube "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/util/retry"
)

// TestSandboxConnectionPool verifies that ConnectionPoolSettings in the
// sandbox-config ConfigMap propagate to the egress gateway's Envoy
// configuration. Each subtest applies a sandbox-config with specific
// connection_pool values, then fetches the egress gateway's config_dump
// and asserts that the Envoy listeners, HCM, and routes reflect the
// configured timeouts, retries, and per-host overrides.
func getEgressGatewayConfigDump(ctx framework.TestContext) (string, error) {
	sysNS := i.Settings().SystemNamespace
	cluster := ctx.Clusters().Default()
	fetchFn := testKube.NewPodFetch(cluster, sysNS, "gateway.networking.k8s.io/gateway-name=egress-gateway")
	pods, err := testKube.CheckPodsAreReady(fetchFn)
	if err != nil {
		return "", fmt.Errorf("egress gateway pods not ready: %v", err)
	}
	if len(pods) == 0 {
		return "", fmt.Errorf("no egress gateway pods found")
	}
	podName := pods[0].Name
	stdout, stderr, err := cluster.PodExec(podName, sysNS, "istio-proxy",
		"curl -sS localhost:15000/config_dump")
	if err != nil {
		return "", fmt.Errorf("config_dump failed: %v, stderr: %s", err, stderr)
	}
	if strings.Contains(stdout, "error_state") {
		return "", fmt.Errorf("config_dump contains error_state, xDS push rejected by Envoy")
	}
	return stdout, nil
}

func curlHTTPCodeFromPod(cluster cluster.Cluster, namespace, podLabel, container, url string) (int, error) {
	fetchFn := testKube.NewPodFetch(cluster, namespace, podLabel)
	pods, err := testKube.CheckPodsAreReady(fetchFn)
	if err != nil || len(pods) == 0 {
		return 0, fmt.Errorf("pods not ready for %s: %v", podLabel, err)
	}
	stdout, stderr, err := cluster.PodExec(pods[0].Name, namespace, container,
		fmt.Sprintf("curl -sS -o /dev/null -w %%{http_code} --connect-timeout 3 --max-time 10 %s", url))
	if err != nil {
		return 0, fmt.Errorf("curl failed: %v, stderr: %s", err, stderr)
	}
	code := 0
	if _, err := fmt.Sscanf(stdout, "%d", &code); err != nil {
		return 0, fmt.Errorf("failed to parse curl http_code %q: %v", stdout, err)
	}
	return code, nil
}

func TestSandboxConnectionPool(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			sysNS := i.Settings().SystemNamespace

			ctx.NewSubTest("stream idle timeout").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(sysNS, map[string]any{
						"Namespace": sysNS,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      connectionPool:
        http:
          streamIdleTimeout: 600s
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						dump, err := getEgressGatewayConfigDump(ctx)
						if err != nil {
							return err
						}
						if !containsStreamIdleTimeout(dump, 600) {
							return fmt.Errorf("config_dump does not have stream_idle_timeout=600s")
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(200*time.Millisecond))
				})

			ctx.NewSubTest("tcp idle timeout and max connection duration").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(sysNS, map[string]any{
						"Namespace": sysNS,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
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
        - "*.example.com"
      connectionPool:
        tcp:
          idleTimeout: 1800s
          maxConnectionDuration: 7200s
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						dump, err := getEgressGatewayConfigDump(ctx)
						if err != nil {
							return err
						}
						if !containsTCPIdleTimeout(dump, 1800) {
							return fmt.Errorf("config_dump does not have tcp idle_timeout=1800s")
						}
						if !containsMaxConnectionDuration(dump, 7200) {
							return fmt.Errorf("config_dump does not have max_downstream_connection_duration=7200s")
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(200*time.Millisecond))
				})

			ctx.NewSubTest("default route timeout").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(sysNS, map[string]any{
						"Namespace": sysNS,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      connectionPool:
        http:
          streamIdleTimeout: 600s
          defaultRoute:
            timeout: 30s
            retries:
              attempts: 3
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						dump, err := getEgressGatewayConfigDump(ctx)
						if err != nil {
							return err
						}
						if !containsRouteTimeout(dump, "sandbox|default|", 30) {
							return fmt.Errorf("config_dump does not have default route timeout=30s")
						}
						if !containsRetryPolicy(dump, "sandbox|default|", 3) {
							return fmt.Errorf("config_dump does not have default route num_retries=3")
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(200*time.Millisecond))
				})

			ctx.NewSubTest("per-host route overrides").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(sysNS, map[string]any{
						"Namespace": sysNS,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      connectionPool:
        http:
          streamIdleTimeout: 600s
          defaultRoute:
            timeout: 30s
          routeOverrides:
          - hosts:
            - "api.example.com"
            - "*.api.example.com"
            settings:
              timeout: 120s
              retries:
                attempts: 5
                perTryTimeout: 10s
                retryOn: "connect-failure,refused-stream"
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						dump, err := getEgressGatewayConfigDump(ctx)
						if err != nil {
							return err
						}
						if !strings.Contains(dump, "sandbox|override|0") {
							return fmt.Errorf("config_dump does not contain sandbox|override|0 virtual host")
						}
						if !strings.Contains(dump, "api.example.com") {
							return fmt.Errorf("config_dump does not contain api.example.com domain")
						}
						if !containsRouteTimeout(dump, "sandbox|override|0", 120) {
							return fmt.Errorf("config_dump does not have override route timeout=120s")
						}
						if !containsRetryPolicy(dump, "sandbox|override|0", 5) {
							return fmt.Errorf("config_dump does not have override route num_retries=5")
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(200*time.Millisecond))
				})

			ctx.NewSubTest("full connection pool settings").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(sysNS, map[string]any{
						"Namespace": sysNS,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
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
        - "*.example.com"
      connectionPool:
        tcp:
          idleTimeout: 3600s
          maxConnectionDuration: 14400s
        http:
          streamIdleTimeout: 900s
          defaultRoute:
            timeout: 60s
            retries:
              attempts: 2
          routeOverrides:
          - hosts:
            - "slow.example.com"
            settings:
              timeout: 300s
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						dump, err := getEgressGatewayConfigDump(ctx)
						if err != nil {
							return err
						}
						if !containsStreamIdleTimeout(dump, 900) {
							return fmt.Errorf("config_dump does not have stream_idle_timeout=900s")
						}
						if !containsTCPIdleTimeout(dump, 3600) {
							return fmt.Errorf("config_dump does not have tcp idle_timeout=3600s")
						}
						if !containsMaxConnectionDuration(dump, 14400) {
							return fmt.Errorf("config_dump does not have max_downstream_connection_duration=14400s")
						}
						if !containsRouteTimeout(dump, "sandbox|default|", 60) {
							return fmt.Errorf("config_dump does not have default route timeout=60s")
						}
						if !strings.Contains(dump, "slow.example.com") {
							return fmt.Errorf("config_dump does not contain slow.example.com domain")
						}
						if !containsRouteTimeout(dump, "sandbox|override|0", 300) {
							return fmt.Errorf("config_dump does not have override route timeout=300s")
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(200*time.Millisecond))
				})

			ctx.NewSubTest("defaults when no connection pool configured").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(sysNS, map[string]any{
						"Namespace": sysNS,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						dump, err := getEgressGatewayConfigDump(ctx)
						if err != nil {
							return err
						}
						// Default stream_idle_timeout is 30min = 1800s
						if !containsStreamIdleTimeout(dump, 1800) {
							return fmt.Errorf("config_dump does not have default stream_idle_timeout=1800s (30min)")
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(200*time.Millisecond))
				})
		})
}

func TestSandboxConnectionPoolTimeout(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			src := all[0]
			dst := all[1]
			sysNS := i.Settings().SystemNamespace
			targetHost := dst.Config().ClusterLocalFQDN()

			ctx.ConfigIstio().Eval(sysNS, map[string]any{
				"Namespace":  sysNS,
				"TargetHost": targetHost,
			}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      connectionPool:
        http:
          streamIdleTimeout: 600s
          routeOverrides:
          - hosts:
            - "{{ .TargetHost }}"
            settings:
              timeout: 1s
`).ApplyOrFail(ctx)

			retry.UntilSuccessOrFail(ctx, func() error {
				dump, err := getEgressGatewayConfigDump(ctx)
				if err != nil {
					return err
				}
				if !strings.Contains(dump, "sandbox|override|0") {
					return fmt.Errorf("sandbox route config not yet propagated")
				}
				if !strings.Contains(dump, targetHost) {
					return fmt.Errorf("sandbox route config for %q not yet propagated", targetHost)
				}
				return nil
			}, retry.Timeout(2*time.Minute), retry.Delay(200*time.Millisecond))

			ctx.NewSubTest("route timeout triggers 504 on slow upstream").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							Address: targetHost,
							Port: echo.Port{
								ServicePort: 80,
								Protocol:    protocol.HTTP,
							},
							HTTP: echo.HTTP{
								Path: "/?delay=5s",
							},
							Timeout: 10 * time.Second,
							Check:   check.Status(504),
						})
						return err
					}, retry.Timeout(30*time.Second), retry.Delay(200*time.Millisecond))
				})

			ctx.NewSubTest("requests within timeout succeed").
				Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						_, err := src.Call(echo.CallOptions{
							Address: targetHost,
							Port: echo.Port{
								ServicePort: 80,
								Protocol:    protocol.HTTP,
							},
							HTTP: echo.HTTP{
								Path: "/",
							},
							Timeout: 10 * time.Second,
							Check:   check.OK(),
						})
						return err
					}, retry.Timeout(30*time.Second), retry.Delay(200*time.Millisecond))
				})
		})
}

func TestSandboxRateLimit(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			sysNS := i.Settings().SystemNamespace

			ctx.NewSubTest("global token bucket").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(sysNS, map[string]any{
						"Namespace": sysNS,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
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
          maxTokens: 100
          tokensPerFill: 100
          fillInterval: 1s
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						dump, err := getEgressGatewayConfigDump(ctx)
						if err != nil {
							return err
						}
						if !strings.Contains(dump, "connect_rate_limit") {
							return fmt.Errorf("config_dump does not contain rate limit stat_prefix")
						}
						if !strings.Contains(dump, "envoy.filters.http.local_ratelimit") {
							return fmt.Errorf("config_dump does not contain local_ratelimit filter")
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(200*time.Millisecond))
				})

			ctx.NewSubTest("per-client CEL descriptor bucketing").
				Run(func(ctx framework.TestContext) {
					dst := all[2] // "another-server"
					targetHost := dst.Config().ClusterLocalFQDN()

					ctx.ConfigIstio().Eval(sysNS, map[string]any{
						"Namespace": sysNS,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
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
        descriptors:
        - entries:
          - key: peer_name
            value: ""
            cel: 'filter_state["downstream_peer"].name'
          tokenBucket:
            maxTokens: 1
            tokensPerFill: 1
            fillInterval: 30s
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						dump, err := getEgressGatewayConfigDump(ctx)
						if err != nil {
							return err
						}
						if !strings.Contains(dump, "connect_rate_limit") {
							return fmt.Errorf("rate limit filter not yet in config_dump")
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(1*time.Second))

					cluster := ctx.Clusters().Default()
					curlFromPod := func(podLabel string) (int, error) {
						return curlHTTPCodeFromPod(cluster, ns.Name(), podLabel, "app", fmt.Sprintf("http://%s:80/", targetHost))
					}

					// Client A (app=client): retry until first request succeeds
					retry.UntilSuccessOrFail(ctx, func() error {
						code, err := curlFromPod("app=client")
						if err != nil {
							return err
						}
						if code != 200 {
							return fmt.Errorf("client A got %d, want 200", code)
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(2*time.Second))

					// Client A: 2nd request → bucket empty (30s refill) → expect failure
					retry.UntilSuccessOrFail(ctx, func() error {
						code, err := curlFromPod("app=client")
						if err != nil {
							return nil
						}
						return fmt.Errorf("client A 2nd request should be rate limited, got %d", code)
					}, retry.Timeout(30*time.Second), retry.Delay(2*time.Second))

					// Client B (app=server): first request should succeed (separate bucket)
					retry.UntilSuccessOrFail(ctx, func() error {
						code, err := curlFromPod("app=server")
						if err != nil {
							return err
						}
						if code != 200 {
							return fmt.Errorf("client B got %d, want 200", code)
						}
						return nil
					}, retry.Timeout(30*time.Second), retry.Delay(2*time.Second))
				})

			ctx.NewSubTest("rate limit enforced").
				Run(func(ctx framework.TestContext) {
					src := all[2]
					dst := all[1]
					targetHost := dst.Config().ClusterLocalFQDN()

					ctx.ConfigIstio().Eval(sysNS, map[string]any{
						"Namespace": sysNS,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
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
          maxTokens: 1
          tokensPerFill: 1
          fillInterval: 60s
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						dump, err := getEgressGatewayConfigDump(ctx)
						if err != nil {
							return err
						}
						if !strings.Contains(dump, "connect_rate_limit") {
							return fmt.Errorf("rate limit config not yet propagated")
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(200*time.Millisecond))

					cluster := ctx.Clusters().Default()
					curlFromPod := func(podLabel string) (int, error) {
						return curlHTTPCodeFromPod(cluster, ns.Name(), podLabel, "app", fmt.Sprintf("http://%s:80/", targetHost))
					}

					// First request should succeed (consumes the single token)
					retry.UntilSuccessOrFail(ctx, func() error {
						code, err := curlFromPod(fmt.Sprintf("app=%s", src.Config().Service))
						if err != nil {
							return err
						}
						if code != 200 {
							return fmt.Errorf("first request got %d, want 200", code)
						}
						return nil
					}, retry.Timeout(30*time.Second), retry.Delay(200*time.Millisecond))

					// Subsequent request should be rate limited (429)
					retry.UntilSuccessOrFail(ctx, func() error {
						code, err := curlFromPod(fmt.Sprintf("app=%s", src.Config().Service))
						if err != nil {
							return nil
						}
						return fmt.Errorf("second request should be rate limited, got %d", code)
					}, retry.Timeout(30*time.Second), retry.Delay(200*time.Millisecond))
				})

			ctx.NewSubTest("no rate limit when not configured").
				Run(func(ctx framework.TestContext) {
					ctx.ConfigIstio().Eval(sysNS, map[string]any{
						"Namespace": sysNS,
					}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + sandboxConfigMapName + `
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
`).ApplyOrFail(ctx)

					retry.UntilSuccessOrFail(ctx, func() error {
						dump, err := getEgressGatewayConfigDump(ctx)
						if err != nil {
							return err
						}
						if strings.Contains(dump, "connect_rate_limit") {
							return fmt.Errorf("config_dump should NOT contain rate limit when not configured")
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(200*time.Millisecond))
				})
		})
}

// --- config_dump JSON parsing helpers ---

func containsJSONField(dump, field string, seconds int) bool {
	val := fmt.Sprintf("%ds", seconds)
	compact := fmt.Sprintf(`"%s":"%s"`, field, val)
	pretty := fmt.Sprintf(`"%s": "%s"`, field, val)
	return strings.Contains(dump, compact) || strings.Contains(dump, pretty)
}

func containsStreamIdleTimeout(dump string, seconds int) bool {
	return containsJSONField(dump, "stream_idle_timeout", seconds)
}

func containsTCPIdleTimeout(dump string, seconds int) bool {
	return containsJSONField(dump, "idle_timeout", seconds)
}

func containsMaxConnectionDuration(dump string, seconds int) bool {
	return containsJSONField(dump, "max_downstream_connection_duration", seconds)
}

func containsRouteTimeout(dump string, vhostPrefix string, seconds int) bool {
	idx := strings.Index(dump, vhostPrefix)
	if idx < 0 {
		return false
	}
	section := dump[idx:]
	return containsJSONField(section, "timeout", seconds)
}

func containsRetryPolicy(dump string, vhostPrefix string, numRetries int) bool {
	idx := strings.Index(dump, vhostPrefix)
	if idx < 0 {
		return false
	}
	section := dump[idx:]
	target := fmt.Sprintf(`"num_retries": %d`, numRetries)
	return strings.Contains(section, target)
}
