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
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// TestSandboxHTTPDFPAuthorityRouting verifies that the sandbox catch-all HTTP
// path selects its upstream from :authority instead of the intercepted original
// destination. TEST-NET-1 is intentionally unreachable; both requests can
// succeed only when DFP uses the supplied hostname or IP literal.
func TestSandboxHTTPDFPAuthorityRouting(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	dstPod := dst.WorkloadsOrFail(t)[0].Name
	dstIP := dst.ServiceIPOrFail(t)

	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    sandboxExtProc:
      service: ext-proc.{{ .Namespace }}.svc.cluster.local
      port: 9002
      failureModeAllow: true
      request:
        headerMode: SEND
      response:
        headerMode: SEND
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
`)

	callAuthority := func(t *testing.T, authority string) {
		t.Helper()
		src.CallOrFail(t, echo.CallOptions{
			Protocol: echo.HTTP,
			Address:  "192.0.2.1",
			Port:     80,
			Count:    1,
			Headers:  map[string]string{"Host": authority},
			Check: check.And(
				check.OK(),
				hostnameIs(dstPod),
				check.RequestHeader("X-Hello-To-Ext-Proc", "true"),
			),
			Retry: harness.FixedRetry(2*time.Minute, 5*time.Second),
		})
	}

	t.Run("hostname authority selects upstream", func(t *testing.T) {
		callAuthority(t, dst.Address())
	})

	t.Run("IP literal authority selects upstream", func(t *testing.T) {
		callAuthority(t, net.JoinHostPort(dstIP, "80"))
	})
}

// TestEgressStaticServiceEntries exercises the route-selected endpoint state
// for static services. The intercepted TEST-NET address cannot reach the echo
// server unless the configured static endpoint replaces it.
func TestEgressStaticServiceEntries(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	dstPod := dst.WorkloadsOrFail(t)[0].Name
	dstIP := dst.ServiceIPOrFail(t)
	const host = "static-entry.example"

	rig.ApplyConfig(t, scope, map[string]any{
		"Endpoint":  dstIP,
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
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
      serviceEntries:
      - hosts:
        - `+host+`
        endpoints:
        - address: {{ .Endpoint }}
`)

	waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
		for _, want := range []string{"sandbox|service-entry|0|0", host, dstIP} {
			if !strings.Contains(dump, want) {
				return fmt.Errorf("gateway config_dump does not contain %q", want)
			}
		}
		return nil
	})

	src.CallOrFail(t, echo.CallOptions{
		Protocol: echo.HTTP,
		Address:  "192.0.2.1",
		Port:     80,
		Count:    1,
		Headers:  map[string]string{"Host": net.JoinHostPort(host, "80")},
		Check:    check.And(check.OK(), hostnameIs(dstPod), hasEnvoyResponseHeader()),
		Retry:    harness.FixedRetry(2*time.Minute, 5*time.Second),
	})
}

func TestSandboxExtProc(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server

	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    sandboxExtProc:
      service: ext-proc.{{ .Namespace }}.svc.cluster.local
      port: 9002
      failureModeAllow: true
      request:
        headerMode: SEND
      response:
        headerMode: SEND
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
`)

	options := dst.CallOptionsOrFail(t, "http")
	options.Count = 1
	options.Check = check.And(
		check.OK(),
		check.RequestHeader("X-Hello-To-Ext-Proc", "true"),
		check.ResponseHeader("X-Hello-From-Ext-Proc", "true"),
	)
	options.Retry = harness.FixedRetry(2*time.Minute, 5*time.Second)
	src.CallOrFail(t, options)
}

func TestSandboxTraffic(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server

	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
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
`)

	t.Run("http traffic", func(t *testing.T) {
		options := dst.CallOptionsOrFail(t, "http")
		options.Count = 1
		// Make the first short-lived request the convergence gate for the
		// protocols below. An origin-only success can still be a direct call
		// while the new egress policy is propagating to the data plane.
		options.Check = check.And(check.OK(), hasEnvoyResponseHeader())
		options.Retry = harness.FixedRetry(2*time.Minute, 5*time.Second)
		src.CallOrFail(t, options)
	})

	t.Run("tcp traffic", func(t *testing.T) {
		src.CallOrFail(t, echo.CallOptions{
			Protocol: echo.TCP,
			Address:  dst.Address(),
			Port:     9091,
			Count:    1,
			Check:    check.OK(),
			Retry:    harness.FixedRetry(2*time.Minute, 5*time.Second),
		})
	})

	t.Run("https traffic", func(t *testing.T) {
		src.CallOrFail(t, echo.CallOptions{
			Protocol: echo.HTTPS,
			Address:  dst.Address(),
			Port:     443,
			Count:    1,
			Check:    check.OK(),
			Retry:    harness.FixedRetry(2*time.Minute, 5*time.Second),
		})
	})

	t.Run("grpc connection remains open and traverses gateway", func(t *testing.T) {
		// The catch-all DFP path derives the upstream port from :authority.
		// Carry the service port so the request reaches the gRPC workload port.
		authority := net.JoinHostPort(dst.Address(), "7070")
		requestID := fmt.Sprintf("agentio-e2e-grpc-%d", time.Now().UnixNano())
		started := time.Now()
		src.CallOrFail(t, echo.CallOptions{
			Protocol: echo.GRPC,
			Address:  dst.Address(),
			Port:     7070,
			// Istio's echo client reuses one gRPC connection by default. Pacing 21
			// unary RPCs at one per second holds the same HTTP/2 connection open
			// beyond Envoy's 15-second default request timeout. Every successful
			// unary response also requires its final gRPC status trailer to arrive.
			Count:   21,
			QPS:     1,
			Timeout: 35 * time.Second,
			Headers: map[string]string{
				"Host":         authority,
				"X-Request-Id": requestID,
			},
			Check: check.And(
				check.OK(),
				check.RequestHeader("X-Request-Id", requestID),
			),
			Retry: harness.FixedRetry(45*time.Second, time.Second),
		})
		if elapsed := time.Since(started); elapsed < 20*time.Second {
			t.Fatalf("paced gRPC connection lasted %s, want at least 20s", elapsed)
		}

		// A successful origin response alone could come from direct traffic.
		// The request ID in the gateway's structured access log proves that
		// this exact gRPC request traversed the egress gateway.
		waitForGatewayAccessLog(t, environment, requestID, authority)
	})

	// h2c sits on a separate branch in waypoint's HTTPInspector path from
	// HTTP/1.1; without an explicit case the protocol matcher could misroute
	// upgraded connections into forward-tcp.
	t.Run("http2 (h2c) traffic", func(t *testing.T) {
		// The service port must be present in :authority or the DFP path
		// resolves the scheme default (80) instead of 85.
		src.CallOrFail(t, echo.CallOptions{
			Protocol: echo.HTTP2,
			Address:  dst.Address(),
			Port:     85,
			Count:    1,
			Headers: map[string]string{
				"Host": net.JoinHostPort(dst.Address(), "85"),
			},
			Check: check.OK(),
			Retry: harness.FixedRetry(2*time.Minute, 5*time.Second),
		})
	})
}

// TestSandboxMatchPorts verifies that EgressPolicy.match_ports gates which
// destination ports are routed through the egress gateway. Traffic to a
// matched port should hit the envoy egress gateway (response carries
// x-envoy-* headers like x-envoy-upstream-service-time added by envoy on
// the way back); traffic to an unmatched port should bypass the gateway
// and arrive without those headers.
func TestSandboxMatchPorts(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server

	// Echo's "http" port -> ServicePort 80 (matched).
	// Echo's "http2" port -> ServicePort 85 (not matched, must bypass).
	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - matchPorts:
      - "80"
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
`)

	t.Run("matched port goes through envoy gateway", func(t *testing.T) {
		options := dst.CallOptionsOrFail(t, "http")
		options.Count = 1
		options.Check = check.And(check.OK(), hasEnvoyResponseHeader())
		options.Retry = harness.FixedRetry(2*time.Minute, 5*time.Second)
		src.CallOrFail(t, options)
	})

	t.Run("unmatched port bypasses envoy gateway", func(t *testing.T) {
		options := dst.CallOptionsOrFail(t, "http2")
		options.Count = 1
		options.Check = check.And(check.OK(), noEnvoyResponseHeader())
		options.Retry = harness.FixedRetry(2*time.Minute, 5*time.Second)
		src.CallOrFail(t, options)
	})
}

func hostnameIs(want string) echo.Checker {
	return check.Each(func(response echo.Response) error {
		if response.Hostname != want {
			return fmt.Errorf("hostname = %q, want %q", response.Hostname, want)
		}
		return nil
	})
}

// noEnvoyResponseHeader asserts no x-envoy-* header is present in the
// response -- i.e. the connection bypassed any envoy proxy on the egress path.
func noEnvoyResponseHeader() echo.Checker {
	return check.Each(func(response echo.Response) error {
		for key := range response.ResponseHeaders {
			if strings.HasPrefix(strings.ToLower(key), "x-envoy-") {
				return fmt.Errorf(
					"did not expect x-envoy-* response header (should bypass envoy gateway), got %s=%v",
					key,
					response.ResponseHeaders.Values(key),
				)
			}
		}
		return nil
	})
}
