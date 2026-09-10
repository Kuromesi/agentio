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

	harness.RunGatewayExtProc(t, src, dst)
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

	harness.RunGatewayTraffic(t, src, dst, hasEnvoyResponseHeader(), check.NoError(), func(t *testing.T, id, authority string) { waitForGatewayAccessLog(t, environment, id, authority) })
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

	harness.RunGatewayMatchPorts(t, src, dst, hasEnvoyResponseHeader(), noEnvoyResponseHeader())
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
