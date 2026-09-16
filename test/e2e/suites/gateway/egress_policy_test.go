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
//
// runScenario restores the global ConfigMap after every case.

package gateway

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/network"
	"github.com/openkruise/agentio/test/e2e/retry"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func TestEgressPolicy(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server

	dstAddr := dst.ServiceIPOrFail(t)
	dstCIDR, err := network.HostCIDR(dstAddr)
	if err != nil {
		t.Fatal(err)
	}
	dstFQDN := dst.Address()

	rig.RunScenario(t, "gateway all", func(t *testing.T, scope *kube.ResourceScope) {
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
    - policy: GATEWAY
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), hasEnvoyResponseHeader()))))
	})

	rig.RunScenario(t, "passthrough all", func(t *testing.T, scope *kube.ResourceScope) {
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
    - policy: PASSTHROUGH
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), noEnvoyResponseHeader()))))
	})

	rig.RunScenario(t, "match_cidrs gateway", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
			"DstCIDR":   dstCIDR,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - matchCidrs:
      - "{{ .DstCIDR }}"
      policy: GATEWAY
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
    - policy: PASSTHROUGH
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), hasEnvoyResponseHeader()))))
	})

	rig.RunScenario(t, "match_ports gateway", func(t *testing.T, scope *kube.ResourceScope) {
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
      policy: GATEWAY
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
    - policy: PASSTHROUGH
`)

		t.Run("matched port uses gateway", func(t *testing.T) {
			src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), hasEnvoyResponseHeader()))))
		})

		t.Run("unmatched port passes through", func(t *testing.T) {
			src.CallOrFail(t, withEgressPolicyRetry(
				dst.CallOptionsOrFail(t, "auto-http").WithCheck(check.And(check.OK(), noEnvoyResponseHeader())),
			))
		})
	})

	rig.RunScenario(t, "match_hosts gateway with passthrough fallback", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
			"DstHost":   dstFQDN,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - matchHosts:
      - "{{ .DstHost }}"
      policy: GATEWAY
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
    - policy: PASSTHROUGH
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), hasEnvoyResponseHeader()))))
	})

	rig.RunScenario(t, "match_hosts passthrough for unmatched host", func(t *testing.T, scope *kube.ResourceScope) {
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
    - matchHosts:
      - "nonexistent.example.com"
      policy: GATEWAY
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
    - policy: PASSTHROUGH
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), noEnvoyResponseHeader()))))
	})

	rig.RunScenario(t, "match_hosts gateway by hostname", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
			"DstHost":   dstFQDN,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - matchHosts:
      - "{{ .DstHost }}"
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    - policy: PASSTHROUGH
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.And(
			check.OK(),
			hasEnvoyResponseHeader(),
		))))
	})

	rig.RunScenario(t, "match_hosts with external domain", func(t *testing.T, scope *kube.ResourceScope) {
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
    - matchHosts:
      - "www.example.com"
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    - policy: PASSTHROUGH
`)

		src.CallOrFail(t, withEgressPolicyRetry(echo.CallOptions{
			Protocol:        echo.HTTP,
			Address:         "www.example.com",
			Port:            80,
			FollowRedirects: true,
			Check:           check.OK(),
		}))
	})

	rig.RunScenario(t, "match_hosts combined with match_ports", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
			"DstHost":   dstFQDN,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - matchHosts:
      - "{{ .DstHost }}"
      matchPorts:
      - "80"
      policy: GATEWAY
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
    - policy: PASSTHROUGH
`)

		t.Run("matched host+port uses gateway", func(t *testing.T) {
			src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), hasEnvoyResponseHeader()))))
		})

		t.Run("matched host but unmatched port passes through", func(t *testing.T) {
			src.CallOrFail(t, withEgressPolicyRetry(
				dst.CallOptionsOrFail(t, "auto-http").WithCheck(check.And(check.OK(), noEnvoyResponseHeader())),
			))
		})
	})

	rig.RunScenario(t, "unresolvable match_hosts does not wildcard route", func(t *testing.T, scope *kube.ResourceScope) {
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
    - matchHosts:
      - "this-domain-does-not-exist.invalid"
      policy: GATEWAY
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
    - policy: PASSTHROUGH
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), noEnvoyResponseHeader()))))
	})

	rig.RunScenario(t, "policy ordering first match wins", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
			"DstCIDR":   dstCIDR,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - matchCidrs:
      - "{{ .DstCIDR }}"
      policy: PASSTHROUGH
    - policy: GATEWAY
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
`)

		src.CallOrFail(t, withEgressPolicyRetry(trafficFixture.AnotherServer.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), hasEnvoyResponseHeader()))))
		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), noEnvoyResponseHeader()))))
	})

	rig.RunScenario(t, "namespace scoped policy", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace":    resolvedAgentioConfig.Namespace,
			"SrcNamespace": src.Namespace(),
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - namespaces:
      - "{{ .SrcNamespace }}"
      policy: GATEWAY
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
    - policy: PASSTHROUGH
`)

		t.Run("traffic from matching namespace uses gateway", func(t *testing.T) {
			src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), hasEnvoyResponseHeader()))))
		})
	})
}

// Access control is independent of the gateway/passthrough routing decision.
func TestTrafficPolicyWithEgressRouting(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src, dst := trafficFixture.Client, trafficFixture.Server
	for _, tc := range []struct{ name, peer, ports, allowedPort string }{
		{name: "deny all", peer: `cidr: "0.0.0.0/0"`},
		{name: "deny destination CIDR", peer: fmt.Sprintf("cidr: %q", dst.ServiceIPOrFail(t))},
		{name: "deny destination hostname", peer: fmt.Sprintf("fqdn: %q", dst.Address())},
		{name: "deny matching port", peer: `cidr: "0.0.0.0/0"`, ports: "        ports:\n          - protocol: TCP\n            port: 80", allowedPort: "auto-http"},
	} {
		rig.RunScenario(t, tc.name, func(t *testing.T, scope *kube.ResourceScope) {
			rig.ApplyConfig(t, scope, map[string]any{"Namespace": resolvedAgentioConfig.Namespace}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - policy: GATEWAY
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
`)
			src.CallOrFail(t, withEgressPolicyRetry(echo.CallOptionsForAddress(echo.HTTP, dst.ServiceIPOrFail(t), 80).WithCheck(check.And(check.OK(), hasEnvoyResponseHeader()))))
			e2econfig.New(scope).Eval(src.Namespace(), map[string]any{"App": src.Name(), "Peer": tc.peer, "Ports": tc.ports}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-routing-deny
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - {{ .Peer }}
{{ .Ports }}
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
			// Use an IP so a DNS failure cannot masquerade as the HTTP denial.
			src.CallOrFail(t, withEgressPolicyRetry(echo.CallOptionsForAddress(echo.HTTP, dst.ServiceIPOrFail(t), 80).WithCheck(check.Error())))
			trafficFixture.AnotherServer.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), hasEnvoyResponseHeader()))))
			if tc.allowedPort != "" {
				src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, tc.allowedPort).WithCheck(check.And(check.OK(), hasEnvoyResponseHeader()))))
			} else if tc.name != "deny all" {
				src.CallOrFail(t, withEgressPolicyRetry(trafficFixture.AnotherServer.CallOptionsOrFail(t, "http").WithCheck(check.And(check.OK(), hasEnvoyResponseHeader()))))
			}
		})
	}
}

func withEgressPolicyRetry(options echo.CallOptions) echo.CallOptions {
	options.Retry = retry.Policy{
		Timeout:  2 * time.Minute,
		Delay:    5 * time.Second,
		Backoff:  1,
		MaxDelay: 5 * time.Second,
		Converge: 1,
	}
	return options
}

// hasEnvoyResponseHeader asserts at least one x-envoy-* header is present
// in the response the client received — envoy injects headers like
// x-envoy-upstream-service-time when it proxies the call back.
func hasEnvoyResponseHeader() echo.Checker {
	return check.Each(func(response echo.Response) error {
		for key := range response.ResponseHeaders {
			if strings.HasPrefix(strings.ToLower(key), "x-envoy-") {
				return nil
			}
		}
		return fmt.Errorf("expected an x-envoy-* response header (proxied via envoy gateway), got: %v", response.ResponseHeaders)
	})
}
