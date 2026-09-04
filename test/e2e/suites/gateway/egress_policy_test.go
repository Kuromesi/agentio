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

	rig.RunScenario(t, "deny all", func(t *testing.T, scope *kube.ResourceScope) {
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
    - policy: DENY
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.Error())))
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

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.OK())))
	})

	rig.RunScenario(t, "match_cidrs deny", func(t *testing.T, scope *kube.ResourceScope) {
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
      policy: DENY
    - policy: PASSTHROUGH
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.Error())))
	})

	rig.RunScenario(t, "match_ports deny", func(t *testing.T, scope *kube.ResourceScope) {
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
      policy: DENY
    - policy: PASSTHROUGH
`)

		t.Run("matched port is denied", func(t *testing.T) {
			src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.Error())))
		})

		t.Run("unmatched port passes through", func(t *testing.T) {
			src.CallOrFail(t, withEgressPolicyRetry(
				echo.CallOptionsForAddress(echo.TCP, dst.Address(), 9091).WithCheck(check.NoError()),
			))
		})
	})

	rig.RunScenario(t, "match_hosts deny by hostname", func(t *testing.T, scope *kube.ResourceScope) {
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
      policy: DENY
    - policy: PASSTHROUGH
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.Error())))
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
      policy: DENY
    - policy: PASSTHROUGH
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.OK())))
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
			Protocol: echo.HTTP, Address: "www.example.com", Port: 80,
			FollowRedirects: true, Check: check.OK(),
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
      policy: DENY
    - policy: PASSTHROUGH
`)

		t.Run("matched host+port is denied", func(t *testing.T) {
			src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.Error())))
		})

		t.Run("matched host but unmatched port passes through", func(t *testing.T) {
			src.CallOrFail(t, withEgressPolicyRetry(
				echo.CallOptionsForAddress(echo.TCP, dst.Address(), 9091).WithCheck(check.NoError()),
			))
		})
	})

	rig.RunScenario(t, "unresolvable match_hosts does not wildcard deny", func(t *testing.T, scope *kube.ResourceScope) {
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
      policy: DENY
    - policy: PASSTHROUGH
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.OK())))
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
    - policy: DENY
`)

		src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.OK())))
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
      policy: DENY
    - policy: PASSTHROUGH
`)

		t.Run("traffic from matching namespace is denied", func(t *testing.T) {
			src.CallOrFail(t, withEgressPolicyRetry(dst.CallOptionsOrFail(t, "http").WithCheck(check.Error())))
		})
	})
}

func withEgressPolicyRetry(options echo.CallOptions) echo.CallOptions {
	options.Retry = retry.Policy{
		Timeout: 2 * time.Minute, Delay: 5 * time.Second,
		Backoff: 1, MaxDelay: 5 * time.Second, Converge: 1,
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
