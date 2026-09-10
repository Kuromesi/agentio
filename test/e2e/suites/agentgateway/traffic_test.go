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

package agentgateway

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func routeTraffic(t *testing.T, scope *kube.ResourceScope, ports bool) {
	t.Helper()
	match := ""
	if ports {
		match = "      matchPorts: [\"80\"]\n"
	}
	rig.ApplyConfig(t, scope, map[string]any{"Namespace": config.Namespace}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
    egressPolicies:
    - policy: GATEWAY
`+match+`      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
`)
}

func TestSandboxTraffic(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	routeTraffic(t, scope, false)
	harness.RunGatewayTraffic(t, traffic.Client, traffic.Server, check.ResponseHeader(marker, "agentgateway"), check.RequestHeader(marker, "agentgateway"), nil)
}

func TestSandboxExtProc(t *testing.T) {
	env, scope := rig.BeginScenario(t)
	routeTraffic(t, scope, false)
	// This is a native agentgateway policy, not translation of sandboxExtProc.
	applyNative(t, env, gatewayName, nativeConfig("extproc", true))
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if _, err := env.Kube.Apply(ctx, configuration(gatewayName, nativeConfig("baseline", false)), kube.ReconcileOwned); err != nil {
			t.Error(err)
			return
		}
		if err := waitConfigReady(ctx, env, gatewayName, nativeConfig("baseline", false)); err != nil {
			t.Error(err)
		}
	})
	harness.RunGatewayExtProc(t, traffic.Client, traffic.Server)
}

func TestSandboxMatchPorts(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	routeTraffic(t, scope, true)
	bypass := check.Each(func(r echo.Response) error {
		if r.ResponseHeaders.Get(marker) != "" || r.RequestHeaders.Get(marker) != "" {
			return fmt.Errorf("unmatched port unexpectedly traversed agentgateway: %v", r.ResponseHeaders)
		}
		return nil
	})
	harness.RunGatewayMatchPorts(t, traffic.Client, traffic.Server, check.ResponseHeader(marker, "agentgateway"), bypass)
}

func applyNative(t *testing.T, env *e2e.Environment, name, content string) {
	t.Helper()
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	if _, err := env.Kube.Apply(ctx, configuration(name, content), kube.ReconcileOwned); err != nil {
		t.Fatal(err)
	}
	if err := waitConfigReady(ctx, env, name, content); err != nil {
		t.Fatal(err)
	}
}
