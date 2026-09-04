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

package securitypolicy

import (
	"context"
	"fmt"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/namespace"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

const sniPolicyLabel = "sni-policy-test"

type suiteSetup struct {
	name  string
	setup e2e.SetupFunc
}

var sniFixture struct {
	localNamespace  namespace.Instance
	globalNamespace namespace.Instance
	selected        echo.Instance
	unselected      echo.Instance
	global          echo.Instance
}

func suiteSetupGraph(config agentiocomponent.Config) []suiteSetup {
	return []suiteSetup{
		{name: "agentio", setup: agentiocomponent.Setup(&agentioInstance, config)},
		{name: "agentio-baseline", setup: harness.SetupBaseline(config.Namespace)},
		{name: "sni-policy-namespace", setup: setupSNINamespace(config.Profile, false)},
		{name: "sni-policy-global-namespace", setup: setupSNINamespace(config.Profile, true)},
		{name: "sni-policy-selected", setup: setupSNIEcho("selected", false, "selected")},
		{name: "sni-policy-unselected", setup: setupSNIEcho("unselected", false, "unselected")},
		{name: "sni-policy-global", setup: setupSNIEcho("global", true, "global")},
		{name: "fixture-readiness", setup: verifyFixtureReadiness(config)},
	}
}

func setupSNINamespace(profile string, global bool) e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		prefix := "sni-policy"
		if global {
			prefix = "sni-policy-global"
		}
		config, err := harness.DataplaneNamespaceConfig(profile, prefix)
		if err != nil {
			return nil, err
		}
		instance, cleanup, err := namespace.Apply(ctx, environment, config)
		if err != nil {
			return nil, err
		}
		if global {
			sniFixture.globalNamespace = instance
		} else {
			sniFixture.localNamespace = instance
		}
		return cleanup, nil
	}
}

func sniEchoConfig(name, namespaceName, policyValue string) echo.Config {
	return echo.Config{
		Name: name, Namespace: namespaceName, Image: echo.DefaultImage, Ports: echo.DefaultPorts(),
		CallTimeout: 90 * time.Second, Converge: 3,
		Labels: map[string]string{
			"app": name, sniPolicyLabel: policyValue,
		},
		Capabilities: harness.ClientCapabilities(),
	}
}

func setupSNIEcho(name string, global bool, policyValue string) e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		namespaceName := sniFixture.localNamespace.Name()
		if global {
			namespaceName = sniFixture.globalNamespace.Name()
		}
		config := sniEchoConfig(name, namespaceName, policyValue)
		instance, cleanup, err := echo.Apply(ctx, environment, config)
		if err != nil {
			return nil, err
		}
		switch name {
		case "selected":
			sniFixture.selected = instance
		case "unselected":
			sniFixture.unselected = instance
		case "global":
			sniFixture.global = instance
		default:
			return nil, fmt.Errorf("unknown shared SNI echo fixture %q", name)
		}
		return cleanup, nil
	}
}

func verifyFixtureReadiness(config agentiocomponent.Config) e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		checks := []struct {
			name, namespace, selector string
		}{
			{name: "egress gateway", namespace: config.Namespace, selector: harness.GatewayPodSelector},
			{name: "selected SNI client", namespace: sniFixture.localNamespace.Name(), selector: "app=selected"},
			{name: "unselected SNI client", namespace: sniFixture.localNamespace.Name(), selector: "app=unselected"},
			{name: "global SNI client", namespace: sniFixture.globalNamespace.Name(), selector: "app=global"},
		}
		waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		for _, fixture := range checks {
			if _, err := environment.Kube.WaitReadyPods(waitCtx, fixture.namespace, fixture.selector, 1); err != nil {
				return nil, fmt.Errorf("wait for shared %s fixture: %w", fixture.name, err)
			}
		}
		if err := agentiocomponent.VerifyFirewallBackend(waitCtx, environment, config); err != nil {
			return nil, fmt.Errorf("verify firewall backend: %w", err)
		}
		return nil, nil
	}
}
