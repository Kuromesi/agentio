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

package epe

import (
	"context"
	"fmt"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

type suiteSetup struct {
	name  string
	setup e2e.SetupFunc
}

var trafficFixture harness.TrafficFixture

func suiteSetupGraph(config agentiocomponent.Config) []suiteSetup {
	trafficFixture = harness.TrafficFixture{}
	return []suiteSetup{
		{name: "agentio", setup: agentiocomponent.Setup(&agentioInstance, config)},
		{name: "agentio-baseline", setup: harness.SetupBaseline(config.Namespace)},
		{name: "traffic-policy-namespace", setup: trafficFixture.SetupNamespace(config.Profile)},
		{name: "traffic-policy-client", setup: trafficFixture.SetupEcho("client", 1, harness.ClientCapabilities())},
		{name: "traffic-policy-server", setup: trafficFixture.SetupEcho("server", 1, nil)},
		{name: "fixture-readiness", setup: verifyFixtureReadiness(config.Namespace)},
	}
}

func verifyFixtureReadiness(controlPlaneNamespace string) e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		checks := []struct {
			name, namespace, selector string
		}{
			{name: "egress gateway", namespace: controlPlaneNamespace, selector: harness.GatewayPodSelector},
			{name: "EPE", namespace: controlPlaneNamespace, selector: harness.EPEPodSelector},
		}
		waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		for _, fixture := range checks {
			if _, err := environment.Kube.WaitReadyPods(waitCtx, fixture.namespace, fixture.selector, 1); err != nil {
				return nil, fmt.Errorf("wait for shared %s fixture: %w", fixture.name, err)
			}
		}
		return nil, rig.VerifyTrafficFixture(waitCtx, environment, &trafficFixture)
	}
}
