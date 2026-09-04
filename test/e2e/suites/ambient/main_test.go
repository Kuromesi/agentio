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

package ambient

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/openkruise/agentio/test/e2e"
	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/namespace"
)

var (
	suite                 *e2e.Suite
	resolvedAgentioConfig agentiocomponent.Config
	ambientNamespace      namespace.Instance
	ambientClient         echo.Instance
	ambientServer         echo.Instance
)

func TestMain(m *testing.M) {
	frameworkInputs := e2e.RegisterFlags(flag.CommandLine)
	agentioInputs := agentiocomponent.RegisterFlags(flag.CommandLine)
	flag.Parse()
	if os.Getenv("AGENTIO_E2E") != "1" {
		os.Exit(m.Run())
	}

	frameworkConfig, err := e2e.ResolveConfig(frameworkInputs, e2e.DefaultConfig())
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve E2E framework configuration: %v\n", err)
		os.Exit(2)
	}
	agentioConfig, err := agentiocomponent.ResolveConfig(agentioInputs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve Agentio E2E configuration: %v\n", err)
		os.Exit(2)
	}
	if agentioConfig.Profile != "ambient" {
		fmt.Fprintf(os.Stderr, "ambient suite requires agentio profile ambient, got %q\n", agentioConfig.Profile)
		os.Exit(2)
	}
	resolvedAgentioConfig = agentioConfig

	suite = e2e.NewSuite(e2e.SuiteSpec{Name: "ambient"}, frameworkConfig)
	for _, collector := range agentiocomponent.Collectors(agentioConfig) {
		suite.RegisterCollector(collector)
	}
	suite.Setup("agentio", agentiocomponent.Setup(nil, agentioConfig))
	suite.Setup("ambient-namespace", setupAmbientNamespace())
	suite.Setup("ambient-client", setupAmbientEcho(&ambientClient, "client"))
	suite.Setup("ambient-server", setupAmbientEcho(&ambientServer, "server"))
	os.Exit(suite.Run(m))
}

func setupAmbientNamespace() e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		instance, cleanup, err := namespace.Apply(ctx, environment, namespace.Config{Prefix: "ambient"})
		if err == nil {
			ambientNamespace = instance
		}
		return cleanup, err
	}
}

func setupAmbientEcho(target *echo.Instance, name string) e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		instance, cleanup, err := echo.Apply(ctx, environment, echo.Config{
			Name: name, Namespace: ambientNamespace.Name(), Image: echo.DefaultImage,
			Ports: echo.DefaultPorts(), Labels: map[string]string{
				"app": name, "agentio.kruise.io/dataplane-mode": "ambient",
			},
		})
		if err == nil {
			*target = instance
		}
		return cleanup, err
	}
}
