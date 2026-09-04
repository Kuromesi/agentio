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
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/openkruise/agentio/test/e2e"
	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

var suite *e2e.Suite
var resolvedAgentioConfig agentiocomponent.Config
var agentioInstance agentiocomponent.Instance
var rig *harness.Harness

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
	resolvedAgentioConfig = agentioConfig

	suite = e2e.NewSuite(e2e.SuiteSpec{Name: "gateway"}, frameworkConfig)
	rig = harness.New(suite, agentioConfig)
	for _, collector := range agentiocomponent.Collectors(agentioConfig) {
		suite.RegisterCollector(collector)
	}
	for _, setup := range suiteSetupGraph(agentioConfig) {
		suite.Setup(setup.name, setup.setup)
	}
	os.Exit(suite.Run(m))
}
