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
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/openkruise/agentio/test/e2e"
	agentio "github.com/openkruise/agentio/test/e2e/components/agentio"
	"github.com/openkruise/agentio/test/e2e/components/extproc"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

var suite *e2e.Suite
var rig *harness.Harness
var config agentio.Config
var installed agentio.Instance
var traffic harness.TrafficFixture

func TestMain(m *testing.M) {
	frameworkFlags := e2e.RegisterFlags(flag.CommandLine)
	componentFlags := agentio.RegisterFlags(flag.CommandLine)
	flag.Parse()
	if os.Getenv("AGENTIO_E2E") != "1" {
		os.Exit(m.Run())
	}
	framework, err := e2e.ResolveConfig(frameworkFlags, e2e.DefaultConfig())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	config, err = agentio.ResolveConfig(componentFlags)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if config.GatewayDataplane != "agentgateway" {
		fmt.Fprintln(os.Stderr, "this suite requires -agentio.gateway-dataplane=agentgateway and an agentgateway digest image")
		os.Exit(2)
	}
	suite = e2e.NewSuite(e2e.SuiteSpec{Name: "agentgateway"}, framework)
	rig = harness.New(suite, config)
	for _, collector := range agentio.Collectors(config) {
		suite.RegisterCollector(collector)
	}
	suite.Setup("gateway-api", requireGatewayAPI)
	suite.Setup("agentio", agentio.Setup(&installed, config))
	suite.Setup("baseline", harness.SetupBaseline(config.Namespace))
	suite.Setup("namespace", traffic.SetupNamespace(config.Profile))
	suite.Setup("client", traffic.SetupEcho("client", 1, harness.ClientCapabilities()))
	suite.Setup("server", traffic.SetupEcho("server", 1, nil))
	suite.Setup("ext-proc", extproc.Setup(config.Namespace, config.ExtProcImage))
	suite.Setup("gateway", setupGateway)
	os.Exit(suite.Run(m))
}
