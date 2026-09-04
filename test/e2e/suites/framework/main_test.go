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

package framework

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/openkruise/agentio/test/e2e"
)

var suite *e2e.Suite

func TestMain(m *testing.M) {
	inputs := e2e.RegisterFlags(flag.CommandLine)
	flag.Parse()
	if os.Getenv("E2E_FRAMEWORK_SMOKE") != "1" {
		os.Exit(m.Run())
	}
	config, err := e2e.ResolveConfig(inputs, e2e.DefaultConfig())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	suite = e2e.NewSuite(e2e.SuiteSpec{Name: "framework-smoke"}, config)
	os.Exit(suite.Run(m))
}
