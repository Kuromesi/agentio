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
	"os"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	"github.com/openkruise/agentio/test/e2e/components/namespace"
	"github.com/openkruise/agentio/test/e2e/retry"
)

func TestFrameworkSmoke(t *testing.T) {
	if os.Getenv("E2E_FRAMEWORK_SMOKE") != "1" {
		t.Skip("set E2E_FRAMEWORK_SMOKE=1 to run the live Kubernetes framework smoke test")
	}
	environment := suite.Environment(t)
	ns := namespace.Create(t, environment, namespace.Config{Prefix: "framework"})
	server := echo.Deploy(t, environment, echo.Config{Name: "server", Namespace: ns.Name()})
	client := echo.Deploy(t, environment, echo.Config{Name: "client", Namespace: ns.Name()})
	client.CallOrFail(t, echo.CallOptions{
		Protocol: echo.HTTP,
		Address:  server.Address(),
		Count:    1,
		Check:    check.And(check.OK(), check.ReachedWorkloads(1)),
		Retry: retry.Policy{
			Timeout: 30 * time.Second, Delay: 200 * time.Millisecond,
			Backoff: 1.5, MaxDelay: 2 * time.Second, Converge: 1,
		},
	})
}
