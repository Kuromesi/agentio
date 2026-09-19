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

package trafficpolicy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
)

// Ordinary Deployments must receive explicit native bindings with no synthetic
// Sandbox. The policy matrix in this suite then tests enforcement and updates.
func TestWorkloadNativeBindingsWithoutSandbox(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	ctx, cancel := e2e.Context(t, time.Minute)
	defer cancel()
	content, err := rig.ConfigDump(ctx, suite.Environment(t), trafficFixture.Client)
	if err != nil {
		t.Fatal(err)
	}
	var dump struct {
		Workload struct {
			TrafficPolicyRefs *[]string `json:"trafficPolicyRefs"`
		} `json:"workload"`
		Sandboxes []json.RawMessage `json:"sandboxes"`
	}
	if err := json.Unmarshal([]byte(content), &dump); err != nil {
		t.Fatal(err)
	}
	if dump.Workload.TrafficPolicyRefs == nil {
		t.Fatal("ordinary Workload has no explicit native TrafficPolicy binding")
	}
	if len(dump.Sandboxes) != 0 {
		t.Fatalf("ordinary Workload has %d synthetic Sandboxes", len(dump.Sandboxes))
	}
}
