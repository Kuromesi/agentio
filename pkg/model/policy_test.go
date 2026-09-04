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

package model

import "testing"

func TestPolicyEqualityTracksSandboxUID(t *testing.T) {
	traffic := TrafficPolicy{Name: "allow", Namespace: "demo", SandboxUID: "sandbox-a"}
	changedTraffic := traffic
	changedTraffic.SandboxUID = "sandbox-b"
	if traffic.Equals(changedTraffic) {
		t.Fatal("TrafficPolicy equality ignored SandboxUID")
	}

	profile := SecurityProfile{Name: "tls", Namespace: "demo", SandboxUID: "sandbox-a"}
	changedProfile := profile
	changedProfile.SandboxUID = "sandbox-b"
	if profile.Equals(changedProfile) {
		t.Fatal("SecurityProfile equality ignored SandboxUID")
	}
}
