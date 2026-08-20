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

package kind

import "testing"

func TestExtendedKindStrings(t *testing.T) {
	for k, want := range map[Kind]string{
		WorkloadConfig:   "WorkloadConfig",
		PolicyBinding:    "PolicyBinding",
		SniTrafficPolicy: "SniTrafficPolicy",
	} {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", k, got, want)
		}
		if got := FromString(want); got != k {
			t.Errorf("FromString(%q) = %v, want %v", want, got, k)
		}
	}
	if got := Kind(255).String(); got != "Unknown" {
		t.Errorf("undefined kind String() = %q, want Unknown", got)
	}
	if got := FromString("NotAKind"); got != Unknown {
		t.Errorf("FromString(NotAKind) = %v, want Unknown", got)
	}
	// Generated kinds must keep taking the generated switch, not the map.
	if got := Pod.String(); got != "Pod" {
		t.Errorf("Pod.String() = %q, want Pod", got)
	}
}
