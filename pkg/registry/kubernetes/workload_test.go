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

package kubernetes

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Pod lookup remains the authorization source of truth, while only Pods with
// usable network addresses become Workload attesters for WDS generation.
func TestWorkloadsExcludeIneligiblePodsButRetainPodAuthorizationInputs(t *testing.T) {
	ctx := t.Context()
	terminal := egressPod("demo", "done", "egress", "10.0.0.9")
	terminal.Status.Phase = corev1.PodSucceeded
	addressless := egressPod("demo", "waiting", "egress", "")
	malformed := egressPod("demo", "bad-address", "egress", "not-an-ip")
	r := newTestRegistry(t, ctx, []runtime.Object{
		egressPod("demo", "valid", "egress", "10.0.0.1"), terminal, addressless, malformed,
	}, nil)

	if got := len(r.Pods.List()); got != 4 {
		t.Fatalf("authorization Pod inputs = %d, want 4", got)
	}
	if got := r.Workloads.List(); len(got) != 1 || got[0].Name != "valid" {
		t.Fatalf("Workloads = %+v, want only valid Pod", got)
	}

	if got := r.Sandboxes.List(); len(got) != 0 {
		t.Fatalf("ordinary Pods created Sandboxes: %+v", got)
	}

}
