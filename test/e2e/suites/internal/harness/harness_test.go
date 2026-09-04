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

package harness

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestDataplaneNamespaceConfig(t *testing.T) {
	tests := []struct {
		name, profile, wantMode string
	}{
		{name: "sidecar", profile: agentiocomponent.ProfileSidecar, wantMode: "sidecar"},
		{name: "ambient", profile: agentiocomponent.ProfileAmbient, wantMode: "ambient"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DataplaneNamespaceConfig(test.profile, "traffic")
			if err != nil {
				t.Fatal(err)
			}
			if got.Prefix != "traffic" || len(got.Labels) != 1 || got.Labels[DataplaneModeLabel] != test.wantMode {
				t.Fatalf("dataplane namespace config = %#v", got)
			}
			got.Labels["example.com/mutated"] = "true"
			again, err := DataplaneNamespaceConfig(test.profile, "traffic")
			if err != nil {
				t.Fatal(err)
			}
			if _, found := again.Labels["example.com/mutated"]; found {
				t.Fatal("DataplaneNamespaceConfig reused a mutable label map")
			}
		})
	}
}

func TestDataplaneNamespaceConfigRejectsUnknownProfile(t *testing.T) {
	if _, err := DataplaneNamespaceConfig("unknown", "traffic"); err == nil {
		t.Fatal("DataplaneNamespaceConfig accepted an unknown dataplane profile")
	}
}

func TestSelectZtunnelPodUsesWorkloadNode(t *testing.T) {
	workload := corev1.Pod{Spec: corev1.PodSpec{NodeName: "worker-b"}}
	candidates := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "ztunnel-a"}, Spec: corev1.PodSpec{NodeName: "worker-a"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "ztunnel-b"}, Spec: corev1.PodSpec{NodeName: "worker-b"}},
	}
	got, err := selectZtunnelPod(workload, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "ztunnel-b" {
		t.Fatalf("selected ztunnel = %q, want ztunnel-b", got.Name)
	}
}

func TestSelectZtunnelPodRejectsMissingWorkloadNode(t *testing.T) {
	_, err := selectZtunnelPod(corev1.Pod{}, []corev1.Pod{{Spec: corev1.PodSpec{NodeName: "worker-a"}}})
	if err == nil {
		t.Fatal("selectZtunnelPod accepted a workload without a node")
	}
}

func TestProjectAmbientConfigDumpKeepsOnlyWorkloadPolicies(t *testing.T) {
	raw := []byte(`{
  "policies": [
    {"namespace":"sandbox","name":"client-policy-egress","scope":"WorkloadSelector","rules":[{"destinationIps":["10.0.0.1/32"]}]},
    {"namespace":"sandbox","name":"server-policy-egress","scope":"WorkloadSelector","rules":[{"destinationIps":["10.0.0.2/32"]}]},
    {"namespace":"agentio-system","name":"global-policy-egress","scope":"Global","rules":[{"destinationIps":["10.0.0.3/32"]}]}
  ],
  "workloads": [
    {"namespace":"sandbox","name":"client-pod","authorizationPolicies":["sandbox/client-policy-egress"]},
    {"namespace":"sandbox","name":"server-pod","authorizationPolicies":["sandbox/server-policy-egress"]}
  ]
}`)
	got, err := projectAmbientConfigDump(raw, "sandbox", "client-pod")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"client-pod", "client-policy-egress", "10.0.0.1/32", "global-policy-egress", "10.0.0.3/32"} {
		if !strings.Contains(got, want) {
			t.Errorf("projected dump does not contain %q: %s", want, got)
		}
	}
	for _, unwanted := range []string{"server-pod", "server-policy-egress", "10.0.0.2/32"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("projected dump contains unrelated %q: %s", unwanted, got)
		}
	}
}

func TestProjectAmbientConfigDumpRejectsUnknownWorkload(t *testing.T) {
	_, err := projectAmbientConfigDump([]byte(`{"policies":[],"workloads":[]}`), "sandbox", "missing")
	if err == nil {
		t.Fatal("projectAmbientConfigDump accepted an unknown workload")
	}
}

func TestFinishScenarioRestoresBaselineAfterCleanup(t *testing.T) {
	var events []string
	dirty, err := finishScenario(false, func() error {
		events = append(events, "cleanup")
		return nil
	}, func() error {
		events = append(events, "restore")
		return nil
	})
	if err != nil || dirty || !reflect.DeepEqual(events, []string{"cleanup", "restore"}) {
		t.Fatalf("finishScenario() = dirty %t, events %v, error %v", dirty, events, err)
	}
}

func TestPreserveFailedScenario(t *testing.T) {
	tests := []struct {
		name         string
		failed       bool
		deferCleanup bool
		want         bool
	}{
		{name: "passed with immediate cleanup", failed: false, deferCleanup: false, want: false},
		{name: "passed with deferred cleanup", failed: false, deferCleanup: true, want: false},
		{name: "failed with immediate cleanup", failed: true, deferCleanup: false, want: false},
		{name: "failed with deferred cleanup", failed: true, deferCleanup: true, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := preserveFailedScenario(tt.failed, tt.deferCleanup); got != tt.want {
				t.Fatalf("preserveFailedScenario(%v, %v) = %v, want %v", tt.failed, tt.deferCleanup, got, tt.want)
			}
		})
	}
}

func TestFinishScenarioPreservesFailedResourcesAndConfig(t *testing.T) {
	var events []string
	dirty, err := finishScenario(true, func() error {
		events = append(events, "cleanup")
		return nil
	}, func() error {
		events = append(events, "restore")
		return nil
	})
	if err != nil || !dirty || len(events) != 0 {
		t.Fatalf("finishScenario() = dirty %t, events %v, error %v", dirty, events, err)
	}
}

func TestFinishScenarioContaminatesOnCleanupFailure(t *testing.T) {
	want := errors.New("delete failed")
	restored := false
	dirty, err := finishScenario(false, func() error { return want }, func() error {
		restored = true
		return nil
	})
	if !dirty || !errors.Is(err, want) {
		t.Fatalf("finishScenario() = dirty %t, error %v", dirty, err)
	}
	if restored {
		t.Fatal("finishScenario() restored the baseline after cleanup failed")
	}
}

func TestFinishScenarioContaminatesOnBaselineFailure(t *testing.T) {
	want := errors.New("restore failed")
	dirty, err := finishScenario(false, func() error { return nil }, func() error { return want })
	if !dirty || !errors.Is(err, want) {
		t.Fatalf("finishScenario() = dirty %t, error %v", dirty, err)
	}
}

func TestAgentioBaselineFixtureIsExactlyPassthroughAndGatewayRegistration(t *testing.T) {
	object := BaselineObject("agentio-system")
	if object.GetName() != "agentio-config-primary" || object.GetNamespace() != "agentio-system" {
		t.Fatalf("baseline ConfigMap = %s/%s", object.GetNamespace(), object.GetName())
	}
	raw, found, err := unstructured.NestedString(object.Object, "data", "config")
	if err != nil || !found {
		t.Fatalf("baseline config = %q, found %t, error %v", raw, found, err)
	}
	var got map[string]any
	if err := yaml.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode baseline config: %v", err)
	}
	want := map[string]any{
		"egressGateways": []any{map[string]any{
			"namespace": "agentio-system",
			"name":      "egress-gateway",
		}},
		"egressPolicies": []any{map[string]any{"policy": "PASSTHROUGH"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("baseline config = %#v, want %#v", got, want)
	}
}
