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
	"testing"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

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
