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

package agentio

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestActorContextFromLabels(t *testing.T) {
	labels := map[string]string{
		LabelActorUID:                          "actor-uid-1",
		LabelActorName:                         "crawler",
		LabelActorAtespace:                     "demo",
		LabelActorGeneration:                   "7",
		ActorLabelPrefix + "role":              "reader",
		ActorLabelPrefix + "tenant.example.io": "tenant-a",
		"worker-only":                          "must-not-leak",
	}

	got := ActorContextFromLabels(labels)
	if got == nil {
		t.Fatal("ActorContextFromLabels() returned nil for a complete binding")
	}
	if got.GetActorUid() != "actor-uid-1" || got.GetActorName() != "crawler" || got.GetAtespace() != "demo" {
		t.Fatalf("unexpected actor identity: %+v", got)
	}
	if got.GetGeneration() != 7 {
		t.Fatalf("generation = %d, want 7", got.GetGeneration())
	}
	wantLabels := map[string]string{
		"role":                       "reader",
		"tenant.example.io":          "tenant-a",
		ActorIdentityLabelUID:        "actor-uid-1",
		ActorIdentityLabelName:       "crawler",
		ActorIdentityLabelAtespace:   "demo",
		ActorIdentityLabelGeneration: "7",
	}
	if diff := cmp.Diff(wantLabels, got.GetLabels()); diff != "" {
		t.Fatalf("actor labels differ (-want +got):\n%s", diff)
	}
}

func TestActorContextFromLabelsRejectsIncompleteBinding(t *testing.T) {
	base := map[string]string{
		LabelActorUID:        "actor-uid-1",
		LabelActorName:       "crawler",
		LabelActorAtespace:   "demo",
		LabelActorGeneration: "7",
	}
	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "missing uid", mutate: func(labels map[string]string) { delete(labels, LabelActorUID) }},
		{name: "missing name", mutate: func(labels map[string]string) { delete(labels, LabelActorName) }},
		{name: "missing atespace", mutate: func(labels map[string]string) { delete(labels, LabelActorAtespace) }},
		{name: "missing generation", mutate: func(labels map[string]string) { delete(labels, LabelActorGeneration) }},
		{name: "zero generation", mutate: func(labels map[string]string) { labels[LabelActorGeneration] = "0" }},
		{name: "invalid generation", mutate: func(labels map[string]string) { labels[LabelActorGeneration] = "not-a-number" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := make(map[string]string, len(base))
			for key, value := range base {
				labels[key] = value
			}
			tt.mutate(labels)
			if got := ActorContextFromLabels(labels); got != nil {
				t.Fatalf("ActorContextFromLabels() = %+v, want nil", got)
			}
		})
	}
}
