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
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
)

func TestExtensionProtoPackage(t *testing.T) {
	tests := []struct {
		name    string
		message proto.Message
	}{
		{name: "agentio config", message: &extensions.AgentioConfig{}},
		{name: "traffic policy", message: &extensions.TrafficPolicyExtension{}},
		{name: "workload metadata", message: &extensions.WorkloadMetadata{}},
		{name: "egress policies", message: &extensions.EgressPolicies{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := anypb.New(tt.message)
			if err != nil {
				t.Fatal(err)
			}

			const wantPrefix = "type.googleapis.com/kruise.networking.extensions.v1."
			if got := value.TypeUrl; !strings.HasPrefix(got, wantPrefix) {
				t.Fatalf("unexpected type URL: got %q, want prefix %q", got, wantPrefix)
			}
		})
	}

	wantTypeURLs := map[string]string{
		"traffic policy":    trafficPolicyExtension,
		"workload metadata": workloadMetadataExtension,
		"egress policies":   egressPoliciesExtension,
	}
	for name, got := range wantTypeURLs {
		const wantPrefix = "type.googleapis.com/kruise.networking.extensions.v1."
		if !strings.HasPrefix(got, wantPrefix) {
			t.Errorf("%s extension has type URL %q, want prefix %q", name, got, wantPrefix)
		}
	}
}

func TestNewWorkloadMetadataExtension(t *testing.T) {
	got := NewWorkloadMetadataExtension(
		map[string]string{"app": "agentio"},
		extensions.MeshInternalTrafficPolicy_MESH_INTERNAL_PASSTHROUGH,
	)

	if got.Name != "workload-metadata" {
		t.Fatalf("unexpected extension name: got %q, want %q", got.Name, "workload-metadata")
	}
	if got.Config.GetTypeUrl() != workloadMetadataExtension {
		t.Fatalf("unexpected type URL: got %q, want %q", got.Config.GetTypeUrl(), workloadMetadataExtension)
	}

	metadata := &extensions.WorkloadMetadata{}
	if err := got.Config.UnmarshalTo(metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Labels["app"] != "agentio" {
		t.Fatalf("unexpected labels: got %v", metadata.Labels)
	}
	if metadata.MeshInternalTrafficPolicy != extensions.MeshInternalTrafficPolicy_MESH_INTERNAL_PASSTHROUGH {
		t.Fatalf("unexpected internal traffic policy: got %v", metadata.MeshInternalTrafficPolicy)
	}
}

func TestNewActorContextExtension(t *testing.T) {
	actor := &extensions.ActorContext{
		ActorUid:   "actor-uid-a",
		ActorName:  "actor-a",
		Atespace:   "tenant-a",
		Generation: 7,
		Labels:     map[string]string{"role": "reader"},
	}
	got := NewActorContextExtension(actor)

	if got.Name != "actor-context" {
		t.Fatalf("extension name = %q, want %q", got.Name, "actor-context")
	}
	if got.Config.GetTypeUrl() != actorContextExtension {
		t.Fatalf("type URL = %q, want %q", got.Config.GetTypeUrl(), actorContextExtension)
	}

	decoded := &extensions.ActorContext{}
	if err := got.Config.UnmarshalTo(decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(decoded, actor) {
		t.Fatalf("decoded ActorContext = %+v, want %+v", decoded, actor)
	}
}
