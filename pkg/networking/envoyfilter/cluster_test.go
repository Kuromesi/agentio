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

package envoyfilter

import (
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"

	"github.com/openkruise/agentio/pkg/model"
)

func TestApplyClustersPreservesAgentioGatewayOperations(t *testing.T) {
	patches := NewPatchSet([]model.GatewayPatch{clusterPolicy(t, "clusters",
		clusterPatch(model.PatchMerge, "main_forward", &clusterv3.Cluster{AltStatName: "patched"}),
		clusterPatch(model.PatchRemove, "BlackHoleCluster", nil),
		clusterPatch(model.PatchAdd, "", &clusterv3.Cluster{Name: "inserted"}),
	)})
	original := []*clusterv3.Cluster{{Name: "main_forward"}, {Name: "BlackHoleCluster"}}

	got, err := ApplyClusters(patches, original)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].GetName() != "main_forward" || got[0].GetAltStatName() != "patched" || got[1].GetName() != "inserted" {
		t.Fatalf("clusters = %+v", got)
	}
	if original[0].GetAltStatName() != "" || len(original) != 2 {
		t.Fatalf("input clusters were mutated: %+v", original)
	}
}

func TestApplyClustersRejectsDuplicateInsertedName(t *testing.T) {
	patches := NewPatchSet([]model.GatewayPatch{clusterPolicy(t, "duplicate",
		clusterPatch(model.PatchAdd, "", &clusterv3.Cluster{Name: "main_forward"}),
	)})
	if _, err := ApplyClusters(patches, []*clusterv3.Cluster{{Name: "main_forward"}}); err == nil {
		t.Fatal("duplicate inserted cluster accepted")
	}
}

func clusterPolicy(t *testing.T, name string, patches ...model.EnvoyPatch) model.GatewayPatch {
	t.Helper()
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "demo", Name: name, Source: "source",
	}, 0, []string{"demo/gateway"}, patches)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func clusterPatch(operation model.PatchOperation, name string, value *clusterv3.Cluster) model.EnvoyPatch {
	return model.EnvoyPatch{Operation: operation, Target: model.ClusterPatch{
		Match: &model.ClusterMatch{Name: name}, Value: value,
	}}
}
