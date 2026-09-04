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
	"slices"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"

	"github.com/openkruise/agentio/pkg/model"
)

func TestNewPatchSetOrdersPoliciesAndPreservesDeclarationOrder(t *testing.T) {
	policies := []model.GatewayPatch{
		testGatewayPatch(t, "demo", "late", "source-b", 10, time.Unix(1, 0), "late-1", "late-2"),
		testGatewayPatch(t, "demo", "same-time-b", "source-c", 0, time.Unix(2, 0), "b"),
		testGatewayPatch(t, "demo", "same-time-a", "source-d", 0, time.Unix(2, 0), "a"),
		testGatewayPatch(t, "demo", "early", "source-a", -10, time.Unix(3, 0), "early"),
	}

	patches := NewPatchSet(policies)
	if got, want := patches.Names(clusterTarget),
		[]string{"demo/early", "demo/same-time-a", "demo/same-time-b", "demo/late", "demo/late"}; !slices.Equal(got, want) {
		t.Fatalf("patch order = %v, want %v", got, want)
	}
	ordered := patches.For(clusterTarget)
	if ordered[3].cluster().Value.GetName() != "late-1" || ordered[4].cluster().Value.GetName() != "late-2" {
		t.Fatalf("declaration order changed: %+v", ordered[3:])
	}
}

func testGatewayPatch(
	t *testing.T,
	namespace, name, source string,
	priority int32,
	created time.Time,
	clusterNames ...string,
) model.GatewayPatch {
	t.Helper()
	patches := make([]model.EnvoyPatch, 0, len(clusterNames))
	for _, clusterName := range clusterNames {
		patches = append(patches, model.EnvoyPatch{
			Operation: model.PatchAdd,
			Target:    model.ClusterPatch{Value: &clusterv3.Cluster{Name: clusterName}},
		})
	}
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: namespace, Name: name, Source: source, CreationTime: created,
	}, priority, []string{"demo/gateway"}, patches)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
