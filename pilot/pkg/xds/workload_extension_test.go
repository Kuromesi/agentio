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

package xds

import (
	"testing"

	"google.golang.org/protobuf/types/known/anypb"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/workloadapi"
)

// This test catches policy enrichment mutating the globally cached Workload.
// Such a mutation would leak gateway-only references to Address WDS clients
// such as ztunnel and make pre-marshaled Address resources stale.
func TestWithWorkloadExtensionsClonesWorkload(t *testing.T) {
	baseExtension := &workloadapi.Extension{Name: "base", Config: &anypb.Any{TypeUrl: "base"}}
	policyExtension := &workloadapi.Extension{Name: "sni-traffic-policy", Config: &anypb.Any{TypeUrl: "refs"}}
	input := model.AddressInfo{Address: &workloadapi.Address{Type: &workloadapi.Address_Workload{
		Workload: &workloadapi.Workload{Uid: "cluster//Pod/ns/pod", Extensions: []*workloadapi.Extension{baseExtension}},
	}}}

	got := withWorkloadExtensions(input, []*workloadapi.Extension{policyExtension})

	if got.GetWorkload() == input.GetWorkload() {
		t.Fatal("workload enrichment reused the globally cached Workload pointer")
	}
	if len(input.GetWorkload().GetExtensions()) != 1 {
		t.Fatalf("cached Workload extensions = %d, want 1", len(input.GetWorkload().GetExtensions()))
	}
	if names := []string{
		got.GetWorkload().GetExtensions()[0].GetName(),
		got.GetWorkload().GetExtensions()[1].GetName(),
	}; names[0] != "base" || names[1] != "sni-traffic-policy" {
		t.Fatalf("enriched extension order = %v, want [base sni-traffic-policy]", names)
	}
}
