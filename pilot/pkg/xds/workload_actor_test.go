// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pilot/pkg/serviceregistry/memory"
	"istio.io/istio/pkg/util/sets"
)

func TestWorkloadConfigGeneratorSkipsActorAddressOnlyPush(t *testing.T) {
	dedicated := &model.Proxy{
		ID:       "worker-0.substrate-system",
		Metadata: &model.NodeMetadata{Namespace: "substrate-system"},
		Labels:   map[string]string{agentio.LabelSandboxProxyType: "ztunnel"},
	}
	generator := WorkloadConfigGenerator{
		Server: &DiscoveryServer{
			Env: &model.Environment{ServiceDiscovery: memory.NewServiceDiscovery()},
		},
	}
	watched := &model.WatchedResource{
		ResourceNames: sets.New("agentio-system/default"),
	}

	resources, removed, _, used, err := generator.GenerateDeltas(dedicated, &model.PushRequest{
		AddressesUpdated: sets.New("//Pod/substrate-system/worker-0"),
	}, watched)
	if err != nil {
		t.Fatal(err)
	}
	if used || len(resources) != 0 || len(removed) != 0 {
		t.Fatalf("address-only WCDS push used=%v resources=%d removed=%d, want skipped", used, len(resources), len(removed))
	}
}
