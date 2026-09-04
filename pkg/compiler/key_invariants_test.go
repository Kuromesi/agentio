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

package compiler

import (
	"strings"
	"testing"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// These tests keep the AddressType key formats of the resource families disjoint.
func TestWorkloadAndServiceAddressKeysStayDisjoint(t *testing.T) {
	workload := testWDSWorkload("client", "client-uid", "10.0.0.1")
	service := model.Service{
		Namespace: "demo",
		Name:      "backend",
		Hostname:  "backend.demo.svc.cluster.local",
	}
	if !strings.Contains(workload.UID, "//") {
		t.Fatalf("WDS workload UID %q lost its stable // separator", workload.UID)
	}
	if strings.Contains(service.ResourceName(), "//") {
		t.Fatalf("service key %q collides with the sandbox UID format", service.ResourceName())
	}
}

func TestCompiledAddressKeysAreUniqueAcrossFamilies(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workload := testWDSWorkload("client", "client-uid", "10.0.0.1")
	service := model.Service{
		Namespace: "demo",
		Name:      "backend",
		Hostname:  "backend.demo.svc.cluster.local",
		Ports: []model.ServicePort{{
			Name:       "http",
			Port:       80,
			TargetPort: 8080,
			Protocol:   "TCP",
		}},
	}
	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{workload}, options...)
	inputs.Services = krt.NewStaticCollection[model.Service](nil, []model.Service{service}, options...)
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := compileSynced(t, compiler)

	sawWorkload, sawService := false, false
	for _, typeURL := range snapshot.Types() {
		for _, resource := range snapshot.List(typeURL) {
			if resource.Key.TypeURL != model.AddressType {
				continue
			}
			switch {
			case resource.Key.Name == workload.UID:
				sawWorkload = true
			case resource.Key.Name == service.ResourceName():
				sawService = true
			default:
				t.Fatalf("unexpected AddressType key %q", resource.Key.Name)
			}
		}
	}
	if !sawWorkload || !sawService {
		t.Fatalf("expected both family keys in the snapshot, workload=%v service=%v", sawWorkload, sawService)
	}
}
