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
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

func TestWildcardFullAddressGenerationCollapsesWireNamesDeterministically(t *testing.T) {
	resources := []model.Resource{
		addressResourceWithWireName(t, "canonical-a", "shared-wire-name"),
		addressResourceWithWireName(t, "canonical-b", "shared-wire-name"),
	}
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}

	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        ztunnelScope(),
		Snapshot:     snapshot,
		TypeURL:      model.AddressType,
		Subscription: SubscriptionView{wildcard: true, sent: map[string]string{}},
		Full:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 1 || delta.Resources[0].Key.Name != "canonical-b" ||
		delta.Resources[0].XDSName != "shared-wire-name" {
		t.Fatalf("generated resources = %#v, want canonical-b under the shared wire name", delta.Resources)
	}
}

func TestWildcardFullAddressGenerationHonorsInitialVersions(t *testing.T) {
	resource := addressResource(t, "cluster//Pod/demo/pod-a", "pod-a")
	snapshot, err := model.NewResourceSet([]model.Resource{resource})
	if err != nil {
		t.Fatal(err)
	}

	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:    ztunnelScope(),
		Snapshot: snapshot,
		TypeURL:  model.AddressType,
		Subscription: SubscriptionView{
			wildcard: true,
			sent:     map[string]string{resource.XDSName: resource.Hash},
		},
		Full: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 0 || len(delta.Removed) != 0 {
		t.Fatalf("generated delta = resources:%v removed:%v, want no change", delta.Resources, delta.Removed)
	}
}

func TestWildcardFullAddressGenerationAllocationBudget(t *testing.T) {
	const resourceCount = 1_000
	resources := make([]model.Resource, 0, resourceCount)
	for index := range resourceCount {
		name := fmt.Sprintf("cluster//Pod/demo/pod-%04d", index)
		resources = append(resources, addressResource(t, name, name))
	}
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	request := GenerationRequest{
		Scope:        ztunnelScope(),
		Snapshot:     snapshot,
		TypeURL:      model.AddressType,
		Subscription: SubscriptionView{wildcard: true, sent: map[string]string{}},
		Full:         true,
	}

	var delta GeneratedDelta
	var generationErr error
	allocations := testing.AllocsPerRun(3, func() {
		delta, generationErr = (WorkloadGenerator{}).Generate(context.Background(), request)
	})
	if generationErr != nil {
		t.Fatal(generationErr)
	}
	if len(delta.Resources) != resourceCount {
		t.Fatalf("generated resources = %d, want %d", len(delta.Resources), resourceCount)
	}
	if allocations > 200 {
		t.Fatalf("allocations per full generation = %.0f, want at most 200", allocations)
	}

	const runs = 10
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		delta, generationErr = (WorkloadGenerator{}).Generate(context.Background(), request)
		if generationErr != nil {
			t.Fatal(generationErr)
		}
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if bytesPerRun := (after.TotalAlloc - before.TotalAlloc) / runs; bytesPerRun > 600<<10 {
		t.Fatalf("full generation allocated %d bytes/run, want at most %d", bytesPerRun, 600<<10)
	}
}

func BenchmarkWildcardFullAddressGeneration10000(b *testing.B) {
	const resourceCount = 10_000
	resources := make([]model.Resource, 0, resourceCount)
	for index := range resourceCount {
		name := fmt.Sprintf("cluster//Pod/demo/pod-%05d", index)
		resources = append(resources, addressResource(b, name, name))
	}
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	request := GenerationRequest{
		Scope:        ztunnelScope(),
		Snapshot:     snapshot,
		TypeURL:      model.AddressType,
		Subscription: SubscriptionView{wildcard: true, sent: map[string]string{}},
		Full:         true,
	}

	b.ReportAllocs()
	b.ReportMetric(resourceCount, "resources/msg")
	b.ResetTimer()
	for b.Loop() {
		delta, err := (WorkloadGenerator{}).Generate(context.Background(), request)
		if err != nil || len(delta.Resources) != resourceCount {
			b.Fatalf("Generate() resources=%d err=%v", len(delta.Resources), err)
		}
	}
}

func addressResourceWithWireName(t testing.TB, keyName, wireName string) model.Resource {
	t.Helper()
	base := addressResource(t, keyName, keyName)
	resource, err := model.NewResource(base.Key, wireName, base.Value, base.Aliases, base.Facts)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}
