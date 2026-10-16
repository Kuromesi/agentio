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
	"slices"
	"testing"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

func TestWorkloadDemandAliasResendAndMissing(t *testing.T) {
	resource := addressResource(t, "canonical", "pod", "instance/one", "/10.0.0.1")
	snapshot := selectionSnapshot(t, []model.Resource{resource})
	for _, name := range []string{resource.XDSName, "instance/one", "/10.0.0.1", "missing"} {
		t.Run(name, func(t *testing.T) {
			view, ok := demandSubscriptionView(snapshot, model.WorkloadType, []string{name})
			if !ok {
				t.Fatal("unique alias/missing demand did not use incremental selection")
			}
			req := GenerationRequest{
				Scope:           gatewayScope(),
				Snapshot:        snapshot,
				TypeURL:         model.WorkloadType,
				Subscription:    view,
				SubscribedNames: []string{name},
				Full:            true,
			}
			first, err := (WorkloadGenerator{}).Generate(t.Context(), req)
			if err != nil {
				t.Fatal(err)
			}
			if name == "missing" {
				if len(first.Resources) != 0 || !slices.Equal(first.Removed, []string{name}) {
					t.Fatalf("missing demand: %v", first)
				}
				return
			}
			if len(first.Resources) != 1 || first.Resources[0].XDSName != resource.XDSName || len(first.Removed) != 0 {
				t.Fatalf("alias resolved incorrectly: %v", first)
			}
			req.Subscription.sent = map[string]string{resource.XDSName: first.Resources[0].Hash}
			again, err := (WorkloadGenerator{}).Generate(t.Context(), req)
			if err != nil {
				t.Fatal(err)
			}
			if len(again.Resources) != 1 || len(again.Removed) != 0 {
				t.Fatalf("explicit alias resubscribe omitted or removed cached resource: %v", again)
			}
		})
	}
}

func TestWorkloadDemandAmbiguousAliasKeepsFullSelection(t *testing.T) {
	resources := []model.Resource{
		addressResource(t, "one", "one", "shared-ip"),
		addressResource(t, "two", "two", "shared-ip"),
	}
	snapshot := selectionSnapshot(t, resources)
	if _, ok := demandSubscriptionView(snapshot, model.WorkloadType, []string{"shared-ip"}); ok {
		t.Fatal("ambiguous alias entered unique-resource fast path")
	}
	delta, err := (WorkloadGenerator{}).Generate(
		t.Context(),
		GenerationRequest{
			Scope:           gatewayScope(),
			Snapshot:        snapshot,
			TypeURL:         model.WorkloadType,
			Subscription:    SubscriptionView{names: []string{"shared-ip"}},
			SubscribedNames: []string{"shared-ip"},
			Full:            true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 2 || len(delta.Removed) != 0 {
		t.Fatalf("ambiguous alias lost owners: %v", delta)
	}
}

func TestWorkloadEvictionRetainsOtherAliasSubscriptions(t *testing.T) {
	a := addressResource(t, "a", "a", "instance-a", "ip-a")
	a.Facts.Workload.ServiceKeys = []string{"demo/service"}
	service := selectionService(t, "demo/service", "service-ip")
	b := addressResource(t, "b", "b", "instance-b")
	snapshot := selectionSnapshot(t, []model.Resource{a, b, service})
	projected, err := (WorkloadGenerator{}).projectAddresses([]model.Resource{a})
	if err != nil {
		t.Fatal(err)
	}
	for _, remaining := range []string{"", "ip-a", "service-ip"} {
		keep := remaining != ""
		names := sets.New("instance-b")
		if keep {
			names.Insert(remaining)
		}
		watch := &watchState{names: names, sent: map[string]string{"a": projected[0].Hash}}
		view, ok := demandReconciliationView(
			snapshot,
			model.WorkloadType,
			gatewayScope(),
			watch,
			[]string{"instance-b"},
			[]string{"instance-a"},
		)
		if !ok {
			t.Fatal("cache eviction fell back to full generation")
		}
		delta, err := (WorkloadGenerator{}).Generate(
			t.Context(),
			GenerationRequest{
				Scope:           gatewayScope(),
				Snapshot:        snapshot,
				TypeURL:         model.WorkloadType,
				Subscription:    view,
				SubscribedNames: []string{"instance-b"},
				Full:            true,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(delta.Resources) != 1 || delta.Resources[0].XDSName != "b" {
			t.Fatalf("eviction regenerated unrelated Workload: %v", delta)
		}
		if keep && len(delta.Removed) != 0 {
			t.Fatalf("removed resource with another subscription: %v", delta)
		}
		if !keep && !slices.Equal(delta.Removed, []string{"a"}) {
			t.Fatalf("last unsubscribe did not remove resource: %v", delta)
		}
	}
}
