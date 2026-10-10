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
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/store"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

type fakeSource struct {
	snapshot xdsclient.Snapshot
	demand   func(string)
	demands  int
	reads    int
	changed  chan struct{}
}

func (f *fakeSource) Snapshot() xdsclient.Snapshot {
	f.reads++
	result := xdsclient.Snapshot{
		Changed:   f.snapshot.Changed,
		Synced:    map[string]bool{},
		Resources: map[string]map[string]*anypb.Any{},
	}
	for typ, resources := range f.snapshot.Resources {
		result.Resources[typ] = map[string]*anypb.Any{}
		for name, resource := range resources {
			result.Resources[typ][name] = proto.Clone(resource).(*anypb.Any)
		}
	}
	maps.Copy(result.Synced, f.snapshot.Synced)
	return result
}

func (f *fakeSource) Demand(_ context.Context, typ, name string) (*anypb.Any, error) {
	f.demands++
	if f.demand != nil {
		f.demand(name)
	}
	v := f.snapshot.Resources[typ][name]
	if v == nil {
		return nil, xdsclient.ErrNotFound
	}
	return v, nil
}

func packed(m proto.Message) *anypb.Any {
	v, err := anypb.New(m)
	if err != nil {
		panic(err)
	}
	return v
}

func testSource() *fakeSource {
	w := &workload.Workload{
		Uid:       "uid",
		Name:      "pod",
		Namespace: "ns",
		Addresses: [][]byte{{192, 0, 2, 1}},
		Extensions: []*workload.Extension{
			{
				Name: "traffic-policy-reference",
				Config: packed(
					&ext.PolicyReference{TypeUrl: model.TrafficPolicyType, ResourceNames: []string{"allow"}},
				),
			},
		},
	}
	return &fakeSource{
		snapshot: xdsclient.Snapshot{
			Synced: map[string]bool{model.WorkloadType: true, model.TrafficPolicyType: true},
			Resources: map[string]map[string]*anypb.Any{
				model.WorkloadType: {
					"uid": packed(w),
				},
				model.TrafficPolicyType: {
					"allow": packed(
						&sec.TrafficPolicy{
							Egress: &sec.TrafficPolicy_RuleSet{
								Rules: []*sec.TrafficPolicy_Rule{
									{
										Match: &sec.TrafficPolicy_Match{
											DestinationIps: []*sec.TrafficPolicy_Address{
												{Address: []byte{203, 0, 113, 0}, Length: 24},
											},
										},
									},
								},
							},
						},
					),
				},
			},
		},
	}
}

func (f *fakeSource) notify() {
	if f.changed != nil {
		close(f.changed)
	}
	f.changed = make(chan struct{})
	f.snapshot.Changed = f.changed
}

func (f *fakeSource) Observe(types ...string) (<-chan struct{}, bool) {
	for _, typ := range types {
		if !f.snapshot.Synced[typ] {
			return f.snapshot.Changed, false
		}
	}
	return f.snapshot.Changed, true
}

func TestResourceQueriesAndFetch(t *testing.T) {
	f := testSource()
	f.notify()
	s := New(f)
	before := s.Read()
	workloads, err := before.Snapshots[store.Workload].List()
	if err != nil || len(workloads) != 1 || workloads[0].Value.(*workload.Workload).Name != "pod" {
		t.Fatalf("workloads: %v %v", workloads, err)
	}
	key := store.Key{Type: store.TrafficPolicy, Name: "allow"}
	first, err := s.Read().Snapshots[key.Type].Get(key.Name)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot.Resources[model.TrafficPolicyType]["allow"] = packed(
		&sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{}},
	)
	f.notify()
	select {
	case <-before.Changed:
	default:
		t.Fatal("batch missed update notification")
	}
	if s.Read().Status != s.Status() {
		t.Fatal("batch and status disagree")
	}
	updated, err := s.Read().Snapshots[key.Type].Get(key.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Value.(*sec.TrafficPolicy).Egress.Rules) != 0 ||
		len(first.Value.(*sec.TrafficPolicy).Egress.Rules) != 1 {
		t.Fatal("update or snapshot ownership incorrect")
	}
	delete(f.snapshot.Resources[model.TrafficPolicyType], "allow")
	f.notify()
	if resource, err := s.Read().Snapshots[key.Type].Get(key.Name); err != nil || resource != nil || f.demands != 0 {
		t.Fatal("Get must not fetch", resource, err)
	}
	if resource, err := s.Fetch(t.Context(), key); err != nil || resource != nil || f.demands != 1 {
		t.Fatal("not-found fetch", resource, err)
	}
	f.demand = func(name string) {
		f.snapshot.Resources[model.TrafficPolicyType][name] = packed(&sec.TrafficPolicy{})
		f.notify()
	}
	if resource, err := s.Fetch(t.Context(), key); err != nil || resource == nil {
		t.Fatal("fetch did not retrieve resource", err)
	}
	f.snapshot.Synced[model.TrafficPolicyType] = false
	f.notify()
	if _, err := s.Read().Snapshots[key.Type].Get(key.Name); err == nil {
		t.Fatal("unsynced resource served")
	}
	if s.Status().Ready {
		t.Fatal("unsynced backend ready")
	}
}

func TestReadReusesUnchangedTypeSnapshots(t *testing.T) {
	f := testSource()
	f.notify()
	s := New(f)
	before := s.Read()
	unchanged := s.Read()
	if f.reads != 1 || unchanged.Changed != before.Changed {
		t.Fatal("unchanged publication copied again")
	}
	f.snapshot.Resources[model.TrafficPolicyType]["allow"] = packed(&sec.TrafficPolicy{})
	f.notify()
	after := s.Read()
	if f.reads != 2 || after.Changed == before.Changed {
		t.Fatal("new publication not captured")
	}
	if before.Snapshots[store.Workload] != after.Snapshots[store.Workload] {
		t.Fatal("unmodified Workload snapshot replaced")
	}
	if before.Snapshots[store.TrafficPolicy] == after.Snapshots[store.TrafficPolicy] {
		t.Fatal("TrafficPolicy update not published")
	}
	old, err := before.Snapshots[store.TrafficPolicy].Get("allow")
	if err != nil {
		t.Fatal(err)
	}
	if len(old.Value.(*sec.TrafficPolicy).Egress.Rules) != 1 {
		t.Fatal("old batch mutated")
	}
	f.snapshot.Synced[model.WorkloadType] = false
	f.notify()
	unavailable := s.Read()
	if unavailable.Ready {
		t.Fatal("readiness change lost")
	}
	if _, err := unavailable.Snapshots[store.Workload].List(); err == nil {
		t.Fatal("unsynced type served")
	}
	if unavailable.Snapshots[store.TrafficPolicy] != after.Snapshots[store.TrafficPolicy] {
		t.Fatal("unrelated readiness invalidated policy")
	}
	f.snapshot.Synced[model.WorkloadType] = true
	f.notify()
	recovered := s.Read()
	if !recovered.Ready {
		t.Fatal("readiness recovery lost")
	}
	if resources, err := recovered.Snapshots[store.Workload].List(); err != nil || len(resources) != 1 {
		t.Fatal(resources, err)
	}
}

func TestReadReusesResourcesWithinChangedType(t *testing.T) {
	f := testSource()
	f.snapshot.Resources[model.WorkloadType]["other"] = packed(&workload.Workload{Uid: "other", Name: "other"})
	f.notify()
	s := New(f)
	a := store.NewAggregate(s)
	before := a.Snapshot()
	unchanged, err := before.Get(store.Key{Type: store.Workload, Name: "uid"})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := before.Get(store.Key{Type: store.Workload, Name: "other"})
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot.Resources[model.WorkloadType]["other"] = packed(&workload.Workload{Uid: "other", Name: "updated"})
	f.notify()
	batch := s.Read()
	current, err := batch.Snapshots[store.Workload].Get("uid")
	if err != nil || current != unchanged {
		t.Fatal("unchanged resource was decoded/replaced", err)
	}
	a.Refresh()
	if a.Snapshot().Type(store.Workload) != batch.Snapshots[store.Workload] {
		t.Fatal("single source snapshot rebuilt")
	}
	updated, err := a.Get(store.Key{Type: store.Workload, Name: "other"})
	if err != nil || updated == changed || updated.Value.(*workload.Workload).Name != "updated" {
		t.Fatal(updated, err)
	}
	if changed.Value.(*workload.Workload).Name != "other" {
		t.Fatal("old snapshot mutated")
	}
	delete(f.snapshot.Resources[model.WorkloadType], "other")
	f.notify()
	a.Refresh()
	if r, err := a.Get(store.Key{Type: store.Workload, Name: "other"}); err != nil || r != nil {
		t.Fatal("removed resource retained", r, err)
	}
	if r, err := a.Get(store.Key{Type: store.Workload, Name: "uid"}); err != nil || r != unchanged {
		t.Fatal("deletion replaced unrelated resource", err)
	}
}

func TestReadRecoversCompleteTypeAfterDecodeFailure(t *testing.T) {
	f := testSource()
	f.snapshot.Resources[model.WorkloadType]["other"] = packed(&workload.Workload{Uid: "other"})
	f.notify()
	s := New(f)
	before := s.Read()
	f.snapshot.Resources[model.WorkloadType]["other"] = &anypb.Any{TypeUrl: model.WorkloadType, Value: []byte{0xff}}
	f.notify()
	broken := s.Read()
	if _, err := broken.Snapshots[store.Workload].List(); err == nil ||
		!strings.Contains(err.Error(), `decode Workload "other"`) || !errors.Is(err, proto.Error) {
		t.Fatalf("decode error lost resource identity or cause: %v", err)
	}
	delete(f.snapshot.Resources[model.WorkloadType], "other")
	f.notify()
	recovered := s.Read()
	resources, err := recovered.Snapshots[store.Workload].List()
	if err != nil || len(resources) != 1 || resources[0].Key.Name != "uid" {
		t.Fatal("unchanged resources missing after recovery", resources, err)
	}
	if resources, err := before.Snapshots[store.Workload].List(); err != nil || len(resources) != 2 {
		t.Fatal("failure mutated old snapshot", resources, err)
	}
}
