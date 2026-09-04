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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/model"
)

var _ ResourceStore = (*Store)(nil)
var _ ResourceSubscription = (*Subscription)(nil)

func TestStoreLogsOneIncrementalPushSummary(t *testing.T) {
	var output bytes.Buffer
	previousLogger := slog.Default()
	previousLevel := agentlog.OutputLevel()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	agentlog.ConfigureOutputLevel(slog.LevelInfo)
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
		agentlog.ConfigureOutputLevel(previousLevel)
	})

	store := NewStore(newSnapshot(t))
	subscription := store.Subscribe(t.Context())
	subscription.Watch(model.ClusterType)
	subscription.Watch(model.SniTrafficPolicyType)
	cluster := updateTestResource(t, model.ClusterType, "cluster-key", "cluster", "cluster")
	sni := updateTestResource(t, model.SniTrafficPolicyType, "policy-key", "policy", "policy")
	publication, err := store.Apply([]model.ResourceChange{
		{Key: sni.Key, New: &sni},
		{Key: cluster.Key, New: &cluster},
	})
	if err != nil {
		t.Fatal(err)
	}

	encoded := bytes.TrimSpace(output.Bytes())
	if len(encoded) == 0 {
		t.Fatal("incremental publication emitted no push summary log")
	}
	lines := bytes.Split(encoded, []byte{'\n'})
	if len(lines) != 1 {
		t.Fatalf("incremental publication logs = %d, want 1:\n%s", len(lines), output.String())
	}
	var entry struct {
		Level              string   `json:"level"`
		Message            string   `json:"msg"`
		ConnectedEndpoints int      `json:"connected_endpoints"`
		Version            string   `json:"version"`
		Types              []string `json:"types"`
	}
	if err := json.Unmarshal(lines[0], &entry); err != nil {
		t.Fatalf("decode incremental push log: %v\n%s", err, lines[0])
	}
	if entry.Level != "INFO" || entry.Message != "XDS: Incremental Pushing" {
		t.Fatalf("incremental push log identity = (%q, %q), want (INFO, XDS: Incremental Pushing)", entry.Level, entry.Message)
	}
	if entry.ConnectedEndpoints != 1 || entry.Version != publication.Snapshot.Version() {
		t.Fatalf("incremental push summary = endpoints:%d version:%q, want endpoints:1 version:%q",
			entry.ConnectedEndpoints, entry.Version, publication.Snapshot.Version())
	}
	wantTypes := []string{model.ClusterType, model.SniTrafficPolicyType}
	if !slices.Equal(entry.Types, wantTypes) {
		t.Fatalf("incremental push types = %v, want %v", entry.Types, wantTypes)
	}
}

func TestResourceSubscriptionStopsWithContext(t *testing.T) {
	empty, err := model.NewResourceSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(empty)
	ctx, cancel := context.WithCancel(context.Background())
	subscription := store.Subscribe(ctx)
	subscription.Watch(model.AddressType)
	cancel()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		store.mu.RLock()
		count := len(store.subscribers)
		store.mu.RUnlock()
		if count == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("subscriber was not released after context cancellation")
}

// Publication returns the committed snapshot on every path, so Controller can
// record metrics without racing a later Store commit by rereading it.
func TestStorePublicationCarriesCommittedSnapshot(t *testing.T) {
	initial := newSnapshot(t, "a")
	store := NewStore(initial)

	publication := store.Replace(newSnapshot(t, "a"))
	if publication.Changed {
		t.Fatal("identical snapshot publication reported a change")
	}
	if got, want := publication.Snapshot.Version(), initial.Version(); got != want {
		t.Fatalf("no-op snapshot version = %q, want %q", got, want)
	}

	resource := newSnapshot(t, "b").List(model.AddressType)[0]
	publication, err := store.Apply([]model.ResourceChange{{Key: resource.Key, New: &resource}})
	if err != nil {
		t.Fatal(err)
	}
	if !publication.Changed || publication.Snapshot.Len() != 2 {
		t.Fatalf("Apply publication = %#v, want changed two-resource snapshot", publication)
	}

	publication, err = store.Apply([]model.ResourceChange{{Key: model.ResourceKey{TypeURL: model.AddressType, Name: "invalid"}, New: &model.Resource{}}})
	if err == nil {
		t.Fatal("invalid resource was accepted")
	}
	if publication.Changed || publication.Snapshot.Len() != 2 {
		t.Fatalf("failed Apply publication = %#v, want unchanged two-resource snapshot", publication)
	}
}

func TestStoreUpdateCarriesPublicationTransition(t *testing.T) {
	oldResource := updateTestResource(t, model.AddressType, "address-key", "address", "old")
	newResource := updateTestResource(t, model.AddressType, "address-key", "address", "new")
	before, err := model.NewResourceSet([]model.Resource{oldResource})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(before)
	ctx := t.Context()
	updates := store.subscribeAll(ctx)

	if _, err := store.Apply([]model.ResourceChange{{Key: newResource.Key, New: &newResource}}); err != nil {
		t.Fatal(err)
	}
	update := <-updates

	if got, found := update.Before().Get(oldResource.Key); !found || got.Hash != oldResource.Hash {
		t.Fatalf("Before resource = (%#v, %v), want old resource", got, found)
	}
	if got, found := update.After().Get(newResource.Key); !found || got.Hash != newResource.Hash {
		t.Fatalf("After resource = (%#v, %v), want new resource", got, found)
	}
}

func TestMergeUpdatesCarriesPublicationTransition(t *testing.T) {
	resource := func(payload string) model.Resource {
		return updateTestResource(t, model.AddressType, "address-key", "address", payload)
	}
	oldResource := resource("old")
	middleResource := resource("middle")
	newResource := resource("new")
	snapshot := func(value model.Resource) model.ResourceSet {
		result, err := model.NewResourceSet([]model.Resource{value})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot(oldResource)
	middle := snapshot(middleResource)
	after := snapshot(newResource)

	merged := mergeUpdates(
		updateBetween(before, middle, []model.ResourceChange{{
			Key: oldResource.Key, Old: &oldResource, New: &middleResource,
		}}),
		updateBetween(middle, after, []model.ResourceChange{{
			Key: oldResource.Key, Old: &middleResource, New: &newResource,
		}}),
	)

	if got, _ := merged.Before().Get(oldResource.Key); got.Hash != oldResource.Hash {
		t.Fatalf("merged Before hash = %q, want %q", got.Hash, oldResource.Hash)
	}
	if got, _ := merged.After().Get(newResource.Key); got.Hash != newResource.Hash {
		t.Fatalf("merged After hash = %q, want %q", got.Hash, newResource.Hash)
	}
	changes := merged.ChangesForType(model.AddressType)
	if len(changes) != 1 || changes[0].Old.Hash != oldResource.Hash || changes[0].New.Hash != newResource.Hash {
		t.Fatalf("merged changes = %#v, want first-old/final-new", changes)
	}
}

func TestMergeUpdatesDropsRevertedTransitionChanges(t *testing.T) {
	oldResource := updateTestResource(t, model.AddressType, "address-key", "address", "old")
	middleResource := updateTestResource(t, model.AddressType, "address-key", "address", "middle")
	snapshot := func(value model.Resource) model.ResourceSet {
		result, err := model.NewResourceSet([]model.Resource{value})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot(oldResource)
	middle := snapshot(middleResource)
	after := snapshot(oldResource)

	merged := mergeUpdates(
		updateBetween(before, middle, []model.ResourceChange{{
			Key: oldResource.Key, Old: &oldResource, New: &middleResource,
		}}),
		updateBetween(middle, after, []model.ResourceChange{{
			Key: oldResource.Key, Old: &middleResource, New: &oldResource,
		}}),
	)

	if merged.Affects(model.AddressType) || len(merged.ChangesForType(model.AddressType)) != 0 {
		t.Fatalf("reverted transition remained dirty: %#v", merged.ChangesForType(model.AddressType))
	}
	if merged.Before().Version() != before.Version() || merged.After().Version() != after.Version() {
		t.Fatalf("reverted transition bounds = (%q, %q), want (%q, %q)",
			merged.Before().Version(), merged.After().Version(), before.Version(), after.Version())
	}
}

// This catches query methods that expose a store-owned index, fail to index a
// renamed resource by both of its wire identities, or return map-order output.
func TestUpdateQueriesIndexOldAndNewNamesWithoutExposingIndexes(t *testing.T) {
	old := updateTestResource(t, model.AddressType, "address-key", "old-name", "old", "old-alias")
	new := updateTestResource(t, model.AddressType, "address-key", "new-name", "new", "new-alias")
	second := updateTestResource(t, model.AddressType, "second-address-key", "second-name", "second")
	cluster := updateTestResource(t, model.ClusterType, "cluster-key", "cluster-name", "cluster")
	snapshot, err := model.NewResourceSet([]model.Resource{old})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(snapshot)
	ctx := t.Context()
	updates := store.subscribeAll(ctx)

	if publication, err := store.Apply([]model.ResourceChange{
		{Key: cluster.Key, New: &cluster},
		{Key: second.Key, New: &second},
		{Key: new.Key, New: &new},
	}); err != nil || !publication.Changed {
		t.Fatalf("Apply() = (%#v, %v), want changed publication and nil", publication, err)
	}
	update := <-updates

	if got, want := update.Version(), store.Snapshot().Version(); got != want {
		t.Fatalf("Version() = %q, want %q", got, want)
	}
	if !update.Affects(model.AddressType) || !update.Affects(model.ClusterType) || update.Affects(model.SecretType) {
		t.Fatalf("Affects() did not report the dirty types correctly")
	}
	if update.FullFor(model.AddressType) {
		t.Fatal("FullFor(Address) = true for a dirty update")
	}

	addressChanges := update.ChangesForType(model.AddressType)
	if len(addressChanges) != 2 {
		t.Fatalf("Address changes = %d, want 2", len(addressChanges))
	}
	if got := []string{addressChanges[0].Key.Name, addressChanges[1].Key.Name}; got[0] != "address-key" || got[1] != "second-address-key" {
		t.Fatalf("Address change order = %v, want ResourceKey order", got)
	}
	if got := update.ChangesForNames(model.AddressType, []string{"old-name", "old-alias", "new-name", "new-alias"}); len(got) != 1 {
		t.Fatalf("named changes = %d, want one deduplicated change", len(got))
	}
	if got := update.ChangesForNames(model.AddressType, []string{"old-alias", "new-name"}); got[0].Key != new.Key {
		t.Fatalf("named change key = %v, want %v", got[0].Key, new.Key)
	}

	addressChanges[0] = model.ResourceChange{}
	if got := update.ChangesForType(model.AddressType); got[0].Key != new.Key {
		t.Fatalf("ChangesForType returned a mutable store index: %#v", got)
	}
	namedChanges := update.ChangesForNames(model.AddressType, []string{"old-alias"})
	namedChanges[0] = model.ResourceChange{}
	if got := update.ChangesForNames(model.AddressType, []string{"new-name"}); got[0].Key != new.Key {
		t.Fatalf("ChangesForNames returned a mutable store index: %#v", got)
	}
}

func TestUpdateNameIndexIncludesCanonicalResourceKey(t *testing.T) {
	oldResource := updateTestResource(t, model.AddressType, "canonical-key", "wire-name", "old", "alias")
	newResource := updateTestResource(t, model.AddressType, "canonical-key", "wire-name", "new", "alias")
	update := updateFor("v2", []model.ResourceChange{{
		Key: oldResource.Key, Old: &oldResource, New: &newResource,
	}})

	changes := update.ChangesForNames(model.AddressType, []string{"canonical-key"})
	if len(changes) != 1 || changes[0].Key != oldResource.Key {
		t.Fatalf("canonical-key changes = %#v, want resource change", changes)
	}
}

func updateTestResource(t testing.TB, typeURL, keyName, xdsName, payload string, aliases ...string) model.Resource {
	t.Helper()
	facts := model.ResourceFacts{}
	if typeURL == model.AddressType {
		facts.Workload = &model.WorkloadResourceFacts{
			SandboxUID: keyName,
			Principal:  serviceAccountPrincipal("default", "default"),
		}
	}
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: typeURL, Name: keyName}, xdsName,
		&anypb.Any{TypeUrl: typeURL, Value: []byte(payload)}, aliases, facts)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}
