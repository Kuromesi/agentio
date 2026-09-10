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

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/model"
)

var _ Subscription = (*subscription)(nil)

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

	store := New(newSnapshot(t))
	subscription := store.Subscribe(t.Context())
	subscription.Watch(model.ClusterType)
	subscription.Watch(model.ListenerType)
	cluster := updateTestResource(t, model.ClusterType, "cluster-key", "cluster", "cluster")
	listener := updateTestResource(t, model.ListenerType, "listener-key", "listener", "listener")
	publication, err := store.Apply([]model.ResourceChange{
		{Key: listener.Key, New: &listener},
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
	wantTypes := []string{model.ClusterType, model.ListenerType}
	if !slices.Equal(entry.Types, wantTypes) {
		t.Fatalf("incremental push types = %v, want %v", entry.Types, wantTypes)
	}
}

// Publication returns the committed snapshot on every path, so Controller can
// record metrics without racing a later Store commit by rereading it.
func TestStorePublicationCarriesCommittedSnapshot(t *testing.T) {
	initial := newSnapshot(t, "a")
	store := New(initial)

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
	store := New(before)
	ctx := t.Context()
	subscription := store.Subscribe(ctx)
	subscription.Watch(model.AddressType)
	updates := subscription.Updates()

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

	merged := Merge(
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

	merged := Merge(
		updateBetween(before, middle, []model.ResourceChange{{
			Key: oldResource.Key, Old: &oldResource, New: &middleResource,
		}}),
		updateBetween(middle, after, []model.ResourceChange{{
			Key: oldResource.Key, Old: &middleResource, New: &oldResource,
		}}),
	)

	if merged.Affects(model.AddressType) || len(merged.ChangesForType(model.AddressType)) != 0 {
		t.Fatalf("reverted transition still contains changes: %#v", merged.ChangesForType(model.AddressType))
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
	store := New(snapshot)
	ctx := t.Context()
	subscription := store.Subscribe(ctx)
	subscription.Watch(model.AddressType)
	subscription.Watch(model.ClusterType)
	updates := subscription.Updates()

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
		t.Fatalf("Affects() did not report the affected types correctly")
	}
	if update.FullFor(model.AddressType) {
		t.Fatal("FullFor(Address) = true for a incremental update")
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
			WorkloadUID: keyName,
			Principal:   serviceAccountPrincipal("default", "default"),
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

// Replacing a snapshot whose version has not changed is a no-op: every connected
// client would otherwise be woken to compute an empty diff.
func TestReplaceIgnoresUnchangedVersion(t *testing.T) {
	first := newSnapshot(t, "a")
	store := New(first)

	if store.Replace(newSnapshot(t, "a")).Changed {
		t.Fatal("republishing identical content reported a change")
	}
	if !store.Replace(newSnapshot(t, "a", "b")).Changed {
		t.Fatal("replacing with new content did not report a change")
	}
	if got := store.Snapshot().Len(); got != 2 {
		t.Fatalf("snapshot length = %d, want 2", got)
	}
}

// A subscriber is woken by a publish, with repeated wake-ups coalesced: the
// consumer re-reads the current snapshot.
func TestSubscribersAreWokenAndCoalesced(t *testing.T) {
	ctx := t.Context()
	store := New(newSnapshot(t, "a"))
	subscription := store.Subscribe(ctx)
	subscription.Watch(model.AddressType)
	updates := subscription.Updates()

	store.Replace(newSnapshot(t, "a", "b"))
	store.Replace(newSnapshot(t, "a", "b", "c"))

	select {
	case <-updates:
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber was not woken")
	}
	// The snapshot the consumer reads is the latest, regardless of how many
	// wake-ups were folded together.
	if got := store.Snapshot().Len(); got != 3 {
		t.Fatalf("snapshot length = %d, want 3", got)
	}
}

// A WDS-only connection must not wake on unrelated gateway updates.
func TestTypedSubscriberIsOnlyWokenForWatchedType(t *testing.T) {
	ctx := t.Context()
	store := New(newSnapshot(t))
	subscription := store.Subscribe(ctx)
	subscription.Watch(model.AddressType)

	cluster := model.Resource{
		Key:   model.ResourceKey{TypeURL: model.ClusterType, Name: "cluster-a"},
		Value: &anypb.Any{TypeUrl: model.ClusterType, Value: []byte("cluster")},
	}
	if _, err := store.Apply([]model.ResourceChange{{Key: cluster.Key, New: &cluster}}); err != nil {
		t.Fatal(err)
	}
	select {
	case update := <-subscription.Updates():
		t.Fatalf("unrelated update woke Address subscriber: %#v", update)
	case <-time.After(50 * time.Millisecond):
	}

	address := newSnapshot(t, "a").List(model.AddressType)[0]
	if _, err := store.Apply([]model.ResourceChange{{Key: address.Key, New: &address}}); err != nil {
		t.Fatal(err)
	}
	select {
	case update := <-subscription.Updates():
		changes := update.ChangesForType(model.AddressType)
		if len(changes) != 1 || changes[0].Key != address.Key || changes[0].New == nil {
			t.Fatalf("incremental update = %#v, want address add", update)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watched Address update did not wake subscriber")
	}
}

// A slow connection keeps one pending notification, but that notification must
// union key-level changes so a deletion or update is not lost while it sends an
// earlier response.
func TestSubscriberCoalescingMergesChangedKeys(t *testing.T) {
	ctx := t.Context()
	store := New(newSnapshot(t))
	subscription := store.Subscribe(ctx)
	subscription.Watch(model.AddressType)

	for _, name := range []string{"a", "b"} {
		resource := newSnapshot(t, name).List(model.AddressType)[0]
		if _, err := store.Apply([]model.ResourceChange{{Key: resource.Key, New: &resource}}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case update := <-subscription.Updates():
		changes := update.ChangesForType(model.AddressType)
		if len(changes) != 2 {
			t.Fatalf("merged changed keys = %d, want 2", len(changes))
		}
		for _, name := range []string{"a", "b"} {
			key := model.ResourceKey{TypeURL: model.AddressType, Name: name}
			if got := update.ChangesForNames(model.AddressType, []string{name}); len(got) != 1 || got[0].Key != key || got[0].New == nil {
				t.Fatalf("missing changed key %v in %#v", key, changes)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber was not woken")
	}
}

func TestTypedFullUpdateDoesNotHideIncrementalOtherType(t *testing.T) {
	ctx := t.Context()
	store := New(newSnapshot(t))
	subscription := store.Subscribe(ctx)
	subscription.Watch(model.AddressType)
	subscription.Watch(model.SecretType)
	address := newSnapshot(t, "a").List(model.AddressType)[0]
	if _, err := store.Apply([]model.ResourceChange{{Key: address.Key, New: &address}}); err != nil {
		t.Fatal(err)
	}
	store.NotifyType(model.SecretType)

	select {
	case update := <-subscription.Updates():
		if !update.Affects(model.AddressType) || !update.Affects(model.SecretType) {
			t.Fatalf("merged update lost an affected type: %#v", update)
		}
		if update.FullFor(model.AddressType) || !update.FullFor(model.SecretType) {
			t.Fatalf("full regeneration scope is wrong: %#v", update)
		}
		if changes := update.ChangesForNames(model.AddressType, []string{address.XDSName}); len(changes) != 1 || changes[0].Key != address.Key || changes[0].New == nil {
			t.Fatalf("Address changed key was lost: %#v", changes)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber was not woken")
	}
}

// Notify exists for resources that live outside the snapshot -- on-demand
// certificates -- and must wake subscribers without changing the version.
func TestNotifyWakesSubscribersWithoutVersionChange(t *testing.T) {
	ctx := t.Context()
	store := New(newSnapshot(t, "a"))
	version := store.Snapshot().Version()
	subscription := store.Subscribe(ctx)
	subscription.Watch(model.AddressType)
	updates := subscription.Updates()

	store.Notify()
	select {
	case update := <-updates:
		if update.Version() != version {
			t.Fatalf("notify changed the version: %s != %s", update.Version(), version)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Notify did not wake the subscriber")
	}
}

func newSnapshot(t testing.TB, names ...string) model.ResourceSet {
	t.Helper()
	resources := make([]model.Resource, 0, len(names))
	for _, name := range names {
		value, err := anypb.New(&workloadv1.Address{Type: &workloadv1.Address_Workload{
			Workload: &workloadv1.Workload{Uid: name, Name: name},
		}})
		if err != nil {
			t.Fatal(err)
		}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: name}, "", value, nil,
			model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				WorkloadUID: name,
				Principal:   serviceAccountPrincipal("default", "default"),
			}})
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, resource)
	}
	set, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func eventually(t testing.TB, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition never held: %s", message)
}

func serviceAccountPrincipal(namespace, serviceAccount string) model.Principal {
	return model.Principal{
		Kind:        model.PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: model.ServiceAccountRef{
			Namespace:      namespace,
			ServiceAccount: serviceAccount,
		},
	}
}

// Cancellation releases both the subscriber and any type-index entries.
func TestSubscriberIsReleasedOnContextCancel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		watch bool
	}{
		{name: "before watch"}, {name: "after watch", watch: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := New(newSnapshot(t, "a"))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			subscription := store.Subscribe(ctx)
			if tc.watch {
				subscription.Watch(model.AddressType)
			}
			cancel()
			eventually(t, func() bool {
				store.mu.RLock()
				defer store.mu.RUnlock()
				return len(store.subscribers) == 0 && len(store.subscribersByType) == 0
			}, "subscriber and watched-type index released after cancel")
		})
	}
}
