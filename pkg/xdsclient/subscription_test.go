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

package xdsclient

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"testing"
	"testing/synctest"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// The transport is unused here; the bubble drives the subscription state
// machine while Demand callers wait, without timing-dependent sleeps.
func withSubscriptionClient(t *testing.T, watch Watch, check func(*testing.T, *Client)) {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///unused", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		client, err := New(conn, Config{Node: &core.Node{Id: "test"}, Watches: []Watch{watch}})
		if err != nil {
			t.Fatal(err)
		}
		check(t, client)
	})
}

func beginDemand(ctx context.Context, client *Client, name string) <-chan error {
	result := make(chan error, 1)
	go func() {
		_, err := client.Demand(ctx, testType, name)
		result <- err
	}()
	synctest.Wait()
	return result
}

func publishString(t *testing.T, client *Client, name, value string, aliases ...string) {
	t.Helper()
	wire, err := anypb.New(wrapperspb.String(value))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.apply(&discovery.DeltaDiscoveryResponse{TypeUrl: testType,
		Resources: []*discovery.Resource{{Name: name, Resource: wire, Aliases: aliases}},
	}); err != nil {
		t.Fatal(err)
	}
}

func removeNames(t *testing.T, client *Client, names ...string) {
	t.Helper()
	if err := client.apply(&discovery.DeltaDiscoveryResponse{TypeUrl: testType, RemovedResources: names}); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteSubscriptionPolicy(t *testing.T) {
	for _, release := range []bool{false, true} {
		watch := Watch{TypeURL: testType}
		if release {
			watch.OnDelete = func(string) DeleteAction { return ReleaseSubscription }
		}
		withSubscriptionClient(t, watch, func(t *testing.T, client *Client) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			first := beginDemand(ctx, client, "a")
			sent := map[string]map[string]*subscription{}
			client.initialRequests(sent)
			removeNames(t, client, "a")
			if err := <-first; !errors.Is(err, ErrNotFound) {
				t.Fatal(err)
			}
			requests := client.pendingRequests(sent)
			if !release {
				if len(requests) != 0 || len(client.types[testType].names) != 1 {
					t.Fatal("default watch was released")
				}
				publishString(t, client, "a", "recreated")
				if _, err := client.Demand(ctx, testType, "a"); err != nil {
					t.Fatal(err)
				}
				return
			}
			if len(requests) != 1 || !slices.Equal(requests[0].ResourceNamesUnsubscribe, []string{"a"}) {
				t.Fatalf("missing unsubscribe: %v", requests)
			}
			if len(client.types[testType].names) != 0 || len(client.types[testType].removed) != 0 {
				t.Fatal("deleted demand retained subscription or tombstone")
			}
			client.reset()
			reconnect := client.initialRequests(map[string]map[string]*subscription{})
			if !slices.Equal(reconnect[0].ResourceNamesSubscribe, []string{"*"}) ||
				!slices.Equal(reconnect[0].ResourceNamesUnsubscribe, []string{"*"}) {
				t.Fatalf("released name replayed: %v", reconnect)
			}
			next := beginDemand(ctx, client, "b")
			publishString(t, client, "b", "new")
			if err := <-next; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRedemandSupersedesPendingUnsubscribe(t *testing.T) {
	withSubscriptionClient(
		t,
		Watch{TypeURL: testType, OnDelete: func(string) DeleteAction { return ReleaseSubscription }},
		func(t *testing.T, client *Client) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			waiters := []<-chan error{beginDemand(ctx, client, "a"), beginDemand(ctx, client, "a")}
			sent := map[string]map[string]*subscription{}
			client.initialRequests(sent)
			removeNames(t, client, "a")
			// Re-publication before waiters resume cannot turn the old deletion
			// into success, nor make the next demand inherit the old tombstone.
			publishString(t, client, "a", "recreated")
			for _, waiter := range waiters {
				if err := <-waiter; !errors.Is(err, ErrNotFound) {
					t.Fatal(err)
				}
			}
			if _, err := client.Demand(ctx, testType, "a"); err != nil {
				t.Fatal(err)
			}
			requests := client.pendingRequests(sent)
			if len(requests) != 1 || !slices.Equal(requests[0].ResourceNamesSubscribe, []string{"a"}) ||
				len(requests[0].ResourceNamesUnsubscribe) != 0 {
				t.Fatalf("old unsubscribe overrode new demand: %v", requests)
			}
			if len(client.pendingRequests(sent)) != 0 {
				t.Fatal("duplicate subscription")
			}
		},
	)
}

func TestReleasedAliasesPreserveWildcardAndOtherOwners(t *testing.T) {
	withSubscriptionClient(
		t,
		Watch{TypeURL: testType, Wildcard: true, OnDelete: func(string) DeleteAction { return ReleaseSubscription }},
		func(t *testing.T, client *Client) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			publishString(t, client, "a", "a", "shared")
			if _, err := client.Demand(ctx, testType, "a"); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Demand(ctx, testType, "shared"); err != nil {
				t.Fatal(err)
			}
			publishString(t, client, "b", "b", "shared")
			sent := map[string]map[string]*subscription{}
			client.initialRequests(sent)
			removeNames(t, client, "a")
			if _, err := client.Demand(ctx, testType, "shared"); err != nil {
				t.Fatal(err)
			}
			requests := client.pendingRequests(sent)
			if len(requests) != 1 || !slices.Equal(requests[0].ResourceNamesUnsubscribe, []string{"a"}) {
				t.Fatal(requests)
			}
			removeNames(t, client, "b")
			requests = client.pendingRequests(sent)
			if len(requests) != 1 || !slices.Equal(requests[0].ResourceNamesUnsubscribe, []string{"shared"}) {
				t.Fatal(requests)
			}
			initial := client.initialRequests(map[string]map[string]*subscription{})
			if !slices.Equal(initial[0].ResourceNamesSubscribe, []string{"*"}) ||
				len(initial[0].ResourceNamesUnsubscribe) != 0 {
				t.Fatal("wildcard lost")
			}
		},
	)
}

func TestDemandCancellationDoesNotReleaseAnotherWaiter(t *testing.T) {
	withSubscriptionClient(
		t,
		Watch{TypeURL: testType, OnDelete: func(string) DeleteAction { return ReleaseSubscription }},
		func(t *testing.T, client *Client) {
			ctx, cancel := context.WithCancel(t.Context())
			first := beginDemand(ctx, client, "a")
			second := beginDemand(t.Context(), client, "a")
			cancel()
			if err := <-first; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			publishString(t, client, "a", "ready")
			if err := <-second; err != nil {
				t.Fatal(err)
			}
		},
	)
}

func TestSubscriptionsAreUnlimited(t *testing.T) {
	withSubscriptionClient(t, Watch{TypeURL: testType}, func(t *testing.T, client *Client) {
		const count = 10001
		wire, err := anypb.New(wrapperspb.String("value"))
		if err != nil {
			t.Fatal(err)
		}
		resources := make([]*discovery.Resource, count)
		for i := range resources {
			resources[i] = &discovery.Resource{Name: strconv.Itoa(i), Resource: wire}
		}
		if err := client.apply(&discovery.DeltaDiscoveryResponse{TypeUrl: testType, Resources: resources}); err != nil {
			t.Fatal(err)
		}
		for _, resource := range resources {
			if _, err := client.Demand(t.Context(), testType, resource.Name); err != nil {
				t.Fatalf("demand %s: %v", resource.Name, err)
			}
		}
		if got := len(client.types[testType].names); got != count {
			t.Fatalf("got %d subscriptions, want %d", got, count)
		}
	})
}

func TestReconnectRetainsSnapshotButDemandsFreshResources(t *testing.T) {
	for _, wildcard := range []bool{false, true} {
		withSubscriptionClient(t, Watch{TypeURL: testType, Wildcard: wildcard}, func(t *testing.T, client *Client) {
			publishString(t, client, "a", "old", "old-alias")
			if _, err := client.Demand(t.Context(), testType, "a"); err != nil {
				t.Fatal(err)
			}
			before := client.Snapshot()
			client.reset()
			disconnected := client.Snapshot()
			if disconnected.Connected || disconnected.Synced[testType] ||
				disconnected.Resources[testType]["a"] != before.Resources[testType]["a"] {
				t.Fatal("disconnect discarded the last publication or retained readiness")
			}
			initial := client.initialRequests(map[string]map[string]*subscription{})
			if !slices.Contains(initial[0].ResourceNamesSubscribe, "a") ||
				len(initial[0].InitialResourceVersions) != 0 {
				t.Fatal("reconnect did not request fresh subscribed data")
			}
			waiting := beginDemand(t.Context(), client, "a")
			wrong, err := anypb.New(wrapperspb.Bool(true))
			if err != nil {
				t.Fatal(err)
			}
			if err := client.apply(&discovery.DeltaDiscoveryResponse{TypeUrl: testType,
				Resources: []*discovery.Resource{{Name: "a", Resource: wrong}},
			}); err == nil {
				t.Fatal("invalid first response accepted")
			}
			if client.Snapshot().Resources[testType]["a"] != before.Resources[testType]["a"] {
				t.Fatal("rejected first response discarded retained data")
			}
			// A response for another name makes the type synchronized, but must
			// neither resurrect old data nor finish a pending demand for a.
			publishString(t, client, "b", "fresh")
			synctest.Wait()
			select {
			case err := <-waiting:
				t.Fatalf("unanswered demand finished with %v", err)
			default:
			}
			after := client.Snapshot()
			if !after.Synced[testType] || after.Resources[testType]["a"] != nil ||
				client.types[testType].aliases["old-alias"] != "" {
				t.Fatal("fresh response retained old resources or aliases")
			}
			removeNames(t, client, "a")
			if err := <-waiting; !errors.Is(err, ErrNotFound) {
				t.Fatal(err)
			}
			if before.Resources[testType]["a"] == nil {
				t.Fatal("resynchronization mutated an older snapshot")
			}
		})
	}
}

func TestEmptyReconnectResponseReplacesRetainedCache(t *testing.T) {
	withSubscriptionClient(t, Watch{TypeURL: testType, Wildcard: true}, func(t *testing.T, client *Client) {
		publishString(t, client, "removed-offline", "old")
		client.reset()
		if err := client.apply(&discovery.DeltaDiscoveryResponse{TypeUrl: testType}); err != nil {
			t.Fatal(err)
		}
		snapshot := client.Snapshot()
		if !snapshot.Synced[testType] || len(snapshot.Resources[testType]) != 0 {
			t.Fatal("empty fresh response retained resources deleted offline")
		}
	})
}
