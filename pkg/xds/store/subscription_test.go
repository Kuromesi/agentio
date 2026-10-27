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
	"context"
	"slices"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/model"
)

func TestNamedNotificationsRetainOnlyRelevantCandidates(t *testing.T) {
	store := New(newSnapshot(t))
	a := store.Subscribe(t.Context())
	b := store.Subscribe(t.Context())
	all := store.Subscribe(t.Context())
	a.WatchNames(model.SandboxType, false, []string{"a"}, nil)
	b.WatchNames(model.SandboxType, false, []string{"b"}, nil)
	all.Watch(model.SandboxType)
	first := notificationSandbox(t, "a", "", "first")
	second := notificationSandbox(t, "b", "", "second")
	if _, err := store.Apply(
		[]model.ResourceChange{{Key: first.Key, New: &first}, {Key: second.Key, New: &second}},
	); err != nil {
		t.Fatal(err)
	}
	// Do not drain a: its creation, migration and deletion must coalesce without
	// pulling another Sandbox into the retained update.
	first = notificationSandbox(t, "a", "new-worker", "moved")
	if _, err := store.Apply([]model.ResourceChange{{Key: first.Key, New: &first}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply([]model.ResourceChange{{Key: first.Key}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		sub  Subscription
		want []string
	}{{a, []string{"a"}}, {b, []string{"b"}}, {all, []string{"a", "b"}}} {
		select {
		case update := <-tc.sub.Updates():
			var names []string
			for _, c := range update.Candidates(model.SandboxType) {
				names = append(names, c.Key.Name)
			}
			if !slices.Equal(names, tc.want) {
				t.Fatalf("candidates=%v, want %v", names, tc.want)
			}
			if len(tc.want) == 1 && tc.want[0] == "a" && len(update.Candidates(model.SandboxType)[0].Identities) != 2 {
				t.Fatal("lost pre-migration identity")
			}
		default:
			t.Fatal("missing notification")
		}
	}
}

func TestNamedNotificationWildcardTransitions(t *testing.T) {
	store := New(newSnapshot(t))
	sub := store.Subscribe(t.Context())
	sub.WatchNames(model.SandboxType, false, []string{"a"}, nil)
	sub.WatchNames(model.SandboxType, true, []string{"*"}, nil)
	b := notificationSandbox(t, "b", "", "b")
	if _, err := store.Apply([]model.ResourceChange{{Key: b.Key, New: &b}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sub.Updates():
	default:
		t.Fatal("wildcard missed unrelated name")
	}
	sub.WatchNames(model.SandboxType, false, nil, []string{"*"})
	if _, err := store.Apply([]model.ResourceChange{{Key: b.Key}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sub.Updates():
		t.Fatal("wildcard unsubscribe left broad interest")
	default:
	}
	a := notificationSandbox(t, "a", "", "a")
	if _, err := store.Apply([]model.ResourceChange{{Key: a.Key, New: &a}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sub.Updates():
	default:
		t.Fatal("wildcard transition lost retained named interest")
	}
	store.NotifyType(model.SecretType)
	select {
	case <-sub.Updates():
		t.Fatal("unwatched type notified named watcher")
	default:
	}
	store.NotifyType(model.SandboxType)
	select {
	case u := <-sub.Updates():
		if !u.FullFor(model.SandboxType) {
			t.Fatal("lost full refresh")
		}
	default:
		t.Fatal("named watcher missed type refresh")
	}
	store.Notify()
	select {
	case u := <-sub.Updates():
		if !u.FullFor(model.SandboxType) {
			t.Fatal("lost global refresh")
		}
	default:
		t.Fatal("named watcher missed global refresh")
	}
}

func TestNamedNotificationIndexesReleased(t *testing.T) {
	store := New(newSnapshot(t))
	ctx, cancel := context.WithCancel(t.Context())
	sub := store.Subscribe(ctx)
	sub.WatchNames(model.SandboxType, false, []string{"a", "b"}, nil)
	sub.Watch(model.AddressType)
	sub.WatchWorkload(model.WorkloadType, "worker")
	cancel()
	eventually(t, func() bool {
		store.mu.RLock()
		defer store.mu.RUnlock()
		return len(store.subscribers) == 0 && len(store.subscribersByType) == 0 && len(store.subscribersByName) == 0 &&
			len(store.wildcardSubscribersByType) == 0 &&
			len(store.subscribersByWorkload) == 0
	}, "all subscription indexes released")
	sub.WatchNames(model.SandboxType, false, []string{"late"}, nil)
	store.mu.RLock()
	defer store.mu.RUnlock()
	if len(store.subscribersByName) != 0 {
		t.Fatal("request racing cancellation leaked an interest")
	}
}

func TestWorkloadNotificationsRetainMigrationAndSharedDependencies(t *testing.T) {
	for _, typeURL := range []string{model.AddressType, model.WorkloadType} {
		t.Run(typeURL, func(t *testing.T) {
			store := New(newSnapshot(t))
			a, b := store.Subscribe(t.Context()), store.Subscribe(t.Context())
			a.WatchWorkload(typeURL, "a")
			b.WatchWorkload(typeURL, "b")
			workload := func(uid string) Identity {
				return Identity{
					Name:  "worker",
					Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{WorkloadUID: uid}},
				}
			}
			for _, tc := range []struct {
				name       string
				identities []Identity
				wantA      bool
				wantB      bool
			}{
				{"own workload", []Identity{workload("a")}, true, false},
				{"migration", []Identity{workload("a"), workload("b")}, true, true},
				{"other workload", []Identity{workload("other")}, false, false},
				{"service", []Identity{{Name: "svc", Facts: model.ResourceFacts{Service: &model.ServiceResourceFacts{ServiceKey: "svc"}}}}, true, true},
				{"gateway", []Identity{{Name: "gw", Facts: model.ResourceFacts{GatewayOwner: "gw", Workload: &model.WorkloadResourceFacts{WorkloadUID: "gw"}}}}, true, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					candidate := Candidate{
						Key:        model.ResourceKey{TypeURL: model.AddressType, Name: "candidate"},
						Identities: tc.identities,
					}
					update := candidateUpdate("v1", model.AddressType, []Candidate{candidate})
					store.mu.Lock()
					store.notifyLocked(update)
					store.mu.Unlock()
					for _, check := range []struct {
						sub  Subscription
						want bool
					}{{a, tc.wantA}, {b, tc.wantB}} {
						notified := false
						select {
						case u := <-check.sub.Updates():
							notified = true
							if len(u.Candidates(typeURL)) != 1 ||
								len(u.Candidates(typeURL)[0].Identities) != len(tc.identities) {
								t.Fatal("lost dependency or migration identities")
							}
						default:
						}
						if notified != check.want {
							t.Fatalf("notified=%v, want %v", notified, check.want)
						}
					}
				})
			}
		})
	}
}

func notificationSandbox(t testing.TB, name, attester, value string) model.Resource {
	t.Helper()
	r, err := model.NewResource(
		model.ResourceKey{TypeURL: model.SandboxType, Name: name},
		"",
		&anypb.Any{TypeUrl: model.SandboxType, Value: []byte(value)},
		nil,
		model.ResourceFacts{Sandbox: &model.SandboxResourceFacts{AttesterWorkloadUID: attester}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
