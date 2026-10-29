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

package registry

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestSourceLookupDoesNotWaitForEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		objects := krt.NewMutableCollection[model.Sandbox](nil, nil,
			krt.WithStop(t.Context().Done()), krt.WithDebounce(time.Second, time.Second))
		source := NewSource(objects.AsCollection())
		key := model.ResourceKey{TypeURL: model.SandboxType, Name: "kruise:example"}
		sandbox := model.Sandbox{
			UID:            "kruise:example",
			Namespace:      "demo",
			SourceIdentity: model.SourceIdentity{UID: "uid"},
		}
		objects.UpdateObject(sandbox)
		if got, found := source.Registry.Lookup(key); !found || got != sandbox.SourceIdentity {
			t.Fatalf("source missing before event delivery: %v, %v", got, found)
		}
		sandbox.SourceIdentity.UID = "replacement"
		objects.UpdateObject(sandbox)
		if got, found := source.Registry.Lookup(key); !found || got != sandbox.SourceIdentity {
			t.Fatalf("source identity lagged behind input: %v, %v", got, found)
		}
		objects.DeleteObject(sandbox.ResourceName())
		if _, found := source.Registry.Lookup(key); found {
			t.Fatal("deleted source still present before event delivery")
		}
	})
}

func TestSourceInitialStateCannotRetainDeletedObjects(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sandbox := model.Sandbox{
			UID:            "kruise:example",
			SourceIdentity: model.SourceIdentity{UID: "source"},
		}
		objects := krt.NewMutableCollection(nil, []model.Sandbox{sandbox}, krt.WithStop(t.Context().Done()))
		source := NewSource(objects.AsCollection())
		objects.DeleteObject(sandbox.UID)
		unregister := source.Registry.RegisterDeletes(func([]model.ResourceKey) {})
		defer unregister()
		if _, found := source.Registry.Lookup(sandbox.SourceKey()); found {
			t.Fatal("initial state retained an object deleted before subscription")
		}
		synctest.Wait()
		if _, found := source.Registry.Lookup(sandbox.SourceKey()); found {
			t.Fatal("initial replay resurrected a deleted object")
		}
	})
}

func TestSourceDeleteNotificationAndUnregister(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sandbox := model.Sandbox{
			UID:            "kruise:example",
			SourceIdentity: model.SourceIdentity{UID: "source"},
		}
		objects := krt.NewMutableCollection(nil, []model.Sandbox{sandbox}, krt.WithStop(t.Context().Done()))
		source := NewSource(objects.AsCollection())
		notifications := 0
		unregister := source.Registry.RegisterDeletes(func(keys []model.ResourceKey) {
			notifications++
			if len(keys) != 1 || keys[0] != sandbox.SourceKey() {
				t.Errorf("unexpected keys: %v", keys)
			}
			if _, found := source.Registry.Lookup(keys[0]); found {
				t.Error("deleted source observable inside notification")
			}
		})
		objects.DeleteObject(sandbox.UID)
		synctest.Wait()
		if notifications != 1 {
			t.Fatalf("got %d notifications, want 1", notifications)
		}
		unregister()
		objects.UpdateObject(sandbox)
		objects.DeleteObject(sandbox.UID)
		synctest.Wait()
		if notifications != 1 {
			t.Fatal("callback invoked after unregister")
		}
	})
}

func TestJoinedSourcesUseCollectionPrecedence(t *testing.T) {
	first := model.Sandbox{UID: "kruise:duplicate", SourceIdentity: model.SourceIdentity{UID: "first"}}
	second := first
	second.SourceIdentity.UID = "second"
	left := krt.NewMutableCollection(nil, []model.Sandbox{first}, krt.WithStop(t.Context().Done()))
	right := krt.NewMutableCollection(nil, []model.Sandbox{second}, krt.WithStop(t.Context().Done()))
	sources := NewSourceRegistry(NewSource(left.AsCollection()).Registry, NewSource(right.AsCollection()).Registry)
	if got, found := sources.Lookup(first.SourceKey()); !found || got != first.SourceIdentity {
		t.Fatalf("first source should win: %v, %v", got, found)
	}
	left.DeleteObject(first.UID)
	if got, found := sources.Lookup(second.SourceKey()); !found || got != second.SourceIdentity {
		t.Fatalf("fallback source not visible after preferred source deletion: %v, %v", got, found)
	}
}
