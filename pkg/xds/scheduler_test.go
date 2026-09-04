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
	"testing"
	"time"

	"github.com/openkruise/agentio/pkg/model"
)

func TestPushSchedulerMergesPendingUpdatesAndKeepsFIFOOrder(t *testing.T) {
	scheduler := NewPushScheduler(2)
	t.Cleanup(scheduler.Close)
	connectionA := newPushConnection(context.Background())
	connectionB := newPushConnection(context.Background())
	resourceA0 := addressResource(t, "cluster//Pod/demo/a", "a-0")
	resourceA1 := addressResource(t, "cluster//Pod/demo/a", "a-1")
	resourceA2 := addressResource(t, "cluster//Pod/demo/a", "a-2")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	updateA1 := updateFor("one", []model.ResourceChange{{Key: resourceA1.Key, Old: &resourceA0, New: &resourceA1}})
	updateA2 := updateFor("two", []model.ResourceChange{{Key: resourceA2.Key, Old: &resourceA1, New: &resourceA2}})
	updateB := updateFor("two", []model.ResourceChange{{Key: resourceB.Key, New: &resourceB}})

	scheduler.Enqueue(connectionA, updateA1)
	scheduler.Enqueue(connectionB, updateB)
	scheduler.Enqueue(connectionA, updateA2)

	first := scheduler.Next(context.Background())
	if first == nil || first.Connection != connectionA {
		t.Fatalf("first scheduled connection = %v, want connection A", first)
	}
	changes := first.Update.ChangesForType(model.AddressType)
	if first.Update.Version() != "two" || len(changes) != 1 || changes[0].Old == nil || changes[0].New == nil ||
		changes[0].Old.Hash != resourceA0.Hash || changes[0].New.Hash != resourceA2.Hash {
		t.Fatalf("first update = %#v, want version two and first-old/final-new A0 -> A2", first.Update)
	}
	second := scheduler.Next(context.Background())
	if second == nil || second.Connection != connectionB {
		t.Fatalf("second scheduled connection = %v, want connection B", second)
	}
	scheduler.Done(first)
	scheduler.Done(second)
}

func TestPushSchedulerRequeuesMergedUpdateAfterProcessing(t *testing.T) {
	scheduler := NewPushScheduler(2)
	t.Cleanup(scheduler.Close)
	connectionA := newPushConnection(context.Background())
	connectionB := newPushConnection(context.Background())
	resourceA0 := addressResource(t, "cluster//Pod/demo/a", "a-0")
	resourceA1 := addressResource(t, "cluster//Pod/demo/a", "a-1")
	resourceA2 := addressResource(t, "cluster//Pod/demo/a", "a-2")
	resourceA3 := addressResource(t, "cluster//Pod/demo/a", "a-3")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	updateA1 := updateFor("one", []model.ResourceChange{{Key: resourceA1.Key, Old: &resourceA0, New: &resourceA1}})
	updateA2 := updateFor("two", []model.ResourceChange{{Key: resourceA2.Key, Old: &resourceA1, New: &resourceA2}})
	updateA3 := updateFor("three", []model.ResourceChange{{Key: resourceA3.Key, Old: &resourceA2, New: &resourceA3}})
	updateB := updateFor("three", []model.ResourceChange{{Key: resourceB.Key, New: &resourceB}})

	scheduler.Enqueue(connectionA, updateA1)
	first := scheduler.Next(context.Background())
	scheduler.Enqueue(connectionA, updateA2)
	scheduler.Enqueue(connectionB, updateB)
	scheduler.Enqueue(connectionA, updateA3)
	scheduler.Done(first)

	second := scheduler.Next(context.Background())
	if second == nil || second.Connection != connectionB {
		t.Fatalf("second scheduled connection = %v, want already-pending connection B", second)
	}
	scheduler.Done(second)
	third := scheduler.Next(context.Background())
	if third == nil || third.Connection != connectionA {
		t.Fatalf("third scheduled connection = %v, want requeued connection A", third)
	}
	changes := third.Update.ChangesForType(model.AddressType)
	if third.Update.Version() != "three" || len(changes) != 1 || changes[0].Old == nil || changes[0].New == nil ||
		changes[0].Old.Hash != resourceA1.Hash || changes[0].New.Hash != resourceA3.Hash {
		t.Fatalf("requeued update = %#v, want merged-during-processing A1 -> A3", third.Update)
	}
	scheduler.Done(third)
}

func TestPushSchedulerPendingMergeKeepsFirstStartTime(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connection := newPushConnection(context.Background())

	before := time.Now()
	scheduler.Enqueue(connection, Update{version: "one", full: true})
	after := time.Now()
	scheduler.Enqueue(connection, Update{version: "two", full: true})

	push := scheduler.Next(context.Background())
	if push.Started.Before(before) || push.Started.After(after) {
		t.Fatalf("started = %v, want first enqueue window [%v, %v]", push.Started, before, after)
	}
	scheduler.Done(push)
}

func TestPushSchedulerProcessingMergeKeepsLaterBatchStartTime(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connection := newPushConnection(context.Background())
	scheduler.Enqueue(connection, Update{version: "one", full: true})
	first := scheduler.Next(context.Background())

	beforeLater := time.Now()
	scheduler.Enqueue(connection, Update{version: "two", full: true})
	afterLater := time.Now()
	scheduler.Enqueue(connection, Update{version: "three", full: true})
	scheduler.Done(first)

	second := scheduler.Next(context.Background())
	if second.Started.Before(beforeLater) || second.Started.After(afterLater) {
		t.Fatalf("started = %v, want later-batch window [%v, %v]", second.Started, beforeLater, afterLater)
	}
	scheduler.Done(second)
}

func TestPushSchedulerAcquiresCapacityBeforeAssignment(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connectionA := newPushConnection(context.Background())
	connectionB := newPushConnection(context.Background())
	resourceA := addressResource(t, "cluster//Pod/demo/a", "a")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	scheduler.Enqueue(connectionA, updateFor("one", []model.ResourceChange{{Key: resourceA.Key, New: &resourceA}}))
	scheduler.Enqueue(connectionB, updateFor("one", []model.ResourceChange{{Key: resourceB.Key, New: &resourceB}}))

	first := scheduler.Next(context.Background())
	next := make(chan *scheduledPush, 1)
	go func() { next <- scheduler.Next(context.Background()) }()
	select {
	case push := <-next:
		t.Fatalf("second push was assigned without capacity: %#v", push)
	case <-time.After(25 * time.Millisecond):
	}
	scheduler.Done(first)
	select {
	case push := <-next:
		if push == nil || push.Connection != connectionB {
			t.Fatalf("push after capacity release = %v, want connection B", push)
		}
		scheduler.Done(push)
	case <-time.After(time.Second):
		t.Fatal("second push was not assigned after capacity release")
	}
}

func TestPushSchedulerCancellationReleasesProcessingCapacity(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connectionContext, cancelConnection := context.WithCancel(context.Background())
	connectionA := newPushConnection(connectionContext)
	connectionB := newPushConnection(context.Background())
	resourceA := addressResource(t, "cluster//Pod/demo/a", "a")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	scheduler.Enqueue(connectionA, updateFor("one", []model.ResourceChange{{Key: resourceA.Key, New: &resourceA}}))
	first := scheduler.Next(context.Background())
	scheduler.Enqueue(connectionB, updateFor("one", []model.ResourceChange{{Key: resourceB.Key, New: &resourceB}}))

	cancelConnection()
	nextContext, cancelNext := context.WithTimeout(context.Background(), time.Second)
	defer cancelNext()
	second := scheduler.Next(nextContext)
	if second == nil || second.Connection != connectionB {
		t.Fatalf("push after connection cancellation = %v, want connection B", second)
	}
	// Completion may race cancellation, but it must remain idempotent and must
	// not release connection B's permit.
	scheduler.Done(first)
	scheduler.Done(second)
}

func TestPushSchedulerCanceledNextDoesNotConsumeCapacity(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connectionA := newPushConnection(context.Background())
	connectionB := newPushConnection(context.Background())
	resourceA := addressResource(t, "cluster//Pod/demo/a", "a")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	scheduler.Enqueue(connectionA, updateFor("one", []model.ResourceChange{{Key: resourceA.Key, New: &resourceA}}))
	first := scheduler.Next(context.Background())
	scheduler.Enqueue(connectionB, updateFor("one", []model.ResourceChange{{Key: resourceB.Key, New: &resourceB}}))

	nextContext, cancelNext := context.WithCancel(context.Background())
	cancelNext()
	if push := scheduler.Next(nextContext); push != nil {
		t.Fatalf("Next with canceled context = %#v, want nil", push)
	}
	scheduler.Done(first)
	second := scheduler.Next(context.Background())
	if second == nil || second.Connection != connectionB {
		t.Fatalf("push after canceled Next = %v, want connection B", second)
	}
	scheduler.Done(second)
}

func TestPushSchedulerDropsCanceledPendingConnection(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connectionA := newPushConnection(context.Background())
	canceledContext, cancelConnection := context.WithCancel(context.Background())
	connectionB := newPushConnection(canceledContext)
	connectionC := newPushConnection(context.Background())
	resourceA := addressResource(t, "cluster//Pod/demo/a", "a")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	resourceC := addressResource(t, "cluster//Pod/demo/c", "c")
	scheduler.Enqueue(connectionA, updateFor("one", []model.ResourceChange{{Key: resourceA.Key, New: &resourceA}}))
	first := scheduler.Next(context.Background())
	scheduler.Enqueue(connectionB, updateFor("one", []model.ResourceChange{{Key: resourceB.Key, New: &resourceB}}))
	scheduler.Enqueue(connectionC, updateFor("one", []model.ResourceChange{{Key: resourceC.Key, New: &resourceC}}))
	cancelConnection()
	scheduler.Done(first)

	nextContext, cancelNext := context.WithTimeout(context.Background(), time.Second)
	defer cancelNext()
	second := scheduler.Next(nextContext)
	if second == nil || second.Connection != connectionC {
		t.Fatalf("push after pending cancellation = %v, want connection C", second)
	}
	scheduler.Done(second)
}

func TestPushSchedulerCloseUnblocksNext(t *testing.T) {
	scheduler := NewPushScheduler(1)
	next := make(chan *scheduledPush, 1)
	go func() { next <- scheduler.Next(context.Background()) }()
	scheduler.Close()
	select {
	case push := <-next:
		if push != nil {
			t.Fatalf("Next after Close = %#v, want nil", push)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Next")
	}
}

// A connection waiting for a push slot must keep handling Delta subscription
// changes so on-demand lookups do not deadlock behind a slow connection.
func TestStreamProcessesRequestWhilePushWaitsForPermit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldResource := addressResource(t, "cluster//Pod/demo/old", "old")
	newResource := addressResource(t, "cluster//Pod/demo/new", "new")
	scheduler := NewPushScheduler(1)
	blocker := newPushConnection(context.Background())
	scheduler.Enqueue(blocker, Update{version: "blocker", full: true})
	held := scheduler.Next(context.Background())
	defer scheduler.Done(held)
	server := newTestServerWithScheduler(t, ztunnelScope(), []model.Resource{oldResource}, nil, scheduler)
	stream := newFakeStream(ctx, 4)
	done := server.start(stream)
	stream.send(nodeRequest(model.AddressType, oldResource.XDSName))
	stream.awaitResponses(t, model.AddressType, 1)

	if err := server.resources.apply([]model.ResourceChange{{Key: newResource.Key, New: &newResource}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	queued := false
	for time.Now().Before(deadline) {
		scheduler.mu.Lock()
		queued = len(scheduler.pending) == 1
		scheduler.mu.Unlock()
		if queued {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !queued {
		t.Fatal("push did not queue behind the occupied scheduler slot")
	}

	stream.send(request(model.AddressType, newResource.XDSName))
	deadline = time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(stream.responsesFor(model.AddressType)) >= 2 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream did not stop after cancellation")
	}
	t.Fatal("subscription response was blocked behind push capacity")
}
