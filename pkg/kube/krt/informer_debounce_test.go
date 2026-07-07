// Copyright Istio Authors
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

package krt_test

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/kclient/clienttest"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/test"
)

// TestInformerDebounceHasSyncedNotPremature is the regression for Bug 1:
// when debounce is enabled, HasSynced must not flip true before the initial
// events have actually been delivered to the handler.
func TestInformerDebounceHasSyncedNotPremature(t *testing.T) {
	stop := test.NewStop(t)
	client := kube.NewFakeClient()

	// Seed pods into the client BEFORE wiring the informer, so the informer's
	// initial cache sync delivers them via initialSync events.
	pc := clienttest.Wrap(t, kclient.New[*corev1.Pod](client))
	const N = 10
	for i := 0; i < N; i++ {
		pc.Create(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      fmt.Sprintf("p%d", i),
		}})
	}

	coll := krt.NewInformer[*corev1.Pod](client,
		krt.WithStop(stop),
		krt.WithDebounce(50*time.Millisecond, 500*time.Millisecond))

	var received atomic.Int64
	reg := coll.RegisterBatch(func(events []krt.Event[*corev1.Pod]) {
		received.Add(int64(len(events)))
	}, false)

	// Run the client AFTER RegisterBatch to reproduce Bug 1's exact sequencing:
	// RegisterBatch happens before baseSyncer.HasSynced() returns true.
	client.RunAndWait(stop)

	syncedAt := make(chan int64, 1)
	go func() {
		if reg.WaitUntilSynced(stop) {
			syncedAt <- received.Load()
		}
	}()

	select {
	case got := <-syncedAt:
		if got < int64(N) {
			t.Fatalf("HasSynced returned true with only %d/%d events delivered; "+
				"debounce defers Start to flush, initialFlushed must gate parent sync", got, N)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("WaitUntilSynced did not return within timeout; received=%d", received.Load())
	}
}

// TestInformerDebounceEmptyInitialList covers the empty-list edge case:
// HasSynced must become true within a reasonable timeout even if no events
// ever flow through the debouncer.
func TestInformerDebounceEmptyInitialList(t *testing.T) {
	stop := test.NewStop(t)
	client := kube.NewFakeClient()

	coll := krt.NewInformer[*corev1.Pod](client,
		krt.WithStop(stop),
		krt.WithDebounce(50*time.Millisecond, 500*time.Millisecond))

	client.RunAndWait(stop)

	reg := coll.RegisterBatch(func(_ []krt.Event[*corev1.Pod]) {}, false)

	done := make(chan bool, 1)
	go func() { done <- reg.WaitUntilSynced(stop) }()

	select {
	case ok := <-done:
		if !ok {
			t.Fatalf("WaitUntilSynced returned false")
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("HasSynced did not become true within 1s on empty initial list")
	}
}
