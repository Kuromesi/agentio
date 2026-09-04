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

package controllers

import (
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

func TestQueueRetriesUpToMaxAttempts(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	q := NewQueue("test",
		WithReconciler(func(key types.NamespacedName) error {
			mu.Lock()
			defer mu.Unlock()
			attempts++
			if attempts < 3 {
				return errTestRetry
			}
			return nil
		}),
		WithMaxAttempts(5))
	stop := make(chan struct{})
	defer close(stop)
	go q.Run(stop)
	q.Add(types.NamespacedName{Namespace: "ns", Name: "gw"})
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		done := attempts >= 3
		mu.Unlock()
		if done {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("reconciler retried %d times, want 3", attempts)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestQueueDeduplicatesPendingKeys(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	release := make(chan struct{})
	q := NewQueue("test", WithReconciler(func(types.NamespacedName) error {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release
		return nil
	}))
	stop := make(chan struct{})
	defer close(stop)
	go q.Run(stop)
	key := types.NamespacedName{Namespace: "ns", Name: "gw"}
	q.Add(key)
	// Wait for the first reconcile to start, then pile on duplicates.
	time.Sleep(50 * time.Millisecond)
	q.Add(key)
	q.Add(key)
	q.Add(key)
	close(release)
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls > 2 {
		t.Fatalf("duplicate keys were not collapsed: %d reconciles", calls)
	}
}

var errTestRetry = errTest("retry")

type errTest string

func (e errTest) Error() string { return string(e) }
