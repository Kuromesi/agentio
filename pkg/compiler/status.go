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

package compiler

import (
	"maps"
	"sync"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/metrics"
)

// failureRecorder tracks objects that currently fail to compile, keyed by kind/name; entries are cleared when the object compiles again.
type failureRecorder struct {
	mu       sync.Mutex
	failures map[string]string
}

func newFailureRecorder() *failureRecorder {
	return &failureRecorder{failures: make(map[string]string)}
}

func (r *failureRecorder) record(kind, name string, err error) {
	r.recordIf(kind, name, err, func() bool { return true })
}

func (r *failureRecorder) recordIf(kind, name string, err error, condition func() bool) {
	key := kind + "/" + name
	r.mu.Lock()
	if !condition() {
		r.mu.Unlock()
		return
	}
	previous, existed := r.failures[key]
	r.failures[key] = err.Error()
	count := len(r.failures)
	r.mu.Unlock()

	// Log only on transition or when the reason changes: a failing object is
	// retried on every recompute, and logging each attempt would flood.
	if !existed || previous != err.Error() {
		log.Warn("omitting object from snapshot", "key", key, "error", err)
	}
	metrics.Default.SetCompileFailingObjects(count)
}

func (r *failureRecorder) clear(kind, name string) {
	r.clearIf(kind, name, func() bool { return true })
}

func (r *failureRecorder) clearIf(kind, name string, condition func() bool) {
	key := kind + "/" + name
	r.mu.Lock()
	if !condition() {
		r.mu.Unlock()
		return
	}
	_, existed := r.failures[key]
	if existed {
		delete(r.failures, key)
	}
	count := len(r.failures)
	r.mu.Unlock()

	if existed {
		log.Info("object compiles again", "key", key)
		metrics.Default.SetCompileFailingObjects(count)
	}
}

func (r *failureRecorder) snapshot() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make(map[string]string, len(r.failures))
	maps.Copy(result, r.failures)
	return result
}

type namedFailureSource interface {
	ResourceName() string
}

// clearFailureOnSourceDelete handles the KRT delete path, which removes a
// transform's previous output without invoking the transform function itself.
// The current-key check prevents a delayed delete event from clearing a failure
// for a replacement object that already uses the same name.
func clearFailureOnSourceDelete[T namedFailureSource](
	collection krt.Collection[T],
	failures *failureRecorder,
	kind string,
) {
	collection.Register(func(event krt.Event[T]) {
		if event.New != nil {
			return
		}
		item := event.Latest()
		name := item.ResourceName()
		failures.clearIf(kind, name, func() bool {
			return collection.GetKey(name) == nil
		})
	})
}
