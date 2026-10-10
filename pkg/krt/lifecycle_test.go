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

package krt

import (
	"context"
	"testing"

	"istio.io/istio/pkg/test/util/assert"
)

func handlerCount[T any](handlers *handlerSet[T]) int {
	handlers.mu.RLock()
	defer handlers.mu.RUnlock()
	return len(handlers.handlers)
}

func TestCollectionDependencyHandlersLifecycle(t *testing.T) {
	parent := NewStaticCollection(nil, []allocationItem{{Name: "input"}}, WithStop(t.Context().Done()))
	dependency := NewStaticCollection(nil, []allocationItem{{Name: "dependency"}}, WithStop(t.Context().Done()))
	other := NewStaticCollection(nil, []allocationItem{{Name: "other"}}, WithStop(t.Context().Done()))
	for generation := range 3 {
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		result := NewCollection(parent, func(ctx HandlerContext, item allocationItem) *allocationItem {
			item.Value = FetchOne(ctx, dependency, FilterKey("dependency")).Value
			Fetch(ctx, dependency)
			Fetch(ctx, other)
			return &item
		}, WithStop(ctx.Done()))
		assert.EventuallyEqual(t, result.HasSynced, true)
		assert.Equal(t, handlerCount(parent.eventHandlers), 1)
		assert.Equal(t, handlerCount(dependency.eventHandlers), 1)
		assert.Equal(t, handlerCount(other.eventHandlers), 1)
		dependency.UpdateObject(allocationItem{Name: "dependency", Value: generation + 1})
		assert.EventuallyEqual(t, func() int { return result.GetKey("input").Value }, generation+1)
		cancel()
		assert.EventuallyEqual(t, func() int { return handlerCount(parent.eventHandlers) }, 0)
		assert.EventuallyEqual(t, func() int { return handlerCount(dependency.eventHandlers) }, 0)
		assert.EventuallyEqual(t, func() int { return handlerCount(other.eventHandlers) }, 0)
	}
}

type waitingRegistration struct {
	HandlerRegistration
	entered chan struct{}
}

func (r waitingRegistration) WaitUntilSynced(stop <-chan struct{}) bool {
	close(r.entered)
	<-stop
	return false
}

type waitingRegistrationCollection struct {
	internalCollection[allocationItem]
	entered chan struct{}
}

func (c waitingRegistrationCollection) RegisterBatch(
	f func([]Event[allocationItem]),
	existing bool,
) HandlerRegistration {
	return waitingRegistration{HandlerRegistration: c.internalCollection.RegisterBatch(f, existing), entered: c.entered}
}

func TestCollectionDependencyRegistrationCancelled(t *testing.T) {
	for _, phase := range []string{"dependency sync", "registration sync"} {
		t.Run(phase, func(t *testing.T) {
			parent := NewStaticCollection(nil, []allocationItem{{Name: "input"}}, WithStop(t.Context().Done()))
			ready := make(chan struct{})
			var syncer Syncer
			if phase == "dependency sync" {
				syncer = channelSyncer{synced: ready}
			}
			dependency := NewStaticCollection[allocationItem](syncer, nil, WithStop(t.Context().Done()))
			entered := make(chan struct{})
			var source Collection[allocationItem] = dependency
			if phase == "registration sync" {
				source = waitingRegistrationCollection{internalCollection: dependency, entered: entered}
			}
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			result := NewCollection(parent, func(ctx HandlerContext, item allocationItem) *allocationItem {
				if phase == "dependency sync" {
					close(entered)
				}
				Fetch(ctx, source)
				return &item
			}, WithStop(ctx.Done()))
			assert.EventuallyEqual(t, func() bool {
				select {
				case <-entered:
					return true
				default:
					return false
				}
			}, true)
			cancel()
			assert.EventuallyEqual(t, func() bool {
				select {
				case <-result.(*manyCollection[allocationItem, allocationItem]).queue.Closed():
					return true
				default:
					return false
				}
			}, true)
			assert.EventuallyEqual(t, func() int { return handlerCount(parent.eventHandlers) }, 0)
			assert.EventuallyEqual(t, func() int { return handlerCount(dependency.eventHandlers) }, 0)
		})
	}
}
