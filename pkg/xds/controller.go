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
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/util/nilutil"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// CompiledResources is the compiler output that the controller publishes.
type CompiledResources interface {
	Snapshot() (model.ResourceSet, error)
	Resources() krt.EventStream[model.Resource]
}

// ResourcePublisher atomically commits compiled snapshots and changes.
type ResourcePublisher interface {
	Replace(model.ResourceSet) xdsstore.Publication
	Apply([]model.ResourceChange) (xdsstore.Publication, error)
}

type Controller struct {
	source   CompiledResources
	store    ResourcePublisher
	quiet    time.Duration
	maximum  time.Duration
	triggers chan struct{}

	mu          sync.Mutex
	pendingFull bool
	changes     map[model.ResourceKey]model.ResourceChange
}

func NewController(source CompiledResources, store ResourcePublisher, quiet, maximum time.Duration) (*Controller, error) {
	if source == nil || nilutil.IsNilInterface(store) {
		return nil, fmt.Errorf("snapshot source and store are required")
	}
	if quiet <= 0 || maximum < quiet {
		return nil, fmt.Errorf("invalid push debounce periods")
	}
	return &Controller{
		source:   source,
		store:    store,
		quiet:    quiet,
		maximum:  maximum,
		triggers: make(chan struct{}, 1),
		changes:  make(map[model.ResourceKey]model.ResourceChange),
	}, nil
}

func (c *Controller) Trigger() {
	c.mu.Lock()
	c.pendingFull = true
	c.mu.Unlock()
	c.signal()
}

// Enqueue preserves the compiled KRT delta through the debounce boundary. A
// later event for the same key replaces the desired value while retaining the
// first Old resource, so add/update/delete bursts collapse to their net effect.
func (c *Controller) Enqueue(changes []model.ResourceChange) {
	if len(changes) == 0 {
		return
	}
	c.mu.Lock()
	for _, change := range changes {
		if existing, found := c.changes[change.Key]; found {
			change.Old = existing.Old
		}
		if resourcesEqual(change.Old, change.New) {
			delete(c.changes, change.Key)
		} else {
			c.changes[change.Key] = change
		}
	}
	c.mu.Unlock()
	c.signal()
}

func (c *Controller) signal() {
	select {
	case c.triggers <- struct{}{}:
	default:
	}
}

func (c *Controller) takePending() (bool, []model.ResourceChange) {
	c.mu.Lock()
	defer c.mu.Unlock()
	full := c.pendingFull
	c.pendingFull = false
	changes := make([]model.ResourceChange, 0, len(c.changes))
	for _, change := range c.changes {
		changes = append(changes, change)
	}
	clear(c.changes)
	return full, changes
}

func (c *Controller) Run(ctx context.Context) error {
	registration := c.source.Resources().RegisterBatch(func(batch []krt.Event[model.Resource]) {
		c.Enqueue(resourceChanges(batch))
	}, true)
	defer registration.UnregisterHandler()
	c.Trigger()
	var quietTimer, maximumTimer *time.Timer
	var quietChannel, maximumChannel <-chan time.Time
	pending := false
	var debounceStarted time.Time
	markPending := func() {
		if !pending {
			debounceStarted = time.Now()
		}
		pending = true
	}
	stop := func(timer **time.Timer) {
		if *timer != nil {
			(*timer).Stop()
			*timer = nil
		}
	}
	flush := func() {
		if !pending {
			return
		}
		pending = false
		stop(&quietTimer)
		stop(&maximumTimer)
		quietChannel, maximumChannel = nil, nil
		full, changes := c.takePending()
		started := time.Now()
		debounceDuration := started.Sub(debounceStarted)
		var publication xdsstore.Publication
		var err error
		publishStarted := time.Now()
		if full {
			var snapshot model.ResourceSet
			snapshot, err = c.source.Snapshot()
			if err == nil {
				publication = c.store.Replace(snapshot)
			}
		} else {
			publication, err = c.store.Apply(changes)
		}
		compileDuration := time.Since(started)
		metrics.Default.RecordCompile(compileDuration, err, publication.Snapshot.Len())
		if err != nil {
			log.Error("xDS snapshot publication failed; preserving last-known-good snapshot",
				"full", full, "changes", len(changes),
				"debounce_duration", debounceDuration, "publication_duration", compileDuration, "error", err)
			return
		}
		if publication.Changed {
			metrics.Default.RecordPublish(time.Since(publishStarted))
			metrics.Default.SetSnapshotResourcesByType(publication.Snapshot.CountsByType())
		}
		logPublication(ctx, full, changes, publication, debounceDuration, compileDuration)
	}
	for {
		select {
		case <-ctx.Done():
			// Drain an unread trigger before flushing; select may pick ctx.Done()
			// while a trigger is still queued.
			select {
			case <-c.triggers:
				markPending()
			default:
			}
			flush()
			return nil
		case <-c.triggers:
			markPending()
			stop(&quietTimer)
			quietTimer = time.NewTimer(c.quiet)
			quietChannel = quietTimer.C
			if maximumTimer == nil {
				maximumTimer = time.NewTimer(c.maximum)
				maximumChannel = maximumTimer.C
			}
		case <-quietChannel:
			flush()
		case <-maximumChannel:
			flush()
		}
	}
}

// Summarize one publication outside the Store lock. Publication is send-side
// work only: it does not mean subscribers have received or ACKed the snapshot.
func logPublication(ctx context.Context, full bool, changes []model.ResourceChange, publication xdsstore.Publication,
	debounceDuration, publicationDuration time.Duration,
) {
	level, message := slog.LevelDebug, "xDS snapshot unchanged"
	emit := log.Debug
	if publication.Changed {
		level, message, emit = slog.LevelInfo, "xDS snapshot published", log.Info
	}
	if !log.Enabled(ctx, level) {
		return
	}
	// These are compiled input changes after coalescing, not counts of sends or
	// all resources replaced by a full snapshot. Only sample a few keys; never
	// format resource payloads or sort the entire change set just for logging.
	byType := make(map[string]int)
	sample := make([]model.ResourceKey, 0, min(3, len(changes)))
	for _, change := range changes {
		byType[change.Key.TypeURL]++
		if len(sample) < 3 {
			sample = append(sample, change.Key)
		}
	}
	emit(message, "version", publication.Snapshot.Version(), "full", full,
		"connected_endpoints", publication.SubscriberCount,
		"changes", len(changes), "changes_by_type", byType, "resource_sample", sample,
		"resources", publication.Snapshot.Len(),
		"debounce_duration", debounceDuration, "publication_duration", publicationDuration)
}

func resourceChanges(events []krt.Event[model.Resource]) []model.ResourceChange {
	changes := make([]model.ResourceChange, 0, len(events))
	for _, event := range events {
		if event.Old != nil && event.New != nil && event.Old.Key != event.New.Key {
			oldResource := *event.Old
			changes = append(changes, model.ResourceChange{Key: oldResource.Key, Old: &oldResource})
			newResource := *event.New
			changes = append(changes, model.ResourceChange{Key: newResource.Key, New: &newResource})
			continue
		}
		change := model.ResourceChange{}
		if event.Old != nil {
			oldResource := *event.Old
			change.Key = oldResource.Key
			change.Old = &oldResource
		}
		if event.New != nil {
			newResource := *event.New
			change.Key = newResource.Key
			change.New = &newResource
		}
		changes = append(changes, change)
	}
	return changes
}

func resourcesEqual(left, right *model.Resource) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Hash == right.Hash
}
