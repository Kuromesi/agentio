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
	"sync"
	"time"
)

// pushConnection is the scheduler identity and delivery point for one Delta
// stream; pointer identity avoids collisions with reused node IDs.
type pushConnection struct {
	context context.Context
	pushes  chan *scheduledPush
}

func newPushConnection(ctx context.Context) *pushConnection {
	return &pushConnection{context: ctx, pushes: make(chan *scheduledPush, 1)}
}

type scheduledPush struct {
	Connection *pushConnection
	Update     Update
	Started    time.Time
}

type queuedUpdate struct {
	Update  Update
	Started time.Time
}

// PushScheduler FIFO-schedules per-connection pushes and bounds process-wide push concurrency.
type PushScheduler struct {
	mu sync.Mutex

	// pending contains at most one merged update per queued connection. queue
	// preserves the order in which distinct connections became pending.
	pending map[*pushConnection]queuedUpdate
	queue   []*pushConnection

	// processing contains every assigned connection. A nil value means no later
	// update has arrived; otherwise Done requeues the merged later update.
	processing map[*pushConnection]*queuedUpdate

	cancellations map[*pushConnection]func() bool
	slots         chan struct{}
	wake          chan struct{}
	closed        chan struct{}
	closing       bool
}

func NewPushScheduler(concurrency int) *PushScheduler {
	if concurrency <= 0 {
		panic("push concurrency must be positive")
	}
	return &PushScheduler{
		pending:       make(map[*pushConnection]queuedUpdate),
		processing:    make(map[*pushConnection]*queuedUpdate),
		cancellations: make(map[*pushConnection]func() bool),
		slots:         make(chan struct{}, concurrency),
		wake:          make(chan struct{}, 1),
		closed:        make(chan struct{}),
	}
}

// Enqueue adds a connection to the FIFO once and merges repeated updates into
// either its pending work or the work accumulated while it is processing.
func (s *PushScheduler) Enqueue(connection *pushConnection, update Update) {
	if connection == nil || connection.context.Err() != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || connection.context.Err() != nil {
		return
	}
	incoming := queuedUpdate{Update: update, Started: time.Now()}
	if _, found := s.cancellations[connection]; !found {
		s.cancellations[connection] = context.AfterFunc(connection.context, func() {
			s.cancel(connection)
		})
	}
	if later, found := s.processing[connection]; found {
		if later == nil {
			copy := incoming
			s.processing[connection] = &copy
		} else {
			later.Update = mergeUpdates(later.Update, update)
		}
		return
	}
	if pending, found := s.pending[connection]; found {
		pending.Update = mergeUpdates(pending.Update, update)
		s.pending[connection] = pending
		return
	}
	s.pending[connection] = incoming
	s.queue = append(s.queue, connection)
	s.signalLocked()
}

// Next waits for pending work and global capacity, acquiring capacity before it
// assigns the FIFO head. It returns nil after cancellation or Close.
func (s *PushScheduler) Next(ctx context.Context) *scheduledPush {
	for {
		if ctx.Err() != nil {
			return nil
		}
		if !s.waitForPending(ctx) {
			return nil
		}
		select {
		case s.slots <- struct{}{}:
		case <-ctx.Done():
			return nil
		case <-s.closed:
			return nil
		}

		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			s.releaseSlot()
			return nil
		}
		for len(s.queue) > 0 {
			connection := s.queue[0]
			s.queue[0] = nil
			s.queue = s.queue[1:]
			queued, found := s.pending[connection]
			if !found {
				continue
			}
			delete(s.pending, connection)
			if connection.context.Err() != nil {
				continue
			}
			s.processing[connection] = nil
			s.mu.Unlock()
			return &scheduledPush{Connection: connection, Update: queued.Update, Started: queued.Started}
		}
		s.mu.Unlock()
		s.releaseSlot()
	}
}

func (s *PushScheduler) waitForPending(ctx context.Context) bool {
	for {
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			return false
		}
		if len(s.queue) > 0 {
			s.mu.Unlock()
			return true
		}
		s.mu.Unlock()
		select {
		case <-s.wake:
		case <-ctx.Done():
			return false
		case <-s.closed:
			return false
		}
	}
}

// Done releases an assigned push. Updates that arrived for the connection while
// it was assigned return at the FIFO tail as one merged pending entry.
func (s *PushScheduler) Done(push *scheduledPush) {
	if push == nil || push.Connection == nil {
		return
	}
	s.mu.Lock()
	later, found := s.processing[push.Connection]
	if !found {
		s.mu.Unlock()
		return
	}
	delete(s.processing, push.Connection)
	if later != nil && !s.closing && push.Connection.context.Err() == nil {
		s.pending[push.Connection] = *later
		s.queue = append(s.queue, push.Connection)
		s.signalLocked()
	}
	s.mu.Unlock()
	s.releaseSlot()
}

func (s *PushScheduler) cancel(connection *pushConnection) {
	s.mu.Lock()
	delete(s.pending, connection)
	_, processing := s.processing[connection]
	if processing {
		delete(s.processing, connection)
	}
	stop := s.cancellations[connection]
	delete(s.cancellations, connection)
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
	if processing {
		s.releaseSlot()
	}
}

func (s *PushScheduler) signalLocked() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *PushScheduler) releaseSlot() {
	<-s.slots
}

// Close rejects new work, releases all scheduler state, and unblocks Next.
func (s *PushScheduler) Close() {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.closing = true
	close(s.closed)
	for index := range s.queue {
		s.queue[index] = nil
	}
	s.queue = nil
	clear(s.pending)
	processing := len(s.processing)
	clear(s.processing)
	cancellations := s.cancellations
	s.cancellations = make(map[*pushConnection]func() bool)
	s.mu.Unlock()

	for _, stop := range cancellations {
		stop()
	}
	for range processing {
		s.releaseSlot()
	}
}
