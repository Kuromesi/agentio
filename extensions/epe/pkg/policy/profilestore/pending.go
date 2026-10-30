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

package profilestore

import (
	"context"

	"k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/pkg/model"
)

type pendingProfile struct {
	changed chan struct{}
	waiters int
}

// Publication and registration share mu, so an unchanged snapshot needs no second source lookup.
func (s *store) waitForProfileChange(ctx context.Context, name types.NamespacedName, observed *profileSnapshot) error {
	key := sandboxProfileKey(name.Namespace, name.Name)
	s.mu.Lock()
	if s.snapshot.Load() != observed {
		s.mu.Unlock()
		return ctx.Err()
	}
	pending := s.pending[key]
	if pending == nil {
		pending = &pendingProfile{changed: make(chan struct{})}
		if s.pending == nil {
			s.pending = make(map[model.ResourceKey]*pendingProfile)
		}
		s.pending[key] = pending
	}
	pending.waiters++
	s.mu.Unlock()
	select {
	case <-pending.changed:
		return nil
	case <-ctx.Done():
		s.mu.Lock()
		// A notification may have removed this generation and a new request replaced it.
		if s.pending[key] == pending {
			pending.waiters--
			if pending.waiters == 0 {
				delete(s.pending, key)
			}
		}
		s.mu.Unlock()
		return ctx.Err()
	}
}

// Notifications invalidate pending checks; they do not assert that a policy is ready.
func (s *store) notifyPendingLocked(key model.ResourceKey) {
	if pending := s.pending[key]; pending != nil {
		delete(s.pending, key)
		close(pending.changed)
	}
}
