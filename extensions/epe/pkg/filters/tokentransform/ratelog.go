// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package tokentransform

import (
	"sync"
	"time"
)

// Clock returns the current time; injectable for tests.
type Clock func() time.Time

// Limiter is a tiny in-memory rate limiter that allows the first call per
// key within each TTL window; it throttles repeated log lines.
type Limiter struct {
	ttl  time.Duration
	now  Clock
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewLimiter returns a Limiter with the given TTL. Pass nil clock for
// real time.
func NewLimiter(ttl time.Duration, clock Clock) *Limiter {
	if clock == nil {
		clock = time.Now
	}
	return &Limiter{ttl: ttl, now: clock, seen: make(map[string]time.Time)}
}

const gcThreshold = 1000

// Allow returns true when key has not been seen within the TTL window.
// On a returned true, the key's timestamp is updated. Periodically
// purges expired entries to prevent unbounded map growth.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if t, ok := l.seen[key]; ok && now.Sub(t) < l.ttl {
		return false
	}
	l.seen[key] = now
	if len(l.seen) > gcThreshold {
		l.purgeLocked(now)
	}
	return true
}

func (l *Limiter) purgeLocked(now time.Time) {
	for k, t := range l.seen {
		if now.Sub(t) >= l.ttl {
			delete(l.seen, k)
		}
	}
}
