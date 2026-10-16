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

package xdsclient

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type demandObservation struct {
	waited   bool
	duration time.Duration
	err      error
}
type demandProbe struct {
	mu        sync.Mutex
	active    int
	completed []demandObservation
}

func (p *demandProbe) WaitStarted(string, string) func() {
	p.mu.Lock()
	p.active++
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
	}
}
func (p *demandProbe) DemandCompleted(_ string, waited bool, duration time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.completed = append(p.completed, demandObservation{waited, duration, err})
}

func TestDemandObserverWaitCacheAndCancellation(t *testing.T) {
	withSubscriptionClient(t, Watch{TypeURL: testType}, func(t *testing.T, c *Client) {
		probe := &demandProbe{}
		c.cfg.DemandObserver = probe
		first := beginDemand(t.Context(), c, "a")
		lease := acquire(t, c, "a")
		defer lease.Release()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		second := make(chan error, 1)
		go func() {
			_, err := lease.Demand(ctx)
			second <- err
		}()
		synctest.Wait()
		if probe.active != 2 {
			t.Fatalf("active=%d", probe.active)
		}
		time.Sleep(time.Second)
		cancel()
		if err := <-second; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if probe.active != 1 {
			t.Fatalf("active=%d", probe.active)
		}
		publishString(t, c, "a", "ready")
		if err := <-first; err != nil {
			t.Fatal(err)
		}
		if _, err := lease.Demand(t.Context()); err != nil {
			t.Fatal(err)
		}
		if probe.active != 0 || len(probe.completed) != 3 {
			t.Fatalf("observations=%+v", probe)
		}
		for i, entry := range probe.completed {
			if entry.waited != (i < 2) {
				t.Fatalf("wait path=%+v", entry)
			}
		}
		if probe.completed[0].duration != time.Second || probe.completed[2].duration != 0 {
			t.Fatalf("durations=%+v", probe.completed)
		}
	})
}
