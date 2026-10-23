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

package epe

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// Each update changes exactly one field. A retired idle socket acknowledges the
// ConfigMap watcher; another old socket stays busy throughout the new-pool checks.
func testDeployedCalloutLimits(
	t *testing.T,
	origin string,
	apply func(string),
	request func(time.Duration) error,
	stats func() deployedCalloutConnections,
	release func(string),
) {
	type limits struct {
		connections int
		idle        int
		timeout     string
		streams     int
	}
	for _, protocol := range []string{"HTTP1", "HTTP2"} {
		for _, field := range []string{"maxConnections", "maxIdleConnections", "idleTimeout", "streams-increase", "streams-decrease"} {
			if protocol == "HTTP1" && (field == "streams-increase" || field == "streams-decrease") {
				continue
			}
			t.Run(protocol+"/"+field, func(t *testing.T) {
				baseline := limits{connections: 2, idle: 2, timeout: "30s", streams: 1}
				if field == "maxConnections" {
					baseline.idle = 1
				}
				if field == "streams-decrease" {
					baseline.streams = 2
				}
				updated := baseline
				switch field {
				case "maxConnections":
					updated.connections = 1
				case "maxIdleConnections":
					updated.idle = 1
				case "idleTimeout":
					updated.timeout = "500ms"
				case "streams-increase":
					updated.streams = 2
				case "streams-decrease":
					updated.streams = 1
				}
				endpoint := "/controlled/" + protocol + "/" + field
				update := func(v limits) {
					raw := fmt.Sprintf(
						"extensionProviders:\n- name: transport\n  httpCallout:\n    url: %q\n    timeout: 30s\n    protocol: %s\n    connectionPool:\n      maxConnections: %d\n      maxIdleConnections: %d\n      idleTimeout: %s\n",
						origin+endpoint,
						protocol,
						v.connections,
						v.idle,
						v.timeout,
					)
					if protocol == "HTTP2" {
						raw += fmt.Sprintf("    http2: {maxConcurrentStreams: %d}\n", v.streams)
					}
					apply(raw)
				}
				previous := stats()
				update(baseline)
				harness.RetryAssertion(t, 10*time.Second, 20*time.Millisecond, func() error {
					state := stats()
					for addr := range previous.Connections {
						if !state.Connections[addr].Closed {
							return fmt.Errorf("waiting for previous pool connection %s to close", addr)
						}
					}
					return nil
				})
				t.Cleanup(func() {
					for addr, c := range stats().Connections {
						if c.Path == endpoint && c.Active > 0 {
							release(addr)
						}
					}
				})
				start := func(n int, ready *atomic.Bool) <-chan error {
					done := make(chan error, n)
					for range n {
						go func() {
							for {
								err := request(30 * time.Second)
								if err != nil || ready == nil || ready.Load() {
									done <- err
									return
								}
								time.Sleep(20 * time.Millisecond)
							}
						}()
					}
					return done
				}
				finish := func(done <-chan error, n int) {
					t.Helper()
					for range n {
						select {
						case err := <-done:
							if err != nil {
								t.Fatal(err)
							}
						case <-time.After(10 * time.Second):
							t.Fatal("callout did not complete after release")
						}
					}
				}
				// Fill both baseline connections, then release exactly one into the idle pool.
				var ready atomic.Bool
				oldDone := start(baseline.connections*baseline.streams, &ready)
				var old []string
				harness.RetryAssertion(t, 10*time.Second, 20*time.Millisecond, func() error {
					old = nil
					active := 0
					for addr, c := range stats().Connections {
						if c.Path == endpoint {
							old = append(old, addr)
							active += c.Active
						} else if c.Active > 0 {
							// If the preceding idle-timeout case left no sockets,
							// their closure cannot acknowledge this setup update.
							// Release calls that still selected the preceding config
							// and let them retry until all calls reach this endpoint.
							release(addr)
						}
					}
					if len(old) != baseline.connections || active != baseline.connections*baseline.streams {
						return fmt.Errorf("baseline connections=%d active=%d", len(old), active)
					}
					return nil
				})
				ready.Store(true)
				idle, held := old[0], old[1]
				release(idle)
				finish(oldDone, baseline.streams)
				state := stats()
				if state.Connections[idle].Closed || state.Connections[idle].Active != 0 {
					t.Fatalf("baseline did not retain idle connection: %+v", state.Connections[idle])
				}
				update(updated)
				harness.RetryAssertion(t, 10*time.Second, 20*time.Millisecond, func() error {
					if !stats().Connections[idle].Closed {
						return fmt.Errorf("updated config has not retired the idle connection")
					}
					return nil
				})
				before := stats()
				capacity := updated.connections * updated.streams
				done := start(capacity+1, nil)
				var fresh []string
				checkCapacity := func() error {
					fresh = nil
					active := 0
					state := stats()
					for addr, c := range state.Connections {
						if _, exists := before.Connections[addr]; exists {
							continue
						}
						fresh = append(fresh, addr)
						active += c.Active
						expectedProtocol := 1
						if protocol == "HTTP2" {
							expectedProtocol = 2
						}
						if c.Protocol != expectedProtocol || c.Peak > updated.streams || c.Closed {
							return fmt.Errorf("new connection %s: %+v", addr, c)
						}
					}
					if len(fresh) != updated.connections || active != capacity {
						return fmt.Errorf(
							"new pool connections=%d active=%d, want %d/%d",
							len(fresh),
							active,
							updated.connections,
							capacity,
						)
					}
					return nil
				}
				harness.RetryAssertion(t, 10*time.Second, 20*time.Millisecond, checkCapacity)
				// Keep all slots occupied long enough for the extra call to reach the pool.
				// It must remain queued, without an extra socket or stream being admitted.
				deadline := time.Now().Add(300 * time.Millisecond)
				for time.Now().Before(deadline) {
					if err := checkCapacity(); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-done:
						t.Fatalf("call completed before release: %v", err)
					case <-time.After(20 * time.Millisecond):
					}
				}
				for _, addr := range fresh {
					release(addr)
				}
				finish(done, capacity+1)
				expectedIdle := min(updated.idle, updated.connections)
				if field == "idleTimeout" {
					expectedIdle = 0
				}
				harness.RetryAssertion(t, 5*time.Second, 20*time.Millisecond, func() error {
					state := stats()
					open, calls := 0, 0
					for addr, c := range state.Connections {
						if _, exists := before.Connections[addr]; exists {
							continue
						}
						calls += c.Calls
						if !c.Closed {
							open++
						}
					}
					if open != expectedIdle || calls != capacity+1 || state.Refused != before.Refused {
						return fmt.Errorf(
							"new pool idle=%d calls=%d refused=%d, want idle=%d calls=%d refused=0",
							open,
							calls,
							state.Refused-before.Refused,
							expectedIdle,
							capacity+1,
						)
					}
					return nil
				})
				state = stats()
				if c := state.Connections[held]; c.Closed || c.Active != baseline.streams ||
					c.Calls != baseline.streams {
					t.Fatalf("old active connection was interrupted or reused: %+v", c)
				}
				release(held)
				finish(oldDone, baseline.streams)
				harness.RetryAssertion(t, 5*time.Second, 20*time.Millisecond, func() error {
					if !stats().Connections[held].Closed {
						return fmt.Errorf("old connection remains open after draining")
					}
					return nil
				})
				t.Logf(
					"%s: %+v -> %+v; new capacity=%d, idle=%d; old calls completed and connection closed",
					protocol,
					baseline,
					updated,
					capacity,
					expectedIdle,
				)
			})
		}
	}
}
