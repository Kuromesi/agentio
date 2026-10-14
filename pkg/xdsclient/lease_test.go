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
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/openkruise/agentio/pkg/demandcache"
)

func acquire(t *testing.T, c *Client, name string) *Subscription {
	t.Helper()
	s, err := c.Acquire(testType, name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOwnedSubscriptions(t *testing.T) {
	withSubscriptionClient(t, Watch{
		TypeURL: testType,
		OnDelete: func(string) DeleteAction {
			t.Error("local eviction called server deletion callback")
			return ReleaseSubscription
		}}, func(t *testing.T, c *Client) {
		first, second := acquire(t, c, "a"), acquire(t, c, "a")
		sent := map[string]map[string]*subscription{}
		c.initialRequests(sent)
		result := make(chan error, 1)
		go func() {
			_, err := first.Demand(t.Context())
			result <- err
		}()
		synctest.Wait()
		first.Release()
		first.Release()
		if err := <-result; !errors.Is(err, ErrReleased) {
			t.Fatal(err)
		}
		if len(c.pendingRequests(sent)) != 0 {
			t.Fatal("released another owner")
		}
		publishString(t, c, "a", "value", "alias")
		if _, err := second.Demand(t.Context()); err != nil {
			t.Fatal(err)
		}
		second.Release()
		select {
		case <-second.Done():
		default:
			t.Fatal("last release did not end generation")
		}
		st := c.types[testType]
		if len(st.resources)+len(st.names)+len(st.aliases)+len(st.resourceAliases)+len(st.removed) != 0 {
			t.Fatal("last release retained state")
		}
		requests := c.pendingRequests(sent)
		if len(requests) != 1 || !slices.Equal(requests[0].ResourceNamesUnsubscribe, []string{"a"}) {
			t.Fatal(requests)
		}
		publishString(t, c, "a", "late", "alias")
		if len(st.resources)+len(st.aliases) != 0 {
			t.Fatal("late response repopulated evicted resource")
		}
		c.reset()
		requests = c.initialRequests(map[string]map[string]*subscription{})
		if slices.Contains(requests[0].ResourceNamesSubscribe, "a") {
			t.Fatal("reconnect restored released interest")
		}
		next := acquire(t, c, "a")
		defer next.Release()
		publishString(t, c, "a", "new")
		if _, err := next.Demand(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestOldHandleCannotReleaseNewGeneration(t *testing.T) {
	withSubscriptionClient(
		t,
		Watch{TypeURL: testType, OnDelete: func(string) DeleteAction { return ReleaseSubscription }},
		func(t *testing.T, c *Client) {
			old := acquire(t, c, "a")
			sent := map[string]map[string]*subscription{}
			c.initialRequests(sent)
			removeNames(t, c, "a")
			next := acquire(t, c, "a")
			defer next.Release()
			old.Release()
			if _, err := old.Demand(t.Context()); !errors.Is(err, ErrNotFound) {
				t.Fatal(err)
			}
			requests := c.pendingRequests(sent)
			if len(requests) != 1 || !slices.Equal(requests[0].ResourceNamesSubscribe, []string{"a"}) ||
				len(requests[0].ResourceNamesUnsubscribe) != 0 {
				t.Fatal(requests)
			}
			publishString(t, c, "a", "new")
			if _, err := next.Demand(t.Context()); err != nil {
				t.Fatal(err)
			}
		},
	)
}

func TestReleasePreservesPersistentOrWildcardInterest(t *testing.T) {
	for _, wildcard := range []bool{false, true} {
		withSubscriptionClient(t, Watch{TypeURL: testType, Wildcard: wildcard}, func(t *testing.T, c *Client) {
			handle := acquire(t, c, "a")
			publishString(t, c, "a", "value")
			if !wildcard {
				if _, err := c.Demand(t.Context(), testType, "a"); err != nil {
					t.Fatal(err)
				}
			}
			handle.Release()
			if c.Snapshot().Resources[testType]["a"] == nil {
				t.Fatal("shared value removed")
			}
			publishString(t, c, "a", "updated")
			if c.Snapshot().Resources[testType]["a"] == nil {
				t.Fatal("shared update ignored")
			}
		})
	}
}

func TestReleaseAliasOwnership(t *testing.T) {
	withSubscriptionClient(t, Watch{TypeURL: testType}, func(t *testing.T, c *Client) {
		alias, canonical := acquire(t, c, "shared"), acquire(t, c, "a")
		publishString(t, c, "a", "a", "shared")
		publishString(t, c, "b", "b", "shared")
		alias.Release()
		st := c.types[testType]
		if len(st.resources) != 1 || st.resources["a"] == nil || st.aliases["shared"] != "a" {
			t.Fatal("ambiguous alias release did not preserve canonical owner")
		}
		canonical.Release()
		if len(st.resources)+len(st.aliases)+len(st.resourceAliases) != 0 {
			t.Fatal("canonical release retained alias state")
		}
		alias, canonical = acquire(t, c, "shared"), acquire(t, c, "a")
		publishString(t, c, "a", "a", "shared")
		canonical.Release()
		if _, err := alias.Demand(t.Context()); err != nil {
			t.Fatal(err)
		}
		alias.Release()
		if len(st.resources)+len(st.aliases)+len(st.resourceAliases) != 0 {
			t.Fatal("alias release retained canonical value")
		}
	})
}

type cacheSource struct {
	client *Client
}

func (s cacheSource) Acquire(typ, name string) (demandcache.Lease[*Resource], error) {
	return s.client.Acquire(typ, name)
}

func TestDemandCacheReleasesAndRedemands(t *testing.T) {
	withSubscriptionClient(
		t,
		Watch{TypeURL: testType, OnDelete: func(string) DeleteAction { return ReleaseSubscription }},
		func(t *testing.T, c *Client) {
			cache, err := demandcache.New(
				cacheSource{client: c},
				demandcache.Config{IdleTTL: time.Minute, MaxEntries: 1},
			)
			if err != nil {
				t.Fatal(err)
			}
			defer cache.Close()
			go func() {
				if err := cache.Run(t.Context()); err != nil {
					t.Error(err)
				}
			}()
			demand := func(name string) <-chan error {
				done := make(chan error, 1)
				go func() {
					_, err := cache.Demand(t.Context(), testType, name)
					done <- err
				}()
				synctest.Wait()
				return done
			}
			first := demand("a")
			publishString(t, c, "a", "one")
			if err := <-first; err != nil {
				t.Fatal(err)
			}
			second := demand("b")
			if c.Snapshot().Resources[testType]["a"] != nil {
				t.Fatal("LRU retained underlying value")
			}
			publishString(t, c, "b", "two")
			if err := <-second; err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Minute)
			synctest.Wait()
			if len(c.types[testType].names)+len(c.Snapshot().Resources[testType]) != 0 {
				t.Fatal("TTL retained source state")
			}
			again := demand("a")
			removeNames(t, c, "a")
			if err := <-again; !errors.Is(err, ErrNotFound) {
				t.Fatal(err)
			}
			again = demand("a")
			publishString(t, c, "a", "recreated")
			if err := <-again; err != nil {
				t.Fatal(err)
			}
			// Closing the cache also cancels a lookup waiting for discovery.
			waiting := demand("pending")
			cache.Close()
			if err := <-waiting; !errors.Is(err, ErrReleased) {
				t.Fatal(err)
			}
			if _, err := cache.Demand(context.Background(), testType, "a"); !errors.Is(err, demandcache.ErrClosed) {
				t.Fatal(err)
			}
		},
	)
}
