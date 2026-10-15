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

package cache

import (
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func build[K comparable, V any](t *testing.T, b *Builder[K, V]) *Cache[K, V] {
	t.Helper()
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLRUAndUnboundedStorage(t *testing.T) {
	for _, capacity := range []int{0, 2} {
		t.Run(strconv.Itoa(capacity), func(t *testing.T) {
			c := build(t, NewBuilder[string, int]().WithLRU(capacity))
			c.Set("a", 1)
			c.Set("b", 2)
			c.Get("a")
			c.Set("c", 3)
			if _, ok := c.Get("b"); ok != (capacity == 0) {
				t.Fatal("capacity or recency was not honored")
			}
			if value, ok := c.Get("a"); !ok || value != 1 {
				t.Fatal("recently accessed value evicted")
			}
			c.Remove("a")
			if _, ok := c.Get("a"); ok {
				t.Fatal("removed value returned")
			}
		})
	}
}

func TestExpiration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := build(t, NewBuilder[string, int]())
		c.Set("permanent", 1)
		c.SetWithExpiration("fixed", 2, time.Now().Add(time.Minute))
		time.Sleep(30 * time.Second)
		c.Get("fixed")
		time.Sleep(30 * time.Second)
		if _, ok := c.Get("fixed"); ok {
			t.Fatal("hit extended fixed TTL")
		}
		if _, ok := c.Get("permanent"); !ok {
			t.Fatal("zero settings expired a value")
		}
		if c.SetWithExpiration("permanent", 3, time.Now()) {
			t.Fatal("expired write accepted")
		}
		if got, _ := c.Get("permanent"); got != 1 {
			t.Fatal("expired write replaced valid value")
		}
	})
}

func TestBuilderConfiguration(t *testing.T) {
	for _, b := range []*Builder[string, int]{
		NewBuilder[string, int]().WithLRU(-1),
		NewBuilder[string, int]().WithTTL(-1),
		NewBuilder[string, int]().WithClock(nil),
	} {
		if _, err := b.Build(); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	b := NewBuilder[string, int]().WithLRU(-1).WithLRU(1)
	c := build(t, b)
	b.WithLRU(2)
	other := build(t, b)
	c.Set("a", 1)
	c.Set("b", 2)
	if c.Len() != 1 || other.Len() != 0 {
		t.Fatal("builder reuse mutated built cache")
	}
	other.Set("a", 1)
	other.Set("b", 2)
	if other.Len() != 2 {
		t.Fatal("new cache ignored changed builder")
	}
}

func TestConcurrentReplacementAndEviction(t *testing.T) {
	for _, capacity := range []int{0, 8} {
		t.Run(strconv.Itoa(capacity), func(t *testing.T) {
			c := build(t, NewBuilder[int, int]().WithLRU(capacity))
			var wg sync.WaitGroup
			for worker := range 8 {
				wg.Go(func() {
					for i := range 100 {
						key := (worker + i) % 16
						c.Set(key, key)
						if value, ok := c.Get(key); ok && value != key {
							t.Errorf("key %d returned value %d", key, value)
						}
						if i%5 == 0 {
							c.Remove(key)
						}
					}
				})
			}
			wg.Wait()
			if capacity > 0 && c.Len() > capacity {
				t.Fatal("concurrent writes exceeded capacity")
			}
		})
	}
}

func TestDefaultTTLAndExplicitOverrides(t *testing.T) {
	for _, capacity := range []int{0, 10} {
		t.Run(strconv.Itoa(capacity), func(t *testing.T) {
			now := time.Unix(1000, 0)
			c := build(t, NewBuilder[string, int]().WithLRU(capacity).WithTTL(time.Minute).
				WithClock(func() time.Time { return now }))
			c.Set("default", 1)
			c.SetWithExpiration("short", 2, now.Add(30*time.Second))
			c.SetWithExpiration("long", 3, now.Add(2*time.Minute))
			c.SetWithExpiration("unlimited", 4, time.Time{})
			now = now.Add(30 * time.Second)
			if _, ok := c.Get("short"); ok {
				t.Fatal("shorter override ignored")
			}
			if _, ok := c.Get("default"); !ok {
				t.Fatal("default TTL expired early")
			}
			now = now.Add(30 * time.Second)
			if _, ok := c.Get("default"); ok {
				t.Fatal("default TTL missing or extended by Get")
			}
			if _, ok := c.Get("long"); !ok {
				t.Fatal("default TTL capped longer override")
			}
			now = now.Add(time.Minute)
			if _, ok := c.Get("long"); ok {
				t.Fatal("longer override did not expire at its deadline")
			}
			if _, ok := c.Get("unlimited"); !ok {
				t.Fatal("zero override did not disable default TTL")
			}
		})
	}
}

func TestSetResetsDefaultLifetime(t *testing.T) {
	now := time.Unix(1000, 0)
	c := build(t, NewBuilder[string, int]().WithTTL(time.Minute).WithClock(func() time.Time { return now }))
	c.Set("key", 1)
	c.SetWithExpiration("override", 1, now.Add(time.Hour))
	now = now.Add(30 * time.Second)
	c.Set("key", 2)
	c.Set("override", 2)
	now = now.Add(30 * time.Second)
	if got, ok := c.Get("key"); !ok || got != 2 {
		t.Fatal("replacement did not restart TTL")
	}
	now = now.Add(30 * time.Second)
	for _, key := range []string{"key", "override"} {
		if _, ok := c.Get(key); ok {
			t.Fatal("Set did not apply default TTL to replacement")
		}
	}
}
