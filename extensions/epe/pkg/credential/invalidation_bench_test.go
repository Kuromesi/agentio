// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package credential

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential/tokencache"
)

// Populate directly so fixture setup does not itself perform quadratic invalidations.
func invalidationBenchClient(apiEntries, stsEntries, states, affected int) (*Client, func()) {
	c := NewClient("", http.DefaultClient, nil, nil, WithInvalidationCachePolicy(30*time.Second, 5*time.Second))
	expiration := time.Now().Add(time.Hour)
	stsValue := tokencache.STSCacheEntry{AccessKeyID: "ak", AccessKeySecret: "sk", SecurityToken: "st"}
	key := func(i, size int) tokencache.Key {
		provider := fmt.Sprintf("p-%d", i%100)
		if i >= size-affected {
			provider = "target"
		}
		return tokencache.Key{ProviderName: provider, ResourceID: fmt.Sprint(i)}
	}
	if apiEntries > 0 {
		c.cache = tokencache.NewCache(time.Hour, apiEntries)
		for i := range apiEntries {
			c.cache.Set(key(i, apiEntries), "key")
		}
	}
	if stsEntries > 0 {
		c.stsCache = tokencache.NewSTSCache(stsEntries)
		for i := range stsEntries {
			c.stsCache.SetWithExpiration(key(i, stsEntries), stsValue, expiration, 0)
		}
	}
	for i := range states {
		c.refresh[fmt.Sprintf("p-%d", i)] = refreshState{generation: 1, shortUntil: expiration}
	}
	return c, func() {
		for i := apiEntries - affected; i < apiEntries && i >= 0; i++ {
			c.cache.Set(key(i, apiEntries), "key")
		}
		for i := stsEntries - affected; i < stsEntries && i >= 0; i++ {
			c.stsCache.SetWithExpiration(key(i, stsEntries), stsValue, expiration, 0)
		}
	}
}

// Run with -run '^$' -bench '^BenchmarkCredentialInvalidation$' -benchtime=30x -count=3.
// Each operation invalidates one provider; fixture restoration is outside timing.
func BenchmarkCredentialInvalidation(b *testing.B) {
	for _, tc := range []struct {
		name     string
		api      int
		sts      int
		states   int
		affected int
		expired  bool
	}{
		{name: "refresh_live_100", states: 100},
		{name: "refresh_live_10000", states: 10000},
		{name: "refresh_live_100000", states: 100000},
		{name: "refresh_expired_100", states: 100, expired: true},
		{name: "refresh_expired_10000", states: 10000, expired: true},
		{name: "refresh_expired_100000", states: 100000, expired: true},
		{name: "api1000_sts1000_refresh100_remove1", api: 1000, sts: 1000, states: 100, affected: 1},
		{name: "api10000_sts0_refresh100_remove1", api: 10000, states: 100, affected: 1},
		{name: "api10000_sts100000_refresh100_remove1", api: 10000, sts: 100000, states: 100, affected: 1},
		{name: "api10000_sts100000_refresh100_remove100", api: 10000, sts: 100000, states: 100, affected: 100},
		{name: "api100000_sts100000_refresh100_remove1", api: 100000, sts: 100000, states: 100, affected: 1},
	} {
		b.Run(tc.name, func(b *testing.B) {
			c, refill := invalidationBenchClient(tc.api, tc.sts, tc.states, tc.affected)
			durations := make([]time.Duration, 0, b.N)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				refill()
				if tc.expired {
					for i := range tc.states {
						c.refresh[fmt.Sprintf("p-%d", i)] = refreshState{generation: 1}
					}
				}
				b.StartTimer()
				start := time.Now()
				result, err := c.InvalidateCredentials(InvalidationRequest{ProviderName: "target"})
				durations = append(durations, time.Since(start))
				if err != nil || (tc.api > 0 && result.APIKeyEntries != tc.affected) ||
					(tc.sts > 0 && result.STSEntries != tc.affected) {
					b.Fatalf("result=%+v err=%v", result, err)
				}
			}
			b.StopTimer()
			slices.Sort(durations)
			b.ReportMetric(float64(durations[len(durations)/2].Nanoseconds())/1000, "p50-us")
			b.ReportMetric(float64(durations[(len(durations)-1)*95/100].Nanoseconds())/1000, "p95-us")
			b.ReportMetric(float64(durations[len(durations)-1].Nanoseconds())/1000, "max-us")
		})
	}
}

type invalidationLoadSample struct {
	start   time.Time
	elapsed time.Duration
}
type invalidationLoadStats struct {
	service [100001]int64 // Microsecond buckets, final bucket includes >=100ms.
	total   [100001]int64
	slow    []invalidationLoadSample
	count   int64
	max     time.Duration
	err     error
}

func invalidationLoadPercentile(hist []int64, count int64, q float64) int {
	target := int64(float64(count) * q)
	var seen int64
	for i, n := range hist {
		seen += n
		if seen >= target {
			return i
		}
	}
	return len(hist) - 1
}

// Run separately with -run '^$' -bench '^BenchmarkCredentialCacheUnderInvalidation$' -benchtime=1x -cpu=8.
// This is an in-process open-loop load probe, not an HTTP or Kubernetes benchmark.
func BenchmarkCredentialCacheUnderInvalidation(b *testing.B) {
	ctx := log.IntoContext(context.Background(), logr.Discard())
	for _, invalidate := range []bool{false, true} {
		b.Run(fmt.Sprintf("invalidate=%t", invalidate), func(b *testing.B) {
			for range b.N {
				c, refill := invalidationBenchClient(10000, 100000, 100, 1)
				const duration = 70 * time.Second
				const spacing = 100 * time.Microsecond // 10,000 offered requests/s, split API key / STS.
				const workers = 8
				jobs := make(chan time.Time, 1024)
				stats := make([]invalidationLoadStats, workers)
				var wg sync.WaitGroup
				start := time.Now()
				stop := make(chan struct{})
				var events []invalidationLoadSample
				eventDone := make(chan struct{})
				go func() {
					defer close(eventDone)
					if !invalidate {
						return
					}
					timer := time.NewTimer(5 * time.Second)
					defer timer.Stop()
					for {
						select {
						case <-stop:
							return
						case <-timer.C:
							before := time.Now()
							result, err := c.InvalidateCredentials(InvalidationRequest{ProviderName: "target"})
							events = append(events, invalidationLoadSample{before, time.Since(before)})
							if err != nil || result.APIKeyEntries != 1 || result.STSEntries != 1 {
								b.Errorf("result=%+v err=%v", result, err)
								return
							}
							refill()
							timer.Reset(30 * time.Second)
						}
					}
				}()
				for i := range workers {
					wg.Go(func() {
						s := &stats[i]
						for scheduled := range jobs {
							before := time.Now()
							var err error
							if i%2 == 0 {
								var v string
								v, err = c.GetToken(ctx, "access", "0", "p-0")
								if err == nil && v != "key" {
									err = fmt.Errorf("unexpected API key")
								}
							} else {
								var v STSCredential
								v, err = c.GetSTSCredential(ctx, "access", "0", "p-0")
								if err == nil && v.AccessKeyID != "ak" {
									err = fmt.Errorf("unexpected STS credential")
								}
							}
							elapsed := time.Since(before)
							if err != nil {
								s.err = err
							}
							s.count++
							s.service[min(elapsed.Microseconds(), 100000)]++
							s.total[min(time.Since(scheduled).Microseconds(), 100000)]++
							if elapsed > s.max {
								s.max = elapsed
							}
							if elapsed >= time.Millisecond {
								s.slow = append(s.slow, invalidationLoadSample{before, elapsed})
							}
						}
					})
				}
				// Catch up after scheduler delays instead of silently dropping offered requests.
				for n := range int(duration / spacing) {
					scheduled := start.Add(time.Duration(n) * spacing)
					if wait := time.Until(scheduled); wait > 0 {
						time.Sleep(wait)
					}
					jobs <- scheduled
				}
				close(jobs)
				wg.Wait()
				close(stop)
				<-eventDone
				elapsed := time.Since(start)
				var merged invalidationLoadStats
				for _, s := range stats {
					if s.err != nil {
						b.Fatal(s.err)
					}
					merged.count += s.count
					merged.max = max(merged.max, s.max)
					merged.slow = append(merged.slow, s.slow...)
					for i := range s.service {
						merged.service[i] += s.service[i]
						merged.total[i] += s.total[i]
					}
				}
				b.ReportMetric(float64(merged.count)/elapsed.Seconds(), "requests/s")
				b.ReportMetric(float64(invalidationLoadPercentile(merged.service[:], merged.count, .99)), "hit-p99-us")
				b.ReportMetric(
					float64(invalidationLoadPercentile(merged.service[:], merged.count, .999)),
					"hit-p999-us",
				)
				b.ReportMetric(
					float64(invalidationLoadPercentile(merged.total[:], merged.count, .99)),
					"queue+hit-p99-us",
				)
				b.ReportMetric(float64(merged.max.Microseconds()), "hit-max-us")
				b.ReportMetric(float64(len(merged.slow)), "hits-ge1ms")
				for _, event := range events {
					overlaps := 0
					var worst time.Duration
					for _, sample := range merged.slow {
						if sample.start.Before(event.start.Add(event.elapsed)) &&
							sample.start.Add(sample.elapsed).After(event.start) {
							overlaps++
							worst = max(worst, sample.elapsed)
						}
					}
					b.Logf(
						"event_at=%s invalidate=%s overlapping_hits_ge1ms=%d worst_hit=%s",
						event.start.Sub(start),
						event.elapsed,
						overlaps,
						worst,
					)
				}
			}
		})
	}
}
