// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

// Package kube provides cache synchronization helpers used by local KRT collections.
package kube

import (
	"time"

	"k8s.io/client-go/tools/cache"

	"istio.io/istio/pkg/sleep"
)

func WaitForCacheSync(name string, stop <-chan struct{}, cacheSyncs ...cache.InformerSynced) (r bool) {
	t0 := time.Now()
	maximum := time.Millisecond * 100
	delay := time.Millisecond
	f := func() bool {
		for _, syncFunc := range cacheSyncs {
			if !syncFunc() {
				return false
			}
		}
		return true
	}
	attempt := 0
	defer func() {
		if r {
			log.Info("cache sync complete", "name", name,
				"attempt", attempt, "elapsed", time.Since(t0))
		} else {
			log.Error("cache sync failed", "name", name,
				"attempt", attempt, "elapsed", time.Since(t0))
		}
	}()
	for {
		select {
		case <-stop:
			return false
		default:
		}
		attempt++
		res := f()
		if res {
			return true
		}
		delay *= 2
		if delay > maximum {
			delay = maximum
		}
		log.Debug("waiting for cache sync", "name", name,
			"attempt", attempt, "elapsed", time.Since(t0))
		if attempt%50 == 0 {
			// Log every 50th attempt (5s) at info, to avoid too much noisy
			log.Info("waiting for cache sync", "name", name,
				"attempt", attempt, "elapsed", time.Since(t0))
		}
		if !sleep.Until(stop, delay) {
			return false
		}
	}
}
