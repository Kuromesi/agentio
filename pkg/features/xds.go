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

package features

import (
	"fmt"
	"math"
	"runtime"
	"time"

	"istio.io/istio/pkg/env"
)

var (
	KRTDebounceAfter = env.Register(
		"AGENTIO_KRT_DEBOUNCE",
		200*time.Millisecond,
		"Quiet period before an informer-backed collection distributes events.",
	).Get()
	KRTDebounceMax = env.Register(
		"AGENTIO_KRT_DEBOUNCE_MAX",
		10*time.Second,
		"Upper bound on the collection quiet period, so a continuously changing cluster still makes progress.",
	).Get()
	PushDebounceAfter = env.Register(
		"AGENTIO_PUSH_DEBOUNCE",
		100*time.Millisecond,
		"Quiet period before compiled dirty resources are merged and published.",
	).Get()
	PushDebounceMax = env.Register(
		"AGENTIO_PUSH_DEBOUNCE_MAX",
		10*time.Second,
		"Upper bound on the push quiet period.",
	).Get()
	ClientQueueSize = env.Register(
		"AGENTIO_CLIENT_QUEUE_SIZE",
		100,
		"Maximum requests queued per xDS client before the stream is considered stuck.",
	).Get()
	MaxServerConnectionAge, maxServerConnectionAgeErr = time.ParseDuration(env.Register(
		"AGENTIO_KEEPALIVE_MAX_SERVER_CONNECTION_AGE",
		"30m",
		"Maximum lifetime of a server-side gRPC connection before a graceful close. Zero disables periodic connection expiry.",
	).Get())
	PushConcurrency = env.Register(
		"AGENTIO_PUSH_CONCURRENCY",
		defaultPushConcurrency(),
		"Maximum number of client connections generating and sending pushed xDS responses concurrently.",
	).Get()
	RequestRateLimit = effectiveRequestRateLimit(env.Register(
		"AGENTIO_MAX_REQUESTS_PER_SECOND",
		0.0,
		"Maximum incoming xDS requests accepted per second across the process. "+
			"Zero automatically derives the limit from the available CPU count.",
	).Get())
)

func validateXDS() error {
	if maxServerConnectionAgeErr != nil {
		return fmt.Errorf("parse max server connection age: %w", maxServerConnectionAgeErr)
	}
	if MaxServerConnectionAge < 0 {
		return fmt.Errorf("max server connection age must not be negative")
	}
	if KRTDebounceAfter <= 0 {
		return fmt.Errorf("KRT debounce quiet period must be positive")
	}
	if KRTDebounceMax < KRTDebounceAfter {
		return fmt.Errorf("KRT debounce maximum wait must be at least the quiet period")
	}
	if PushDebounceAfter <= 0 {
		return fmt.Errorf("push debounce quiet period must be positive")
	}
	if PushDebounceMax < PushDebounceAfter {
		return fmt.Errorf("push debounce maximum wait must be at least the quiet period")
	}
	if PushConcurrency <= 0 {
		return fmt.Errorf("push concurrency must be positive")
	}
	if RequestRateLimit <= 0 || math.IsNaN(RequestRateLimit) || math.IsInf(RequestRateLimit, 0) {
		return fmt.Errorf("request rate limit must be finite and positive")
	}
	if ClientQueueSize <= 0 {
		return fmt.Errorf("client queue size must be positive")
	}
	return nil
}

func defaultPushConcurrency() int {
	limit := 15 + 5*runtime.GOMAXPROCS(0)
	if limit > 100 {
		return 100
	}
	return limit
}

func effectiveRequestRateLimit(configured float64) float64 {
	if configured <= 0 || math.IsNaN(configured) || math.IsInf(configured, 0) {
		return float64(defaultPushConcurrency())
	}
	return configured
}
