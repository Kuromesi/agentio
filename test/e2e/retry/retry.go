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

package retry

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	DefaultTimeout  = 30 * time.Second
	DefaultDelay    = 10 * time.Millisecond
	DefaultConverge = 1
)

type Policy struct {
	Timeout time.Duration
	// NoTimeout delegates timeout control entirely to the caller's context.
	NoTimeout bool
	Delay     time.Duration
	Backoff   float64
	MaxDelay  time.Duration
	Converge  int
}

func UntilSuccess(ctx context.Context, policy Policy, fn func() error) error {
	if fn == nil {
		return errors.New("retry function is required")
	}
	policy = policy.withDefaults()
	retryCtx, cancel := ctx, func() {}
	if !policy.NoTimeout {
		retryCtx, cancel = context.WithTimeout(ctx, policy.Timeout)
	}
	defer cancel()

	delay := policy.Delay
	consecutive := 0
	attempts := 0
	var lastErr error
	for {
		if err := retryCtx.Err(); err != nil {
			return exhausted(err, lastErr, attempts, consecutive, policy.Converge)
		}
		err := fn()
		attempts++
		if err == nil {
			consecutive++
			if consecutive >= policy.Converge {
				return nil
			}
			continue
		}
		lastErr = err
		consecutive = 0
		if err := wait(retryCtx, delay); err != nil {
			return exhausted(err, lastErr, attempts, consecutive, policy.Converge)
		}
		delay = nextDelay(delay, policy.Backoff, policy.MaxDelay)
	}
}

func (p Policy) withDefaults() Policy {
	if p.Timeout <= 0 {
		p.Timeout = DefaultTimeout
	}
	if p.Delay <= 0 {
		p.Delay = DefaultDelay
	}
	if p.Backoff < 1 {
		p.Backoff = 2
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = p.Delay * 16
	}
	if p.MaxDelay < p.Delay {
		p.MaxDelay = p.Delay
	}
	if p.Converge <= 0 {
		p.Converge = DefaultConverge
	}
	return p
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func nextDelay(delay time.Duration, backoff float64, maximum time.Duration) time.Duration {
	next := time.Duration(float64(delay) * backoff)
	if next <= delay && backoff > 1 {
		next = delay + 1
	}
	if next > maximum {
		return maximum
	}
	return next
}

func exhausted(contextErr, lastErr error, attempts, consecutive, converge int) error {
	cause := contextErr
	if lastErr != nil {
		cause = errors.Join(contextErr, lastErr)
	}
	if converge > 1 {
		return fmt.Errorf("retry exhausted after %d attempts (%d/%d consecutive successes): %w", attempts, consecutive, converge, cause)
	}
	return fmt.Errorf("retry exhausted after %d attempts: %w", attempts, cause)
}
