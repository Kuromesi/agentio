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
	"strings"
	"testing"
	"time"
)

func TestUntilSuccessRetriesUntilSuccess(t *testing.T) {
	attempts := 0
	err := UntilSuccess(context.Background(), Policy{
		Timeout:  time.Second,
		Delay:    time.Millisecond,
		Backoff:  1,
		MaxDelay: time.Millisecond,
	}, func() error {
		attempts++
		if attempts < 3 {
			return fmt.Errorf("attempt %d", attempts)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestUntilSuccessRequiresConsecutiveSuccesses(t *testing.T) {
	results := []error{nil, errors.New("reset"), nil, nil, nil}
	attempts := 0
	err := UntilSuccess(context.Background(), Policy{
		Timeout:  time.Second,
		Delay:    time.Millisecond,
		Backoff:  1,
		MaxDelay: time.Millisecond,
		Converge: 3,
	}, func() error {
		result := results[attempts]
		attempts++
		return result
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 5 {
		t.Fatalf("attempts = %d, want 5", attempts)
	}
}

func TestUntilSuccessAlternatingResultDoesNotConverge(t *testing.T) {
	attempts := 0
	err := UntilSuccess(context.Background(), Policy{
		Timeout:  15 * time.Millisecond,
		Delay:    time.Millisecond,
		Backoff:  1,
		MaxDelay: time.Millisecond,
		Converge: 2,
	}, func() error {
		attempts++
		if attempts%2 == 0 {
			return nil
		}
		return errors.New("failure resets convergence")
	})
	if err == nil {
		t.Fatal("UntilSuccess converged on non-consecutive successes")
	}
}

func TestUntilSuccessCancellationPreservesLastError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	last := errors.New("endpoint refused connection")
	attempts := 0
	err := UntilSuccess(ctx, Policy{
		Timeout:  time.Second,
		Delay:    time.Millisecond,
		Backoff:  1,
		MaxDelay: time.Millisecond,
	}, func() error {
		attempts++
		if attempts == 2 {
			cancel()
		}
		return last
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	if !errors.Is(err, last) || !strings.Contains(err.Error(), last.Error()) {
		t.Fatalf("error = %v, want last operation error", err)
	}
}

func TestUntilSuccessBackoffIsCapped(t *testing.T) {
	started := time.Now()
	err := UntilSuccess(context.Background(), Policy{
		Timeout:  28 * time.Millisecond,
		Delay:    2 * time.Millisecond,
		Backoff:  10,
		MaxDelay: 4 * time.Millisecond,
	}, func() error { return errors.New("still failing") })
	if err == nil {
		t.Fatal("UntilSuccess succeeded")
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("retry ignored timeout/cap: elapsed %v", elapsed)
	}
}

func TestUntilSuccessNoTimeoutUsesCallerContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := UntilSuccess(ctx, Policy{NoTimeout: true, Delay: time.Millisecond, Backoff: 1, MaxDelay: time.Millisecond}, func() error {
		return errors.New("still failing")
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want caller deadline", err)
	}
}
