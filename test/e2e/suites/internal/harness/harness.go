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

// Package harness carries the Agentio product-suite conventions shared by the
// per-domain E2E suites: the AGENTIO_E2E gate, the baseline ConfigMap
// contract, scenario ledgers with contamination tracking, and the
// profile-aware echo fixture layout. Generic Kubernetes, echo, and retry helpers stay in
// their reusable components.
package harness

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/retry"
)

// Harness binds a suite to its resolved Agentio configuration and tracks
// whether a retained scenario failure has contaminated the shared
// environment. Each suite process owns exactly one Harness.
type Harness struct {
	Suite  *e2e.Suite
	Config agentiocomponent.Config

	contaminated atomic.Bool
}

func New(suite *e2e.Suite, config agentiocomponent.Config) *Harness {
	return &Harness{Suite: suite, Config: config}
}

// RequireLive skips the test unless the live E2E gate is set and fails when
// the gate is set but the suite was never initialized. It is safe to call on
// a nil Harness so tests can run in plain unit mode.
func (h *Harness) RequireLive(t *testing.T) {
	t.Helper()
	if os.Getenv("AGENTIO_E2E") != "1" {
		t.Skip("set AGENTIO_E2E=1 and immutable Agentio image inputs to run this live test")
	}
	if h == nil || h.Suite == nil {
		t.Fatal("Agentio E2E suite was not initialized")
	}
}

func (h *Harness) RequireUncontaminated(t *testing.T) {
	t.Helper()
	if h.contaminated.Load() {
		t.Skip("shared Agentio environment was retained after an earlier scenario failure")
	}
}

// Contaminate marks the shared environment as retained-dirty so later
// scenarios skip instead of running against contaminated state.
func (h *Harness) Contaminate() {
	h.contaminated.Store(true)
}

// RunScenario runs body as a subtest with a scoped resource ledger. A
// successful scenario cleans its resources and restores the Agentio baseline;
// a failed scenario under deferred cleanup retains its evidence and
// contaminates the environment.
func (h *Harness) RunScenario(t *testing.T, name string, body func(*testing.T, *kube.ResourceScope)) {
	t.Helper()
	if h.contaminated.Load() {
		t.Run(name, func(t *testing.T) {
			t.Skip("shared Agentio environment was retained after an earlier scenario failure")
		})
		return
	}
	t.Run(name, func(t *testing.T) {
		environment := h.Suite.Environment(t)
		scope := kube.NewResourceScope(environment.Kube)
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			dirty, err := finishScenario(preserveFailedScenario(t.Failed(), environment.DefersResourceCleanup()), func() error {
				return scope.DeleteReverse(ctx)
			}, func() error {
				return h.RestoreBaseline(ctx, environment)
			})
			if dirty {
				h.contaminated.Store(true)
			}
			if err != nil {
				t.Errorf("clean scenario resources: %v", err)
			}
		})
		body(t, scope)
	})
}

// BeginScenario gates on the live environment and returns a scoped resource
// ledger for a whole-test scenario. Cleanup preserves resources whenever the
// test failed, regardless of the retention mode.
func (h *Harness) BeginScenario(t *testing.T) (*e2e.Environment, *kube.ResourceScope) {
	t.Helper()
	h.RequireLive(t)
	h.RequireUncontaminated(t)
	environment := h.Suite.Environment(t)
	scope := kube.NewResourceScope(environment.Kube)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		dirty, err := finishScenario(t.Failed(), func() error {
			return scope.DeleteReverse(ctx)
		}, func() error {
			return h.RestoreBaseline(ctx, environment)
		})
		if dirty {
			h.contaminated.Store(true)
		}
		if err != nil {
			t.Errorf("clean scenario resources: %v", err)
		}
	})
	return environment, scope
}

// ApplyConfig renders manifest with the control-plane namespace and values
// and reconciles it through the scenario scope.
func (h *Harness) ApplyConfig(t *testing.T, scope *kube.ResourceScope, values map[string]any, manifest string) {
	t.Helper()
	e2econfig.New(scope).
		Eval(h.Config.Namespace, values, manifest).
		ApplyOrFail(t, kube.ReconcileOwned)
}

func preserveFailedScenario(failed, deferCleanup bool) bool {
	return failed && deferCleanup
}

func finishScenario(preserve bool, cleanup, restore func() error) (bool, error) {
	if preserve {
		return true, nil
	}
	if err := cleanup(); err != nil {
		return true, err
	}
	if err := restore(); err != nil {
		return true, err
	}
	return false, nil
}

// RetryAssertion polls assertion at a fixed delay until it succeeds or the
// timeout elapses.
func RetryAssertion(t *testing.T, timeout, delay time.Duration, assertion func() error) {
	t.Helper()
	ctx, cancel := e2e.Context(t, timeout)
	defer cancel()
	if err := retry.UntilSuccess(ctx, FixedRetry(timeout, delay), assertion); err != nil {
		t.Fatal(err)
	}
}

// FixedRetry is a constant-delay, single-success retry policy.
func FixedRetry(timeout, delay time.Duration) retry.Policy {
	return retry.Policy{
		Timeout:  timeout,
		Delay:    delay,
		Backoff:  1,
		MaxDelay: delay,
		Converge: 1,
	}
}
