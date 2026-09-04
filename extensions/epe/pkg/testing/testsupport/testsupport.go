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

// Package testsupport holds EPE's test helpers that the standard library
// does not provide. Everything is built on testing.TB and t.Cleanup only.
package testsupport

import (
	"testing"
	"time"
)

// SetForTest sets vv to v for the duration of the test and restores the
// previous value on cleanup. The standard library covers environment
// variables (t.Setenv) but not package-level Go variables.
func SetForTest[T any](t testing.TB, vv *T, v T) {
	old := *vv
	*vv = v
	t.Cleanup(func() { *vv = old })
}

// Eventually polls fn every 50ms until it returns nil, failing the test with
// the last error once timeout elapses.
func Eventually(t testing.TB, timeout time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := fn()
		if err == nil {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("condition not met within %v: %v", timeout, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
