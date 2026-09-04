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

package e2e

import (
	"testing"
	"time"
)

func TestContextUsesRequestedTimeout(t *testing.T) {
	started := time.Now()
	ctx, cancel := Context(t, 100*time.Millisecond)
	defer cancel()
	deadline, found := ctx.Deadline()
	if !found {
		t.Fatal("Context() returned no deadline")
	}
	if remaining := deadline.Sub(started); remaining < 50*time.Millisecond || remaining > 150*time.Millisecond {
		t.Fatalf("deadline remaining = %v, want about 100ms", remaining)
	}
}
