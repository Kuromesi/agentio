// Copyright Istio Authors
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

package krt

import (
	"testing"
	"time"
)

func TestWithDebounce(t *testing.T) {
	opts := buildCollectionOptions(WithDebounce(50*time.Millisecond, 500*time.Millisecond))
	if opts.debounceInterval != 50*time.Millisecond {
		t.Fatalf("debounceInterval = %v, want 50ms", opts.debounceInterval)
	}
	if opts.debounceMaxInterval != 500*time.Millisecond {
		t.Fatalf("debounceMaxInterval = %v, want 500ms", opts.debounceMaxInterval)
	}
}

func TestWithDebounceDefault(t *testing.T) {
	opts := buildCollectionOptions()
	if opts.debounceInterval != 0 {
		t.Fatalf("debounceInterval = %v, want 0", opts.debounceInterval)
	}
	if opts.debounceMaxInterval != 0 {
		t.Fatalf("debounceMaxInterval = %v, want 0", opts.debounceMaxInterval)
	}
}
