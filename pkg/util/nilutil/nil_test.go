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

package nilutil

import (
	"testing"
	"unsafe"
)

func TestIsNilInterface(t *testing.T) {
	var pointer *int
	var channel chan int
	var function func()
	var mapping map[string]int
	var slice []int
	for _, value := range []any{nil, pointer, channel, function, mapping, slice, unsafe.Pointer(nil)} {
		if !IsNilInterface(value) {
			t.Errorf("typed nil %T was not nil", value)
		}
	}
	for _, value := range []any{0, false, "", struct{}{}, new(int), make(chan int), func() {}, map[string]int{}, []int{}} {
		if IsNilInterface(value) {
			t.Errorf("non-nil %T was nil", value)
		}
	}
}
