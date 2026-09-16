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

package registry

import (
	"slices"
	"testing"
)

func TestParseSandboxRuntimes(t *testing.T) {
	for _, tt := range []struct {
		value   string
		want    []SandboxRuntime
		wantErr bool
	}{
		{value: ""},
		{value: "  "},
		{value: "kruise", want: []SandboxRuntime{SandboxRuntimeKruise}},
		{value: " kruise, kruise ", want: []SandboxRuntime{SandboxRuntimeKruise}},
		{value: "pod", wantErr: true},
		{value: "kruise,unknown", wantErr: true},
		{value: "kruise,", wantErr: true},
	} {
		t.Run(tt.value, func(t *testing.T) {
			got, err := ParseSandboxRuntimes(tt.value)
			if (err != nil) != tt.wantErr || !slices.Equal(got, tt.want) {
				t.Fatalf("ParseSandboxRuntimes(%q) = %v, %v; want %v, error=%t", tt.value, got, err, tt.want, tt.wantErr)
			}
		})
	}
}
