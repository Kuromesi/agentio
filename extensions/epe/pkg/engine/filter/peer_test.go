// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package filter

import (
	"encoding/json"
	"testing"

	"k8s.io/apimachinery/pkg/types"
)

func TestSandboxTokenJSONRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want SandboxToken
	}{
		{
			name: "all fields",
			in:   `{"requestId":"r1","accessToken":"a1","sandboxClientId":"c1"}`,
			want: SandboxToken{RequestID: "r1", AccessToken: "a1", SandboxClientID: "c1"},
		},
		{
			name: "empty object",
			in:   `{}`,
			want: SandboxToken{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got SandboxToken
			if err := json.Unmarshal([]byte(tt.in), &got); err != nil {
				t.Fatalf("json.Unmarshal(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("SandboxToken: want %+v, got %+v", tt.want, got)
			}
		})
	}
}

func TestPeerValid(t *testing.T) {
	tests := []struct {
		name string
		peer Peer
		want bool
	}{
		{
			name: "namespace and name present",
			peer: Peer{Pod: types.NamespacedName{Namespace: "ns", Name: "pod"}},
			want: true,
		},
		{
			name: "missing name",
			peer: Peer{Pod: types.NamespacedName{Namespace: "ns"}},
			want: false,
		},
		{
			name: "missing namespace",
			peer: Peer{Pod: types.NamespacedName{Name: "pod"}},
			want: false,
		},
		{
			name: "zero peer",
			peer: Peer{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.peer.Valid(); got != tt.want {
				t.Errorf("Valid(): want %v, got %v", tt.want, got)
			}
		})
	}
}
