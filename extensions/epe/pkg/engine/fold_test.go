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
package engine

import (
	"strings"
	"testing"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// TestFold drives Fold through a net-effect table: each case is one ordered
// mutation list and the exact op sequence it must fold to. Header names are
// compared case-insensitively because HTTP header names are case-insensitive
// and Envoy lower-cases them; the spelling Fold preserves is not part of the
// contract.
func TestFold(t *testing.T) {
	tests := []struct {
		name string
		in   []filter.Mutation
		want []filter.HeaderOp
	}{
		{
			// Envoy applies all removes before all sets inside one
			// HeaderMutation, so "B removes what A set" concatenated as
			// [set, remove] would come out SET. Folding must yield a remove
			// only.
			name: "remove after set yields remove",
			in: []filter.Mutation{
				filter.SetHeader("x-token", "secret"),
				filter.RemoveHeader("x-token"),
			},
			want: []filter.HeaderOp{{Kind: filter.HeaderRemove, Name: "x-token"}},
		},
		{
			name: "set after remove yields set",
			in: []filter.Mutation{
				filter.RemoveHeader("x-a"),
				filter.SetHeader("x-a", "v"),
			},
			want: []filter.HeaderOp{{Kind: filter.HeaderSet, Name: "x-a", Value: "v"}},
		},
		{
			// Remove-then-Add must keep the remove. Envoy runs all removes
			// before all set/add operations inside one HeaderMutation, so
			// [Remove, Add] is expressible and means "drop the inbound
			// value, then add v". Emitting the add alone makes Envoy append
			// to the inbound value instead, yielding "inbound, v".
			//
			// Note the "never both" invariant in Fold's doc is only required
			// in the Set->Remove direction; this direction genuinely needs
			// both ops.
			name: "add after remove keeps the remove",
			in: []filter.Mutation{
				filter.RemoveHeader("x-a"),
				filter.AddHeader("x-a", "v"),
			},
			want: []filter.HeaderOp{
				{Kind: filter.HeaderRemove, Name: "x-a"},
				{Kind: filter.HeaderAdd, Name: "x-a", Value: "v"},
			},
		},
		{
			// Set-then-Remove-then-Add: the set is discarded by the remove,
			// and the remove must still be materialized ahead of the add.
			name: "set remove add keeps the remove",
			in: []filter.Mutation{
				filter.SetHeader("x-a", "old"),
				filter.RemoveHeader("x-a"),
				filter.AddHeader("x-a", "v"),
			},
			want: []filter.HeaderOp{
				{Kind: filter.HeaderRemove, Name: "x-a"},
				{Kind: filter.HeaderAdd, Name: "x-a", Value: "v"},
			},
		},
		{
			// Header names are case-insensitive in HTTP and Envoy lower-cases
			// them, so folding must treat X-Foo and x-foo as one key. Signers
			// may emit mixed-case names like "Authorization" while other
			// filters emit lower-case names.
			name: "header names fold case-insensitively",
			in: []filter.Mutation{
				filter.SetHeader("X-Foo", "a"),
				filter.RemoveHeader("x-foo"),
			},
			want: []filter.HeaderOp{{Kind: filter.HeaderRemove, Name: "x-foo"}},
		},
		{
			// The reverse order must also collapse to one key.
			name: "header name case folds across set and add",
			in: []filter.Mutation{
				filter.SetHeader("Authorization", "Bearer a"),
				filter.SetHeader("authorization", "Bearer b"),
			},
			want: []filter.HeaderOp{{Kind: filter.HeaderSet, Name: "authorization", Value: "Bearer b"}},
		},
		{
			// map[string]string cannot express two set-cookie values; the
			// ordered op list must.
			name: "add preserves ordered multi-value",
			in: []filter.Mutation{
				filter.AddHeader("set-cookie", "a=1"),
				filter.AddHeader("set-cookie", "b=2"),
			},
			want: []filter.HeaderOp{
				{Kind: filter.HeaderAdd, Name: "set-cookie", Value: "a=1"},
				{Kind: filter.HeaderAdd, Name: "set-cookie", Value: "b=2"},
			},
		},
		{
			name: "set overrides earlier adds",
			in: []filter.Mutation{
				filter.AddHeader("x-a", "1"),
				filter.SetHeader("x-a", "final"),
			},
			want: []filter.HeaderOp{{Kind: filter.HeaderSet, Name: "x-a", Value: "final"}},
		},
		{
			name: "independent keys keep first-touch order",
			in: []filter.Mutation{
				filter.SetHeader("b", "2"),
				filter.SetHeader("a", "1"),
			},
			want: []filter.HeaderOp{
				{Kind: filter.HeaderSet, Name: "b", Value: "2"},
				{Kind: filter.HeaderSet, Name: "a", Value: "1"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := Fold(tc.in)
			if len(out) != len(tc.want) {
				t.Fatalf("Fold = %+v, want %+v", out, tc.want)
			}
			for i, w := range tc.want {
				if out[i].Kind != w.Kind || !strings.EqualFold(out[i].Name, w.Name) || out[i].Value != w.Value {
					t.Errorf("Fold[%d] = %+v, want %+v (name compared case-insensitively)", i, out[i], w)
				}
			}
		})
	}
}
