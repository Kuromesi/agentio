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

package agentio

import (
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
)

func TestNormalizeSNI(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		// Normalization.
		{name: "no-op", input: "example.com", want: "example.com"},
		{name: "uppercase", input: "EXAMPLE.COM", want: "example.com"},
		{name: "mixed case", input: "Example.COM", want: "example.com"},
		{name: "trailing dot", input: "example.com.", want: "example.com"},
		{name: "uppercase and trailing dot", input: "Example.COM.", want: "example.com"},
		{name: "wildcard uppercase trailing dot", input: "*.Example.COM.", want: "*.example.com"},
		{name: "empty", input: "", wantErr: true},
		{name: "dot alone", input: ".", wantErr: true},
		{name: "two trailing dots", input: "example.com..", wantErr: true},

		// Accepted forms.
		{name: "wildcard label", input: "*.example.com", want: "*.example.com"},
		{name: "bare wildcard", input: "*", want: "*"},
		{name: "bare wildcard with dot", input: "*.", want: "*"},
		{name: "deep subdomain", input: "a.b.c.example.com", want: "a.b.c.example.com"},
		{name: "wildcard deep subdomain", input: "*.a.b.example.com", want: "*.a.b.example.com"},
		{name: "single label", input: "localhost", want: "localhost"},

		// Rejected forms.
		{name: "partial wildcard prefix", input: "*foo.example.com", wantErr: true},
		{name: "dashed partial wildcard", input: "*-foo.example.com", wantErr: true},
		{name: "wildcard in middle", input: "foo.*.com", wantErr: true},
		{name: "two wildcard labels", input: "*.*.com", wantErr: true},
		{name: "double star", input: "**", wantErr: true},
		{name: "wildcard inside label", input: "ex*ample.com", wantErr: true},
		// These have a legal leading "*." but an additional '*' further right, so
		// only the "no other '*' anywhere" half of the rule rejects them.
		{name: "wildcard suffix in later label", input: "*.foo*.com", wantErr: true},
		{name: "wildcard inside later label", input: "*.a*b.com", wantErr: true},
		{name: "wildcard as last label", input: "*.foo.*", wantErr: true},
		{name: "wildcard prefix then bare wildcard", input: "*.*", wantErr: true},
		// These have no leading "*." at all, so only the "must start with *."
		// half of the rule rejects them.
		{name: "trailing star single label", input: "x*", wantErr: true},
		{name: "leading star single label", input: "*x", wantErr: true},
		{name: "star at end of first label", input: "a*.b.com", wantErr: true},
		{name: "regex anchors", input: "^a.com$", wantErr: true},
		{name: "all-numeric tld", input: "example.123", wantErr: true},
		{name: "wildcard all-numeric tld", input: "*.example.123", wantErr: true},
		{name: "empty inner label", input: "example..com", wantErr: true},
		{name: "leading dot", input: ".example.com", wantErr: true},
		{name: "leading dash label", input: "-a.com", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeSNI(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeSNI(%q) = %q, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeSNI(%q) returned unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeSNI(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeSNIIsIdempotent(t *testing.T) {
	for _, input := range []string{"Example.COM.", "*.Example.COM.", "*.", "a.b.example.com"} {
		first, err := normalizeSNI(input)
		if err != nil {
			t.Fatalf("NormalizeSNI(%q) returned unexpected error: %v", input, err)
		}
		second, err := normalizeSNI(first)
		if err != nil {
			t.Fatalf("NormalizeSNI(%q) returned unexpected error: %v", first, err)
		}
		if first != second {
			t.Errorf("NormalizeSNI not idempotent for %q: %q then %q", input, first, second)
		}
	}
}

func sniRule(action extensions.SniAction, sni ...string) *extensions.SniRule {
	return &extensions.SniRule{
		Match:  &extensions.SniMatch{Sni: sni},
		Action: action,
	}
}

func TestNormalizeSniTrafficPolicy(t *testing.T) {
	cases := []struct {
		name    string
		input   *extensions.SniTrafficPolicy
		want    *extensions.SniTrafficPolicy
		wantErr bool
	}{
		{
			name:  "nil policy",
			input: nil, wantErr: true,
		},
		{
			name:  "empty rules",
			input: &extensions.SniTrafficPolicy{},
			want:  &extensions.SniTrafficPolicy{},
		},
		{
			name: "normalizes and dedupes",
			input: &extensions.SniTrafficPolicy{
				Rules: []*extensions.SniRule{
					sniRule(extensions.SniAction_SNI_ACTION_PASSTHROUGH, "Example.com", "example.com.", "*.Example.COM"),
				},
			},
			want: &extensions.SniTrafficPolicy{
				Rules: []*extensions.SniRule{
					sniRule(extensions.SniAction_SNI_ACTION_PASSTHROUGH, "example.com", "*.example.com"),
				},
			},
		},
		{
			name: "preserves first occurrence order",
			input: &extensions.SniTrafficPolicy{
				Rules: []*extensions.SniRule{
					sniRule(extensions.SniAction_SNI_ACTION_DENY, "b.com", "A.com", "b.com.", "a.com"),
				},
			},
			want: &extensions.SniTrafficPolicy{
				Rules: []*extensions.SniRule{
					sniRule(extensions.SniAction_SNI_ACTION_DENY, "b.com", "a.com"),
				},
			},
		},
		{
			name: "multiple rules preserved in order",
			input: &extensions.SniTrafficPolicy{
				Rules: []*extensions.SniRule{
					sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, "a.com"),
					sniRule(extensions.SniAction_SNI_ACTION_DENY, "*"),
				},
			},
			want: &extensions.SniTrafficPolicy{
				Rules: []*extensions.SniRule{
					sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, "a.com"),
					sniRule(extensions.SniAction_SNI_ACTION_DENY, "*"),
				},
			},
		},
		{
			name: "unspecified action rejected",
			input: &extensions.SniTrafficPolicy{
				Rules: []*extensions.SniRule{sniRule(extensions.SniAction_SNI_ACTION_UNSPECIFIED, "a.com")},
			},
			wantErr: true,
		},
		{
			name: "nil match rejected",
			input: &extensions.SniTrafficPolicy{
				Rules: []*extensions.SniRule{{Action: extensions.SniAction_SNI_ACTION_DENY}},
			},
			wantErr: true,
		},
		{
			name: "empty sni list rejected",
			input: &extensions.SniTrafficPolicy{
				Rules: []*extensions.SniRule{sniRule(extensions.SniAction_SNI_ACTION_DENY)},
			},
			wantErr: true,
		},
		{
			name: "invalid sni rejected",
			input: &extensions.SniTrafficPolicy{
				Rules: []*extensions.SniRule{sniRule(extensions.SniAction_SNI_ACTION_DENY, "a.com", "*foo.example.com")},
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeSniTrafficPolicy(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeSniTrafficPolicy() = %v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeSniTrafficPolicy() returned unexpected error: %v", err)
			}
			if !proto.Equal(got, tc.want) {
				t.Errorf("NormalizeSniTrafficPolicy() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNormalizeSniTrafficPolicyDoesNotMutateInput(t *testing.T) {
	input := &extensions.SniTrafficPolicy{
		Rules: []*extensions.SniRule{
			sniRule(extensions.SniAction_SNI_ACTION_PASSTHROUGH, "Example.com", "example.com.", "*.Example.COM"),
		},
	}
	original := proto.Clone(input).(*extensions.SniTrafficPolicy)

	got, err := normalizeSniTrafficPolicy(input)
	if err != nil {
		t.Fatalf("NormalizeSniTrafficPolicy() returned unexpected error: %v", err)
	}
	if !proto.Equal(input, original) {
		t.Errorf("NormalizeSniTrafficPolicy mutated its input: got %v, want %v", input, original)
	}
	if got == input {
		t.Errorf("NormalizeSniTrafficPolicy returned its input pointer, want a deep copy")
	}
	if got.GetRules()[0] == input.GetRules()[0] {
		t.Errorf("NormalizeSniTrafficPolicy shared a rule pointer with its input, want a deep copy")
	}
}

func TestSortPolicyRefs(t *testing.T) {
	older := time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	cases := []struct {
		name  string
		input []PolicyRef
		want  []string
	}{
		{name: "empty", input: nil, want: []string{}},
		{
			name: "priority descending",
			input: []PolicyRef{
				{ResourceName: "ns/low", Priority: 1},
				{ResourceName: "ns/high", Priority: 100},
				{ResourceName: "ns/mid", Priority: 50},
			},
			want: []string{"ns/high", "ns/mid", "ns/low"},
		},
		{
			name: "creation time tie-break ascending",
			input: []PolicyRef{
				{ResourceName: "ns/a", Priority: 10, CreationTime: newer, SourceName: "a", SourceNamespace: "ns"},
				{ResourceName: "ns/z", Priority: 10, CreationTime: older, SourceName: "z", SourceNamespace: "ns"},
			},
			want: []string{"ns/z", "ns/a"},
		},
		{
			name: "source name before namespace",
			input: []PolicyRef{
				{ResourceName: "a/z", Priority: 10, CreationTime: older, SourceName: "z", SourceNamespace: "a"},
				{ResourceName: "z/a", Priority: 10, CreationTime: older, SourceName: "a", SourceNamespace: "z"},
			},
			want: []string{"z/a", "a/z"},
		},
		{
			name: "namespace after source name",
			input: []PolicyRef{
				{ResourceName: "z/same", Priority: 10, CreationTime: older, SourceName: "same", SourceNamespace: "z"},
				{ResourceName: "a/same", Priority: 10, CreationTime: older, SourceName: "same", SourceNamespace: "a"},
			},
			want: []string{"a/same", "z/same"},
		},
		{
			name: "resource name is final total tie-break",
			input: []PolicyRef{
				{ResourceName: "ns/c", Priority: 10},
				{ResourceName: "ns/a", Priority: 10},
				{ResourceName: "ns/b", Priority: 10},
			},
			want: []string{"ns/a", "ns/b", "ns/c"},
		},
		{
			name: "negative priorities",
			input: []PolicyRef{
				{ResourceName: "ns/neg", Priority: -10},
				{ResourceName: "ns/zero", Priority: 0},
				{ResourceName: "ns/verynge", Priority: -100},
				{ResourceName: "ns/pos", Priority: 5},
			},
			want: []string{"ns/pos", "ns/zero", "ns/neg", "ns/verynge"},
		},
		{
			name: "priority beats name",
			input: []PolicyRef{
				{ResourceName: "ns/a", Priority: 1},
				{ResourceName: "ns/z", Priority: 2},
			},
			want: []string{"ns/z", "ns/a"},
		},
		{
			name:  "single element",
			input: []PolicyRef{{ResourceName: "ns/only", Priority: 7}},
			want:  []string{"ns/only"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sortPolicyRefs(tc.input)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("SortPolicyRefs() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSortPolicyRefsIsTotal(t *testing.T) {
	// The same set in different input orders must produce the same output, i.e.
	// the ordering does not depend on input order.
	a := []PolicyRef{
		{ResourceName: "ns/a", Priority: 10, SourceName: "a", SourceNamespace: "ns"},
		{ResourceName: "ns/b", Priority: 10, SourceName: "b", SourceNamespace: "ns"},
		{ResourceName: "ns/c", Priority: 20, SourceName: "c", SourceNamespace: "ns"},
	}
	b := []PolicyRef{
		{ResourceName: "ns/b", Priority: 10, SourceName: "b", SourceNamespace: "ns"},
		{ResourceName: "ns/c", Priority: 20, SourceName: "c", SourceNamespace: "ns"},
		{ResourceName: "ns/a", Priority: 10, SourceName: "a", SourceNamespace: "ns"},
	}
	want := []string{"ns/c", "ns/a", "ns/b"}
	if got := sortPolicyRefs(a); !reflect.DeepEqual(got, want) {
		t.Errorf("SortPolicyRefs(a) = %v, want %v", got, want)
	}
	if got := sortPolicyRefs(b); !reflect.DeepEqual(got, want) {
		t.Errorf("SortPolicyRefs(b) = %v, want %v", got, want)
	}
}

func TestSortPolicyRefsDoesNotMutateInput(t *testing.T) {
	input := []PolicyRef{
		{ResourceName: "ns/a", Priority: 1},
		{ResourceName: "ns/z", Priority: 99},
	}
	original := make([]PolicyRef, len(input))
	copy(original, input)

	sortPolicyRefs(input)

	if !reflect.DeepEqual(input, original) {
		t.Errorf("SortPolicyRefs mutated its input: got %v, want %v", input, original)
	}
}
