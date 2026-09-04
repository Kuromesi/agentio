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
package inputs

import (
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
)

func TestPodLabel(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		key    string
		want   string
	}{
		{"present", map[string]string{"app": "sleep"}, "app", "sleep"},
		{"absent", map[string]string{"app": "sleep"}, "missing", ""},
		{"nil map", nil, "app", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Pod{Labels: tt.labels}
			if got := p.Label(tt.key); got != tt.want {
				t.Errorf("Label(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestRequestHeaderAndQuery(t *testing.T) {
	r := RequestFrom(httpreq.HTTPRequest{Host: "h", Port: 80, Path: "/p", Scheme: "http", Method: "GET", Query: map[string][]string{"a": {"1", "2"}}, Headers: map[string]string{"x-k": "v"}})
	if got := r.Header("X-K"); got != "v" {
		t.Errorf("Header case-insensitive = %q, want v", got)
	}
	if got := r.Header("missing"); got != "" {
		t.Errorf("Header missing = %q, want empty", got)
	}
	if got := r.QueryParam("a"); got != "1" {
		t.Errorf("QueryParam(a) = %q, want 1", got)
	}
	if got := r.QueryParam("missing"); got != "" {
		t.Errorf("QueryParam missing = %q, want empty", got)
	}
}
