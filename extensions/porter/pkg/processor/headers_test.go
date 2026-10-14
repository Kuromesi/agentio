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

package processor

import (
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

func TestParseConnectHeaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []*core.HeaderValue
		want    string
		invalid bool
	}{
		{name: "absent"},
		{name: "unrelated", headers: []*core.HeaderValue{{Key: "other", Value: "value"}}},
		{name: "raw", headers: []*core.HeaderValue{{Key: HeaderSNI, RawValue: []byte("API.Example.COM.")}}, want: "api.example.com"},
		{name: "value", headers: []*core.HeaderValue{{Key: HeaderSNI, Value: "api.example.com"}}, want: "api.example.com"},
		{name: "empty", headers: []*core.HeaderValue{{Key: HeaderSNI}}, invalid: true},
		{name: "invalid", headers: []*core.HeaderValue{{Key: HeaderSNI, Value: "bad/name"}}, invalid: true},
		{name: "duplicate", headers: []*core.HeaderValue{{Key: HeaderSNI, Value: "a.com"}, {Key: HeaderSNI, Value: "b.com"}}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseConnectHeaders(&extproc.HttpHeaders{Headers: &core.HeaderMap{Headers: tc.headers}})
			if (err != nil) != tc.invalid || (!tc.invalid && got.SNI != tc.want) {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}
