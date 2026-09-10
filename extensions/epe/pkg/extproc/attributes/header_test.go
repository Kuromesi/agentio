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

package attributes

import (
	"context"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extpb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

func TestStringPseudoHeadersPreserveRequestPolicyInputs(t *testing.T) {
	h := &extpb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: ":method", Value: "POST"}, {Key: ":path", Value: "/mcp?x=1"},
		{Key: ":authority", Value: "api.example.com:8443"}, {Key: ":scheme", Value: "https"},
		{Key: "x-request-id", RawValue: []byte("raw-id")},
	}}}
	attrs := makeAttrs(t, map[string]any{FilterStateDownstreamPeerName: "sandbox-a", FilterStateDownstreamPeerNamespace: "poc"})
	_, req := Extract(context.Background(), h, attrs)
	if req.Method != "POST" || req.Path != "/mcp" || req.RawQuery != "x=1" || req.Host != "api.example.com" || req.Port != 8443 || req.Scheme != "https" || req.Headers["x-request-id"] != "raw-id" {
		t.Fatalf("lost policy inputs: %+v", req)
	}
}

func TestHeaderValueRawPrecedence(t *testing.T) {
	if got := HeaderValue(&corev3.HeaderValue{RawValue: []byte("raw"), Value: "string"}); got != "raw" {
		t.Fatal(got)
	}
	if got := HeaderValue(nil); got != "" {
		t.Fatal(got)
	}
}
