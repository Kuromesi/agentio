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

package extproc

import (
	"context"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extpb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

func TestStringResponseStatusAndRequestID(t *testing.T) {
	server, state, _ := responseHeadersState(&responseHeadersProbe{})
	_, err := server.HandleResponseHeaders(context.Background(), &extpb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: ":status", Value: "429"}, {Key: "retry-after", Value: "3"},
	}}}, state)
	if err != nil {
		t.Fatal(err)
	}
	if state.stream.Response.Status != 429 || state.stream.Response.Headers["retry-after"] != "3" {
		t.Fatalf("lost response inputs: %+v", state.stream.Response)
	}
	headers := &extpb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: "X-Request-Id", Value: "agentgateway-id"}}}}
	if got := extractRequestID(headers); got != "agentgateway-id" {
		t.Fatalf("request ID = %q", got)
	}
}
