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

package main

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	servicev3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

func TestConfigFromEnvironmentNormalizesHeaderMutations(t *testing.T) {
	environment := map[string]string{
		"REQUEST_HEADERS_TO_ADD":  " X-Request = one,invalid,=empty,x-request=two ",
		"RESPONSE_HEADERS_TO_ADD": "X-Response=three",
	}
	config := configFromEnvironment(func(name string) string { return environment[name] })
	if got := config.requestHeaders["x-request"]; got != "two" {
		t.Fatalf("request header = %q, want two", got)
	}
	if len(config.requestHeaders) != 1 {
		t.Fatalf("request headers = %#v, want one normalized header", config.requestHeaders)
	}
	if got := config.responseHeaders["x-response"]; got != "three" {
		t.Fatalf("response header = %q, want three", got)
	}
}

func TestResponseForMutatesRequestAndResponseHeaders(t *testing.T) {
	server := processor{config: processorConfig{
		requestHeaders:  map[string]string{"x-request": "one"},
		responseHeaders: map[string]string{"x-response": "two"},
	}}
	requestResponse := server.responseFor(&servicev3.ProcessingRequest{
		Request: &servicev3.ProcessingRequest_RequestHeaders{RequestHeaders: &servicev3.HttpHeaders{
			Headers: &corev3.HeaderMap{},
		}},
	})
	if got := mutationMap(requestResponse.GetRequestHeaders().GetResponse().GetHeaderMutation().GetSetHeaders()); got["x-request"] != "one" {
		t.Fatalf("request mutations = %#v", got)
	}

	responseResponse := server.responseFor(&servicev3.ProcessingRequest{
		Request: &servicev3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &servicev3.HttpHeaders{
			Headers: &corev3.HeaderMap{},
		}},
	})
	if got := mutationMap(responseResponse.GetResponseHeaders().GetResponse().GetHeaderMutation().GetSetHeaders()); got["x-response"] != "two" {
		t.Fatalf("response mutations = %#v", got)
	}
}

func mutationMap(options []*corev3.HeaderValueOption) map[string]string {
	result := make(map[string]string, len(options))
	for _, option := range options {
		result[option.GetHeader().GetKey()] = string(option.GetHeader().GetRawValue())
	}
	return result
}
