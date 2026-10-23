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
	if got := mutationMap(
		requestResponse.GetRequestHeaders().GetResponse().GetHeaderMutation().GetSetHeaders(),
	); got["x-request"] != "one" {
		t.Fatalf("request mutations = %#v", got)
	}

	responseResponse := server.responseFor(&servicev3.ProcessingRequest{
		Request: &servicev3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &servicev3.HttpHeaders{
			Headers: &corev3.HeaderMap{},
		}},
	})
	if got := mutationMap(
		responseResponse.GetResponseHeaders().GetResponse().GetHeaderMutation().GetSetHeaders(),
	); got["x-response"] != "two" {
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

func TestChainRequestsBodyOnlyWhenSelected(t *testing.T) {
	p := processor{config: processorConfig{chainName: "a"}}
	headers := &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: "x-chain-request", RawValue: []byte("epe")}}}
	request := &servicev3.ProcessingRequest{
		Request: &servicev3.ProcessingRequest_RequestHeaders{RequestHeaders: &servicev3.HttpHeaders{Headers: headers}},
	}
	response := p.responseFor(request)
	if response.ModeOverride != nil {
		t.Fatal("unsolicited body subscription")
	}
	if got := mutationMap(response.GetRequestHeaders().GetResponse().GetHeaderMutation().GetSetHeaders())["x-chain-request"]; got != "epe,a" {
		t.Fatalf("trace %q", got)
	}
	headers.Headers = append(headers.Headers, &corev3.HeaderValue{Key: "x-extproc-body", RawValue: []byte("a")})
	if p.responseFor(request).ModeOverride == nil {
		t.Fatal("missing body subscription")
	}
	body := p.responseFor(
		&servicev3.ProcessingRequest{
			Request: &servicev3.ProcessingRequest_RequestBody{
				RequestBody: &servicev3.HttpBody{Body: []byte("payload")},
			},
		},
	)
	if got := mutationMap(body.GetRequestBody().GetResponse().GetHeaderMutation().GetSetHeaders())["x-chain-body-a"]; got != "payload" {
		t.Fatalf("body %q", got)
	}
	response = p.responseFor(
		&servicev3.ProcessingRequest{
			Request: &servicev3.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &servicev3.HttpHeaders{
					Headers: &corev3.HeaderMap{
						Headers: []*corev3.HeaderValue{{Key: "x-chain-response", RawValue: []byte(",b")}},
					},
				},
			},
		},
	)
	mutations := mutationMap(response.GetResponseHeaders().GetResponse().GetHeaderMutation().GetSetHeaders())
	if mutations["x-chain-response"] != ",b,a" || mutations["x-chain-body-count-a"] != "1" {
		t.Fatalf("response %v", mutations)
	}
}
