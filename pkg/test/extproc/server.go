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
	"encoding/json"
	"io"
	"sort"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	servicev3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog/v2"
)

const defaultRequestBodyOverrideHeader = "x-asm-send-request-body"

var (
	defaultRequestHeaders  = map[string]string{"x-ext-proc-header": "hello-to-asm"}
	defaultResponseHeaders = map[string]string{"x-ext-proc-header": "hello-from-asm"}
)

// Config controls the mutations returned by the test external processor.
type Config struct {
	RequestHeadersToAdd       map[string]string
	ResponseHeadersToAdd      map[string]string
	RequestBodyOverrideHeader string
}

// ConfigFromEnvironment returns a fresh configuration for each server.
func ConfigFromEnvironment(getenv func(string) string) Config {
	requestHeaders := cloneMap(defaultRequestHeaders)
	responseHeaders := cloneMap(defaultResponseHeaders)
	mergeMap(requestHeaders, parseHeaderPairs(getenv("REQUEST_HEADERS_TO_ADD")))
	mergeMap(responseHeaders, parseHeaderPairs(getenv("RESPONSE_HEADERS_TO_ADD")))

	overrideHeader := strings.ToLower(strings.TrimSpace(getenv("REQUEST_BODY_OVERRIDE_HEADER")))
	if overrideHeader == "" {
		overrideHeader = defaultRequestBodyOverrideHeader
	}
	return Config{
		RequestHeadersToAdd:       requestHeaders,
		ResponseHeadersToAdd:      responseHeaders,
		RequestBodyOverrideHeader: overrideHeader,
	}
}

func parseHeaderPairs(value string) map[string]string {
	result := make(map[string]string)
	for index, pair := range strings.Split(value, ",") {
		key, headerValue, found := strings.Cut(strings.TrimSpace(pair), "=")
		if !found {
			if strings.TrimSpace(pair) != "" {
				klog.Warningf("ignoring invalid header pair at position %d", index)
			}
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			klog.Warningf("ignoring header pair with an empty key at position %d", index)
			continue
		}
		result[key] = strings.TrimSpace(headerValue)
	}
	return result
}

func cloneMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func mergeMap(target, additions map[string]string) {
	for key, value := range additions {
		target[key] = value
	}
}

// Server implements Envoy's external processing service for integration tests.
type Server struct {
	servicev3.UnimplementedExternalProcessorServer
	config Config
}

// NewServer creates an isolated external processor server.
func NewServer(config Config) *Server {
	overrideHeader := strings.ToLower(strings.TrimSpace(config.RequestBodyOverrideHeader))
	if overrideHeader == "" {
		overrideHeader = defaultRequestBodyOverrideHeader
	}
	return &Server{config: Config{
		RequestHeadersToAdd:       cloneMap(config.RequestHeadersToAdd),
		ResponseHeadersToAdd:      cloneMap(config.ResponseHeadersToAdd),
		RequestBodyOverrideHeader: overrideHeader,
	}}
}

// Process handles each phase of an Envoy HTTP stream.
func (s *Server) Process(stream servicev3.ExternalProcessor_ProcessServer) error {
	for {
		request, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Unknown, "cannot receive stream request: %v", err)
		}

		response := s.responseFor(request)
		if err := stream.Send(response); err != nil {
			return err
		}
	}
}

func (s *Server) responseFor(request *servicev3.ProcessingRequest) *servicev3.ProcessingResponse {
	switch value := request.Request.(type) {
	case *servicev3.ProcessingRequest_RequestHeaders:
		return s.handleRequestHeaders(value)
	case *servicev3.ProcessingRequest_RequestBody:
		return s.handleRequestBody(value)
	case *servicev3.ProcessingRequest_RequestTrailers:
		return &servicev3.ProcessingResponse{Response: &servicev3.ProcessingResponse_RequestTrailers{
			RequestTrailers: &servicev3.TrailersResponse{HeaderMutation: &servicev3.HeaderMutation{}},
		}}
	case *servicev3.ProcessingRequest_ResponseHeaders:
		return s.handleResponseHeaders(value)
	case *servicev3.ProcessingRequest_ResponseBody:
		return &servicev3.ProcessingResponse{Response: &servicev3.ProcessingResponse_ResponseBody{
			ResponseBody: &servicev3.BodyResponse{Response: &servicev3.CommonResponse{}},
		}}
	case *servicev3.ProcessingRequest_ResponseTrailers:
		return &servicev3.ProcessingResponse{Response: &servicev3.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &servicev3.TrailersResponse{HeaderMutation: &servicev3.HeaderMutation{}},
		}}
	default:
		return &servicev3.ProcessingResponse{}
	}
}

func (s *Server) handleRequestHeaders(request *servicev3.ProcessingRequest_RequestHeaders) *servicev3.ProcessingResponse {
	mutations := headerOptions(s.config.RequestHeadersToAdd)
	mutations = append(mutations, headerModifiers("request-header-modifier", request.RequestHeaders)...)

	var mode *extprocv3.ProcessingMode
	clearRouteCache := false
	for _, header := range request.RequestHeaders.GetHeaders().GetHeaders() {
		key := strings.ToLower(header.GetKey())
		value := string(header.GetRawValue())
		if value == "" {
			value = header.GetValue()
		}
		switch {
		case key == s.config.RequestBodyOverrideHeader:
			mode = &extprocv3.ProcessingMode{RequestBodyMode: bodyMode(value)}
		case key == "x-asm-clear-route-cache" && strings.EqualFold(value, "true"):
			clearRouteCache = true
		}
	}

	return &servicev3.ProcessingResponse{
		Response: &servicev3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &servicev3.HeadersResponse{Response: &servicev3.CommonResponse{
				HeaderMutation:  &servicev3.HeaderMutation{SetHeaders: mutations},
				ClearRouteCache: clearRouteCache,
			}},
		},
		ModeOverride: mode,
	}
}

func bodyMode(value string) extprocv3.ProcessingMode_BodySendMode {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "BUFFERED":
		return extprocv3.ProcessingMode_BUFFERED
	case "STREAMED":
		return extprocv3.ProcessingMode_STREAMED
	case "BUFFERED_PARTIAL":
		return extprocv3.ProcessingMode_BUFFERED_PARTIAL
	default:
		// This test server does not emit StreamedBodyResponse mutations, which
		// FULL_DUPLEX_STREAMED requires. Fall back to regular streaming instead.
		return extprocv3.ProcessingMode_STREAMED
	}
}

func (s *Server) handleRequestBody(_ *servicev3.ProcessingRequest_RequestBody) *servicev3.ProcessingResponse {
	return &servicev3.ProcessingResponse{Response: &servicev3.ProcessingResponse_RequestBody{
		RequestBody: &servicev3.BodyResponse{Response: &servicev3.CommonResponse{}},
	}}
}

func (s *Server) handleResponseHeaders(_ *servicev3.ProcessingRequest_ResponseHeaders) *servicev3.ProcessingResponse {
	return &servicev3.ProcessingResponse{Response: &servicev3.ProcessingResponse_ResponseHeaders{
		ResponseHeaders: &servicev3.HeadersResponse{Response: &servicev3.CommonResponse{
			HeaderMutation: &servicev3.HeaderMutation{SetHeaders: headerOptions(s.config.ResponseHeadersToAdd)},
		}},
	}}
}

func headerOptions(headers map[string]string) []*corev3.HeaderValueOption {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	result := make([]*corev3.HeaderValueOption, 0, len(keys))
	for _, key := range keys {
		result = append(result, &corev3.HeaderValueOption{Header: &corev3.HeaderValue{
			Key: key, RawValue: []byte(headers[key]),
		}})
	}
	return result
}

func headerModifiers(key string, headers *servicev3.HttpHeaders) []*corev3.HeaderValueOption {
	if headers == nil || headers.Headers == nil {
		return nil
	}
	for _, header := range headers.Headers.Headers {
		if !strings.EqualFold(header.GetKey(), key) {
			continue
		}
		value := string(header.GetRawValue())
		if value == "" {
			value = header.GetValue()
		}
		modifiers := make(map[string]string)
		if err := json.Unmarshal([]byte(value), &modifiers); err != nil {
			klog.Warningf("ignoring invalid %s value: %v", key, err)
			return nil
		}
		return headerOptions(modifiers)
	}
	return nil
}
