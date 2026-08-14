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
package httpcallout

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/http/httpguts"
)

// ProtocolVersion is the callout wire-contract version implemented by this
// package. It versions the wire format only and is independent of the EPE
// release version, which it currently happens to match: a release that does not
// change this contract must not bump it, because both Validate methods below
// compare it for equality and every deployed endpoint would break at once.
//
// Major.minor rather than a Kubernetes-style vNalphaN: the endpoint is an
// arbitrary HTTP service rather than a k8s API, so this follows the convention
// CloudEvents uses for specversion. Being pre-1.0 is the version's own notice
// that breaking changes are still expected.
const ProtocolVersion = "0.1"

// Phase identifies the side of the upstream exchange being intercepted.
type Phase string

const (
	// PhaseRequest runs before the request is sent upstream.
	PhaseRequest Phase = "request"
	// PhaseResponse runs after a complete upstream response is buffered.
	PhaseResponse Phase = "response"
)

// Invocation is the common request body sent to the configured callout endpoint.
type Invocation struct {
	Version  string        `json:"version"`
	Phase    Phase         `json:"phase"`
	Source   SourceContext `json:"source"`
	Policy   PolicyContext `json:"policy"`
	Request  *HTTPRequest  `json:"request"`
	Response *HTTPResponse `json:"response,omitempty"`
}

// SourceContext identifies the untrusted workload that originated the
// request. It intentionally has no credential or sandbox-token field.
type SourceContext struct {
	Namespace string            `json:"namespace,omitempty"`
	Pod       string            `json:"pod,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// PolicyContext identifies the policy unit that owns this invocation.
type PolicyContext struct {
	Scope   string `json:"scope"`
	Rule    string `json:"rule"`
	Ordinal int    `json:"ordinal"`
}

// HTTPRequest is the original request view delivered to each callout.
// Headers is omitted when request-header forwarding is disabled.
type HTTPRequest struct {
	// ID is the stable correlation ID extracted from the original request. It
	// remains available even when request-header forwarding hides
	// x-request-id. Empty means the original request carried no ID.
	ID          string            `json:"id"`
	Method      string            `json:"method"`
	Scheme      string            `json:"scheme"`
	Host        string            `json:"host"`
	Port        int32             `json:"port"`
	Path        string            `json:"path"`
	RawQuery    string            `json:"rawQuery"`
	ContentType string            `json:"contentType"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body"`
}

// HTTPResponse is the original upstream response view delivered during the
// response phase.
type HTTPResponse struct {
	StatusCode  int               `json:"statusCode"`
	ContentType string            `json:"contentType"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
}

// Validate checks the version, phase shape, and UTF-8 body contract.
func (i Invocation) Validate() error {
	if i.Version != ProtocolVersion {
		return fmt.Errorf("unsupported callout protocol version %q", i.Version)
	}
	if i.Phase != PhaseRequest && i.Phase != PhaseResponse {
		return fmt.Errorf("unknown callout phase %q", i.Phase)
	}
	if i.Request == nil {
		return fmt.Errorf("callout invocation request is nil")
	}
	if !utf8.ValidString(i.Request.Body) {
		return fmt.Errorf("callout request body is not valid UTF-8")
	}

	switch i.Phase {
	case PhaseRequest:
		if i.Response != nil {
			return fmt.Errorf("request-phase callout invocation contains a response")
		}
	case PhaseResponse:
		if i.Response == nil {
			return fmt.Errorf("response-phase callout invocation has no response")
		}
		if i.Response.Headers == nil {
			return fmt.Errorf("response-phase callout invocation has nil response headers")
		}
		if !utf8.ValidString(i.Response.Body) {
			return fmt.Errorf("callout response body is not valid UTF-8")
		}
	}
	return nil
}

// Action controls whether normal processing continues or the request is
// answered locally.
type Action string

const (
	// ActionContinue applies phase-appropriate mutations and continues.
	ActionContinue Action = "continue"
	// ActionRespond short-circuits a request with a local response.
	ActionRespond Action = "respond"
)

// HeaderOperation names one ordered header mutation.
type HeaderOperation string

const (
	// HeaderSet replaces all existing values.
	HeaderSet HeaderOperation = "set"
	// HeaderAppend adds one value after existing values.
	HeaderAppend HeaderOperation = "append"
	// HeaderRemove removes all values.
	HeaderRemove HeaderOperation = "remove"
)

// HeaderMutation is one ordered request or response header operation. Value
// is required for set and append, and forbidden for remove. A pointer keeps an
// explicit empty value distinct from an omitted value.
type HeaderMutation struct {
	Operation HeaderOperation `json:"operation"`
	Name      string          `json:"name"`
	Value     *string         `json:"value,omitempty"`
}

// RequestMutation contains the changes legal in the request phase.
type RequestMutation struct {
	Headers []HeaderMutation `json:"headers,omitempty"`
	Body    *string          `json:"body,omitempty"`
}

// ResponseMutation contains an upstream response change or a request-phase
// local response. StatusCode is optional for response mutation and required
// for a local response.
type ResponseMutation struct {
	StatusCode *int             `json:"statusCode,omitempty"`
	Headers    []HeaderMutation `json:"headers,omitempty"`
	Body       *string          `json:"body,omitempty"`
}

// Decision is the versioned callout result.
type Decision struct {
	Version  string            `json:"version"`
	Action   Action            `json:"action"`
	Request  *RequestMutation  `json:"request,omitempty"`
	Response *ResponseMutation `json:"response,omitempty"`
}

// Validate enforces the result shape allowed by phase.
func (d Decision) Validate(phase Phase) error {
	if phase != PhaseRequest && phase != PhaseResponse {
		return fmt.Errorf("unknown callout phase %q", phase)
	}
	if d.Version != ProtocolVersion {
		return fmt.Errorf("unsupported callout protocol version %q", d.Version)
	}
	if d.Action != ActionContinue && d.Action != ActionRespond {
		return fmt.Errorf("unknown callout action %q", d.Action)
	}

	if d.Action == ActionRespond {
		if phase == PhaseResponse {
			return fmt.Errorf("respond action is not valid in the response phase")
		}
		if d.Request != nil {
			return fmt.Errorf("respond action must not contain a request mutation")
		}
		if d.Response == nil {
			return fmt.Errorf("respond action has no response")
		}
		if d.Response.StatusCode == nil {
			return fmt.Errorf("respond action has no response status")
		}
		return validateResponseMutation(d.Response)
	}

	if phase == PhaseRequest {
		if d.Response != nil {
			return fmt.Errorf("request-phase continue action contains a response mutation")
		}
		return validateRequestMutation(d.Request)
	}
	if d.Request != nil {
		return fmt.Errorf("response-phase continue action contains a request mutation")
	}
	return validateResponseMutation(d.Response)
}

func validateRequestMutation(m *RequestMutation) error {
	if m == nil {
		return nil
	}
	if err := validateHeaderMutations(m.Headers); err != nil {
		return err
	}
	if m.Body != nil && !utf8.ValidString(*m.Body) {
		return fmt.Errorf("callout request body mutation is not valid UTF-8")
	}
	return nil
}

func validateResponseMutation(m *ResponseMutation) error {
	if m == nil {
		return nil
	}
	if m.StatusCode != nil && (*m.StatusCode < 200 || *m.StatusCode > 599) {
		return fmt.Errorf("callout response status %d is outside 200..599", *m.StatusCode)
	}
	if err := validateHeaderMutations(m.Headers); err != nil {
		return err
	}
	if m.Body != nil && !utf8.ValidString(*m.Body) {
		return fmt.Errorf("callout response body mutation is not valid UTF-8")
	}
	return nil
}

func validateHeaderMutations(mutations []HeaderMutation) error {
	for idx, mutation := range mutations {
		if !httpguts.ValidHeaderFieldName(mutation.Name) {
			return fmt.Errorf("header mutation %d has invalid header name %q", idx, mutation.Name)
		}
		if strings.EqualFold(mutation.Name, "host") {
			return fmt.Errorf("header mutation %d cannot modify host", idx)
		}
		switch mutation.Operation {
		case HeaderSet, HeaderAppend:
			if mutation.Value == nil {
				return fmt.Errorf("header mutation %d operation %q requires a value", idx, mutation.Operation)
			}
			if !httpguts.ValidHeaderFieldValue(*mutation.Value) {
				return fmt.Errorf("header mutation %d contains an invalid header value", idx)
			}
		case HeaderRemove:
			if mutation.Value != nil {
				return fmt.Errorf("header mutation %d remove operation must not contain a value", idx)
			}
		default:
			return fmt.Errorf("header mutation %d has unknown operation %q", idx, mutation.Operation)
		}
	}
	return nil
}
