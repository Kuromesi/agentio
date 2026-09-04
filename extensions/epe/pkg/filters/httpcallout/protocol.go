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
	"unicode/utf8"

	"golang.org/x/net/http/httpguts"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
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
	// Body is a pointer because there are three states, not two: nil means the
	// phase's config did not collect a body, a pointer to "" means it did and the
	// message had none, and anything else is the body. A scanner must never read
	// "never saw it" as "saw it and it was empty". The response phase always
	// sends nil here, which is what frees EPE from retaining a request body.
	Body *string `json:"body,omitempty"`
}

// HTTPResponse is the original upstream response view delivered during the
// response phase. Headers is omitted when response-header forwarding is disabled,
// matching HTTPRequest: an absent map and an upstream that sent no headers are
// deliberately indistinguishable, because under none the callout learns nothing
// either way and under all an absent map means an absent header.
type HTTPResponse struct {
	StatusCode  int               `json:"statusCode"`
	ContentType string            `json:"contentType"`
	Headers     map[string]string `json:"headers,omitempty"`
	// Body is a pointer for the same three-state reason as HTTPRequest.Body: a
	// plain string cannot express "not collected" apart from "collected and
	// empty".
	Body *string `json:"body,omitempty"`
}

// Validate checks the version, phase shape, and UTF-8 body contract. It holds
// only what is unconditionally true: body collection is opt-in per phase, so
// whether a body should be present is the config's business, not this contract's.
// What survives is that the response phase carries a response and nothing but the
// request correlation view, and that any body present is valid UTF-8.
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

	switch i.Phase {
	case PhaseRequest:
		if i.Response != nil {
			return fmt.Errorf("request-phase callout invocation contains a response")
		}
		if i.Request.Body != nil && !utf8.ValidString(*i.Request.Body) {
			return fmt.Errorf("callout request body is not valid UTF-8")
		}
	case PhaseResponse:
		if i.Response == nil {
			return fmt.Errorf("response-phase callout invocation has no response")
		}
		// The response-phase request object is a correlation view. Enforcing its
		// emptiness here is what lets EPE drop the request body at the end of
		// the request direction instead of retaining it across the exchange.
		if i.Request.Body != nil {
			return fmt.Errorf("response-phase callout invocation contains a request body")
		}
		if i.Request.Headers != nil {
			return fmt.Errorf("response-phase callout invocation contains request headers")
		}
		if i.Response.Body != nil && !utf8.ValidString(*i.Response.Body) {
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
	// ActionRespond terminates the exchange with a local response instead of
	// the message in flight: in the request phase the upstream is never
	// called, in the response phase the buffered upstream response is
	// discarded.
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
	// Version is the only required field. It is not an echo but the contract
	// guard: if an absent version meant "assume current", an endpoint written
	// against 0.1 would keep working silently after 0.2 changes a meaning.
	Version string `json:"version"`
	// Action is optional: an absent action means continue. The endpoint is a
	// third-party service, and its ergonomics outrank strictness we can afford
	// internally — an observing callout should not have to restate the only
	// answer it ever gives. Omission can only ever reach the permissive outcome:
	// respond still requires an explicit action plus a status, so nothing is
	// denied, mutated, or terminated by silence.
	Action *Action `json:"action,omitempty"`
	// Reason is an optional audit note, legal only with respond. It feeds
	// RESPONSE_CODE_DETAILS, which lands in one access log line per blocked
	// request; reasonMaxBytes bounds it because nothing downstream does.
	Reason   string            `json:"reason,omitempty"`
	Request  *RequestMutation  `json:"request,omitempty"`
	Response *ResponseMutation `json:"response,omitempty"`
}

// reasonMaxBytes caps Reason. Envoy imposes no limit of its own on
// ImmediateResponse.details.
const reasonMaxBytes = 256

// action resolves the optional field. Every reader must go through this rather
// than dereferencing, so the absent-means-continue rule lives in one place.
func (d Decision) action() Action {
	if d.Action == nil {
		return ActionContinue
	}
	return *d.Action
}

// Validate enforces the result shape allowed by the phase being answered. The
// phase comes from the caller because a decision no longer restates it; the
// unknown-phase guard stays as cheap insurance for a caller that forgot.
//
// The normalized header names ValidateHeaderName returns are discarded here: a
// value receiver cannot rewrite the decision, so case folding happens where
// filter.HeaderOp values are built. Rejection is unaffected — every check runs
// against the lower-cased form.
func (d Decision) Validate(phase Phase) error {
	if phase != PhaseRequest && phase != PhaseResponse {
		return fmt.Errorf("unknown callout phase %q", phase)
	}
	if d.Version != ProtocolVersion {
		return fmt.Errorf("unsupported callout protocol version %q", d.Version)
	}
	action := d.action()
	if action != ActionContinue && action != ActionRespond {
		return fmt.Errorf("unknown callout action %q", action)
	}

	if action == ActionRespond {
		if d.Request != nil {
			return fmt.Errorf("respond action must not contain a request mutation")
		}
		if d.Response == nil {
			return fmt.Errorf("respond action has no response")
		}
		if d.Response.StatusCode == nil {
			return fmt.Errorf("respond action has no response status")
		}
		if err := validateReason(d.Reason); err != nil {
			return err
		}
		return validateLocalResponse(d.Response)
	}

	if d.Reason != "" {
		return fmt.Errorf("continue action must not contain a reason")
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

// validateReason enforces what the value can survive on the way to
// RESPONSE_CODE_DETAILS. Invalid UTF-8 fails the proto3 marshaller and would
// destroy the whole ProcessingResponse rather than this one field, so it is a
// harder requirement than the body checks. Control bytes are checked byte-wise
// because every byte of a valid multi-byte UTF-8 sequence is 0x80 or above.
func validateReason(reason string) error {
	if reason == "" {
		return nil
	}
	if len(reason) > reasonMaxBytes {
		return fmt.Errorf("callout reason is longer than %d bytes", reasonMaxBytes)
	}
	if !utf8.ValidString(reason) {
		return fmt.Errorf("callout reason is not valid UTF-8")
	}
	for idx := 0; idx < len(reason); idx++ {
		if reason[idx] < 0x20 || reason[idx] == 0x7f {
			return fmt.Errorf("callout reason contains a control byte at offset %d", idx)
		}
	}
	return nil
}

func validateRequestMutation(m *RequestMutation) error {
	if m == nil {
		return nil
	}
	if err := validateHeaderMutations(m.Headers, removalApplies); err != nil {
		return err
	}
	if m.Body != nil && !utf8.ValidString(*m.Body) {
		return fmt.Errorf("callout request body mutation is not valid UTF-8")
	}
	return nil
}

// validateResponseMutation checks a change to the upstream response, which is a
// real message: every header operation reaches it.
func validateResponseMutation(m *ResponseMutation) error {
	return validateResponse(m, removalApplies)
}

// validateLocalResponse checks the response a respond action synthesizes. Envoy
// applies these mutations to a local reply that holds only :status — itself
// unremovable — and adds content-type and content-length afterwards, so a
// removal can never reach a header. Rejecting beats accepting and ignoring.
func validateLocalResponse(m *ResponseMutation) error {
	return validateResponse(m, removalIgnored)
}

func validateResponse(m *ResponseMutation, removal removalMode) error {
	if m == nil {
		return nil
	}
	if m.StatusCode != nil && (*m.StatusCode < 200 || *m.StatusCode > 599) {
		return fmt.Errorf("callout response status %d is outside 200..599", *m.StatusCode)
	}
	if err := validateHeaderMutations(m.Headers, removal); err != nil {
		return err
	}
	if m.Body != nil && !utf8.ValidString(*m.Body) {
		return fmt.Errorf("callout response body mutation is not valid UTF-8")
	}
	return nil
}

// opKinds maps wire operations to the engine kinds the shared name policy is
// expressed over. The append/Add asymmetry stays: one is a wire contract, the
// other is internal.
var opKinds = map[HeaderOperation]filter.HeaderOpKind{
	HeaderSet:    filter.HeaderSet,
	HeaderAppend: filter.HeaderAdd,
	HeaderRemove: filter.HeaderRemove,
}

// removalMode says whether a header removal in this position reaches a message
// that already has headers. Only a local response answers no.
type removalMode bool

const (
	removalApplies removalMode = true
	removalIgnored removalMode = false
)

func validateHeaderMutations(mutations []HeaderMutation, removal removalMode) error {
	for idx, mutation := range mutations {
		kind, known := opKinds[mutation.Operation]
		if !known {
			return fmt.Errorf("header mutation %d has unknown operation %q", idx, mutation.Operation)
		}
		// A remote service gets no more mutation power than a local policy
		// author: the same name policy headermutation enforces applies here.
		if _, err := filter.ValidateHeaderName(kind, mutation.Name); err != nil {
			return fmt.Errorf("header mutation %d: %w", idx, err)
		}
		if mutation.Operation == HeaderRemove {
			if removal == removalIgnored {
				return fmt.Errorf("header mutation %d cannot remove a header from a local response", idx)
			}
			if mutation.Value != nil {
				return fmt.Errorf("header mutation %d remove operation must not contain a value", idx)
			}
			continue
		}
		if mutation.Value == nil {
			return fmt.Errorf("header mutation %d operation %q requires a value", idx, mutation.Operation)
		}
		if !httpguts.ValidHeaderFieldValue(*mutation.Value) {
			return fmt.Errorf("header mutation %d contains an invalid header value", idx)
		}
	}
	return nil
}
