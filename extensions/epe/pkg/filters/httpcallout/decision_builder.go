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

import "slices"

// DecisionBuilder constructs a decision for one invocation phase. Build validates
// the result using the same contract as EPE. Builders are not concurrency-safe.
type DecisionBuilder struct {
	phase   Phase
	action  *Action
	headers []HeaderMutation
	body    *string
	status  *int
	reason  string
}

// Continue starts a decision that modifies the current phase and continues.
func Continue(phase Phase) *DecisionBuilder {
	return &DecisionBuilder{phase: phase}
}

// Respond starts a local response in either phase, replacing the exchange.
func Respond(phase Phase, statusCode int) *DecisionBuilder {
	action := ActionRespond
	return &DecisionBuilder{phase: phase, action: &action, status: &statusCode}
}

// SetHeader replaces a header on the current phase or local response.
func (b *DecisionBuilder) SetHeader(name, value string) *DecisionBuilder {
	b.headers = append(b.headers, HeaderMutation{Operation: HeaderSet, Name: name, Value: &value})
	return b
}

// AppendHeader appends a value on the current phase or local response.
func (b *DecisionBuilder) AppendHeader(name, value string) *DecisionBuilder {
	b.headers = append(b.headers, HeaderMutation{Operation: HeaderAppend, Name: name, Value: &value})
	return b
}

// RemoveHeader removes a header from the current phase. Build rejects removals
// from a local response, which has no existing headers to remove.
func (b *DecisionBuilder) RemoveHeader(name string) *DecisionBuilder {
	b.headers = append(b.headers, HeaderMutation{Operation: HeaderRemove, Name: name})
	return b
}

// Body replaces the body; an empty string explicitly clears it.
func (b *DecisionBuilder) Body(body string) *DecisionBuilder {
	b.body = &body
	return b
}

// StatusCode sets the response status. Build rejects it on request-phase continue.
func (b *DecisionBuilder) StatusCode(statusCode int) *DecisionBuilder {
	b.status = &statusCode
	return b
}

// Reason sets the audit explanation for a local response. Build rejects a
// nonempty reason on a continue decision.
func (b *DecisionBuilder) Reason(reason string) *DecisionBuilder {
	b.reason = reason
	return b
}

// Build supplies the protocol version and validates the decision. Later builder
// calls do not modify a previously built decision.
func (b *DecisionBuilder) Build() (Decision, error) {
	d := Decision{Version: ProtocolVersion, Action: b.action, Reason: b.reason}
	if b.action != nil || b.phase == PhaseResponse || b.status != nil {
		if len(b.headers) > 0 || b.body != nil || b.status != nil {
			d.Response = &ResponseMutation{Headers: slices.Clone(b.headers), Body: b.body, StatusCode: b.status}
		}
	} else if len(b.headers) > 0 || b.body != nil {
		d.Request = &RequestMutation{Headers: slices.Clone(b.headers), Body: b.body}
	}
	if err := d.Validate(b.phase); err != nil {
		return Decision{}, err
	}
	return d, nil
}
