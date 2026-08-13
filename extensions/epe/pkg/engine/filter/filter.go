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

// Package filter defines the core contract of the EPE request
// framework: the supported-phase Filter interface, the opaque Action type,
// plain Mutation values, and the unit identity types the ordered engine
// dispatches on. Nothing in this package may import ext_proc protos or the
// policy API; adapters translate at the edges.
package filter

import "context"

// Phase is a bitmask of the dispatch points the engine supports.
type Phase uint8

const (
	PhaseRequestHeaders Phase = 1 << iota
	PhaseRequestBody
	PhaseResponseHeaders
)

// DispatchedPhases is the set of phases the engine invokes. Build
// rejects descriptors declaring anything outside it, so a filter can never
// be silently inert. Engine dispatch and this mask must be widened
// together.
//
// Declaring PhaseResponseHeaders only grants the capability to run there. A
// stream reaches that phase solely for the (rule, filter) pairs whose config
// subscribed via Descriptor.SubscribesOf. Subscription is config-derived rather
// than returned from an action because Envoy confines mode_override to
// header-phase replies and response_header_mode is only useful on the
// request-headers one, while the ordered walk may suspend waiting for a request
// body — so a subscription raised by a filter that runs after the pause would
// arrive after that reply was already sent.
const DispatchedPhases = PhaseRequestHeaders | PhaseRequestBody | PhaseResponseHeaders

// Filter is the engine's three-phase contract. Capability is expressed by
// overriding methods over an embedded PassThrough — never by type assertion.
type Filter interface {
	OnRequestHeaders(context.Context, *Stream) (Action, error)
	OnRequestBody(context.Context, *Stream, Body) (Action, error)
	OnResponseHeaders(context.Context, *Stream) (Action, error)
}

// PassThrough continues on every phase. Embed it so a filter only overrides
// the phases it cares about.
type PassThrough struct{}

func (PassThrough) OnRequestHeaders(context.Context, *Stream) (Action, error) {
	return Continue(), nil
}

func (PassThrough) OnRequestBody(context.Context, *Stream, Body) (Action, error) {
	return Continue(), nil
}

func (PassThrough) OnResponseHeaders(context.Context, *Stream) (Action, error) {
	return Continue(), nil
}

var _ Filter = PassThrough{}
