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
	PhaseResponseBody
)

// DispatchedPhases is the set of phases the engine can invoke. Build rejects
// descriptors that declare unsupported phases.
//
// PhaseResponseHeaders grants capability; each config must also subscribe
// through Descriptor.SubscribesOf before its pair is dispatched.
const DispatchedPhases = PhaseRequestHeaders | PhaseRequestBody | PhaseResponseHeaders | PhaseResponseBody

// Filter is the engine's four-phase contract. Capability is expressed by
// overriding methods over an embedded PassThrough — never by type assertion.
type Filter interface {
	OnRequestHeaders(context.Context, *Stream) (Action, error)
	OnRequestBody(context.Context, *Stream, Body) (Action, error)
	OnResponseHeaders(context.Context, *Stream) (Action, error)
	OnResponseBody(context.Context, *Stream, Body) (Action, error)
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

func (PassThrough) OnResponseBody(context.Context, *Stream, Body) (Action, error) {
	return Continue(), nil
}

var _ Filter = PassThrough{}
