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
package filter

import (
	"context"
	"time"
)

// Disposition is both the engine's per-walk control-flow verdict and the
// vocabulary the audit outcome is rendered in. Filters never name it: the
// engine derives the walk's own value from which Action constructor won, and
// extproc derives the stream's audit value from what it actually sent Envoy.
type Disposition uint8

const (
	DispositionPassthrough Disposition = iota
	DispositionMutated
	DispositionBlocked
	DispositionBypassed
	DispositionError
)

// String returns the audit-visible outcome string.
func (d Disposition) String() string {
	switch d {
	case DispositionMutated:
		return "mutated"
	case DispositionBlocked:
		return "blocked"
	case DispositionBypassed:
		return "bypassed"
	case DispositionError:
		return "error"
	default:
		return "passthrough"
	}
}

// UnitRecord is one matched policy unit and what each filter did to it.
type UnitRecord struct {
	ID UnitID
	// FilterActions entries are "<filter>:<kind>" strings, e.g.
	// "block:block", "mcpacl:need-body".
	FilterActions []string
}

// FilterRecord is one filter invocation as the framework observed it.
type FilterRecord struct {
	Filter   string
	Phase    string
	Outcome  string
	Duration time.Duration
	// Err carries the filter's error even when a fail-open policy
	// swallowed it.
	Err error
}

// StreamInfo accumulates what happened to one stream. It holds only what
// filters cannot provide themselves; Peer/Request/Response live on Stream.
type StreamInfo struct {
	Matched []UnitRecord
	Filters []FilterRecord
	// Outcome is written exactly once, at stream end, by the ext_proc layer —
	// derived from the responses it actually sent, the stream's error, and
	// len(Matched). The engine deliberately does not accumulate it: an outcome
	// tracked as filters decide would keep claiming enforcement that the
	// translation layer dropped.
	Outcome Disposition
	// Error records the failure that resolved the stream, when one did.
	Error string
}

// NewStreamInfo builds an empty info for one stream.
func NewStreamInfo() *StreamInfo {
	return &StreamInfo{}
}

// The unit action kinds RecordUnitAction encodes into its "<filter>:<kind>"
// wire format. They live here rather than in the engine because both ends of
// that format need them: the engine writes them, and audit sinks match on them
// when reading a record back.
const (
	ActionBlock     = "block"
	ActionBypass    = "bypass"
	ActionMutate    = "mutate"
	ActionNeedBody  = "need-body"
	ActionErrorOpen = "error-open"
)

// RecordUnitAction appends one "<filter>:<kind>" action to the unit's
// record, creating it on first touch. kind should be one of the ActionXxx
// constants. A nil *StreamInfo is a no-op: a Stream may carry no info (filters
// and tests build one without), and every call site would otherwise restate
// that guard.
func (i *StreamInfo) RecordUnitAction(id UnitID, filterName, kind string) {
	if i == nil {
		return
	}
	action := filterName + ":" + kind
	for idx := range i.Matched {
		if i.Matched[idx].ID == id {
			i.Matched[idx].FilterActions = append(i.Matched[idx].FilterActions, action)
			return
		}
	}
	i.Matched = append(i.Matched, UnitRecord{ID: id, FilterActions: []string{action}})
}

// RecordFilter appends one filter invocation record. A nil *StreamInfo is a
// no-op, as for RecordUnitAction.
func (i *StreamInfo) RecordFilter(rec FilterRecord) {
	if i == nil {
		return
	}
	i.Filters = append(i.Filters, rec)
}

// StreamLogger observes the completed stream. It is invoked exactly once
// per stream, at true stream end — including abnormal termination (ctx
// cancellation, Envoy reset, budget exhaustion). Implementations must not
// block.
type StreamLogger interface {
	Log(ctx context.Context, st *Stream, info *StreamInfo)
}
