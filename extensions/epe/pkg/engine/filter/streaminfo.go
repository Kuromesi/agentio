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

// UnitAction is one filter's action on one policy unit.
type UnitAction struct {
	Filter string
	Kind   UnitActionKind
}

// UnitRecord is one matched policy unit and what each filter did to it.
type UnitRecord struct {
	ID            UnitID
	FilterActions []UnitAction
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

// UnitActionKind names what a filter did to one policy unit, for audit. It is
// deliberately not ActionKind, which names what a filter *decided*
// (action.go:20): this vocabulary is a projection of that one onto what an
// operator can see, and the two differ — error-open has no Action counterpart,
// and mutate is inferred from pending mutations rather than from any kind.
//
// It is a distinct type so a kind outside the vocabulary below cannot be
// recorded by accident: an unconverted string literal does not compile.
type UnitActionKind string

// The unit action kinds. They live here rather than in the engine because both
// ends need them — the engine records them, and the accesslog reader matches on
// them to decide which are audit-visible actions and which only mark a filter
// as skipped.
const (
	ActionBlock     UnitActionKind = "block"
	ActionBypass    UnitActionKind = "bypass"
	ActionMutate    UnitActionKind = "mutate"
	ActionNeedBody  UnitActionKind = "need-body"
	ActionErrorOpen UnitActionKind = "error-open"
)

// RecordUnitAction appends one action to the unit's record, creating it on first
// touch. A nil *StreamInfo is a no-op: a Stream may carry no info (filters and
// tests build one without), and every call site would otherwise restate that
// guard.
func (i *StreamInfo) RecordUnitAction(id UnitID, filterName string, kind UnitActionKind) {
	if i == nil {
		return
	}
	action := UnitAction{Filter: filterName, Kind: kind}
	for idx := range i.Matched {
		if i.Matched[idx].ID == id {
			i.Matched[idx].FilterActions = append(i.Matched[idx].FilterActions, action)
			return
		}
	}
	i.Matched = append(i.Matched, UnitRecord{ID: id, FilterActions: []UnitAction{action}})
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
