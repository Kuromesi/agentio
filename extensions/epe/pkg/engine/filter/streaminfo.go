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

// Disposition is derived by the engine from which Action constructor won;
// filters never name it.
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

// PromoteDisposition keeps the higher-precedence disposition. The order —
// error > bypassed > blocked > mutated > passthrough — is audit-visible
// behavior, not bookkeeping.
func PromoteDisposition(a, b Disposition) Disposition {
	if dispositionRank(b) >= dispositionRank(a) {
		return b
	}
	return a
}

func dispositionRank(d Disposition) int {
	switch d {
	case DispositionError:
		return 5
	case DispositionBypassed:
		return 4
	case DispositionBlocked:
		return 3
	case DispositionMutated:
		return 2
	default:
		return 1
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
	Matched     []UnitRecord
	Filters     []FilterRecord
	Disposition Disposition
	// BytesForwardedBeforeVerdict is "how much leaked before the verdict"
	// in observable form; under BUFFERED it stays 0.
	BytesForwardedBeforeVerdict int
	// Error records the failure that resolved the stream, when one did.
	Error string
}

// NewStreamInfo builds an empty info for one stream.
func NewStreamInfo() *StreamInfo {
	return &StreamInfo{}
}

// RecordUnitAction appends one "<filter>:<kind>" action to the unit's
// record, creating it on first touch. A nil *StreamInfo is a no-op: a Stream
// may carry no info (filters and tests build one without), and every call
// site would otherwise restate that guard.
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

// Promote raises the disposition, never lowers it. A nil *StreamInfo is a
// no-op, as for RecordUnitAction.
func (i *StreamInfo) Promote(d Disposition) {
	if i == nil {
		return
	}
	i.Disposition = PromoteDisposition(i.Disposition, d)
}

// StreamLogger observes the completed stream. It is invoked exactly once
// per stream, at true stream end — including abnormal termination (ctx
// cancellation, Envoy reset, budget exhaustion). Implementations must not
// block.
type StreamLogger interface {
	Log(ctx context.Context, st *Stream, info *StreamInfo)
}
