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
package accesslog

import (
	"context"
	"strings"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// StreamLog adapts a Logger to the StreamLogger contract: it reduces the
// finished stream's StreamInfo to one accesslog Entry and submits it.
type StreamLog struct {
	l Logger
}

// NewStreamLog wraps l; nil falls back to the no-op logger.
func NewStreamLog(l Logger) *StreamLog {
	if l == nil {
		l = Nop()
	}
	return &StreamLog{l: l}
}

var _ filter.StreamLogger = (*StreamLog)(nil)

// committedKinds are the unit actions that count as "the filter acted".
var committedKinds = map[string]bool{
	"block":  true,
	"bypass": true,
	"mutate": true,
}

// Log implements filter.StreamLogger.
func (s *StreamLog) Log(_ context.Context, st *filter.Stream, info *filter.StreamInfo) {
	entry := Entry{
		RequestID: st.RequestID,
		Pod:       st.Peer.Pod,
		Method:    st.Request.Method,
		Host:      st.Request.Host,
		Path:      st.Request.Path,
		Units:     len(info.Matched),
		Outcome:   info.Disposition.String(),
		Skipped:   map[string]int{},
		Error:     info.Error,
	}

	// A filter that asked for the body counts as skipped unless a later
	// action committed for the same unit.
	type pendingKey struct {
		unit   filter.UnitID
		filter string
	}
	pending := map[pendingKey]bool{}

	for _, u := range info.Matched {
		for _, action := range u.FilterActions {
			name, kind, ok := strings.Cut(action, ":")
			if !ok {
				continue
			}
			switch {
			case committedKinds[kind]:
				entry.Actions = append(entry.Actions, name+":"+u.ID.String())
				delete(pending, pendingKey{unit: u.ID, filter: name})
			case kind == "need-body":
				pending[pendingKey{unit: u.ID, filter: name}] = true
			case kind == "error-open":
				entry.Skipped[name]++
			}
		}
	}
	for k := range pending {
		entry.Skipped[k.filter]++
	}

	s.l.Submit(entry)
}
