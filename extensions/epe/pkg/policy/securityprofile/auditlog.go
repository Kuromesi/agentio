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

// auditlog.go is the policy adapter's per-stream StreamLogger: it turns the
// units resolved for one stream into audit.Events once the stream's outcome is
// final. The resolver hands it to the ext_proc adapter, which invokes it
// without knowing what it holds — so the core logger list stays
// policy-ignorant while the attribution stays typed.

package securityprofile

import (
	"context"

	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/extensions/epe/pkg/audit"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/httpreq"
)

// streamLogger evaluates one stream's matched units against their audit
// entries at stream end and enqueues the events that fire. One instance is
// built per resolution, closing over that resolution's units.
type streamLogger struct {
	sink  audit.Sink
	units []unit
}

var _ filter.StreamLogger = (*streamLogger)(nil)

// newStreamLogger builds the per-stream logger for one resolution.
func newStreamLogger(sink audit.Sink, units []unit) *streamLogger {
	return &streamLogger{sink: sink, units: units}
}

// Log implements filter.StreamLogger.
func (l *streamLogger) Log(_ context.Context, st *filter.Stream, info *filter.StreamInfo) {
	result := info.Disposition.String()
	for i := range l.units {
		u := &l.units[i]
		if !u.HasAudits {
			continue
		}
		entries := resolveEntries(u)
		if len(entries) == 0 {
			continue
		}
		scope := buildScope(u, st, result)
		for _, ca := range entries {
			fire, err := audit.EvalWhen(ca.When, &scope)
			if err != nil {
				audit.EvalDroppedTotal.WithLabelValues("when_eval").Inc()
				continue
			}
			if !fire {
				continue
			}
			l.sink.Enqueue(audit.Event{
				ProfileNN:  profileNN(u.Profile),
				RuleName:   u.Rule.Name,
				ActionName: ca.Name,
				Audit:      ca,
				Scope:      &scope,
			})
		}
	}
}

// resolveEntries applies the override semantics: rule-level audits replace
// the profile-level list when present.
func resolveEntries(u *unit) []*audit.Audit {
	if len(u.Rule.Audits) > 0 {
		return u.Rule.Audits
	}
	return u.Profile.Audits
}

func profileNN(p *Profile) types.NamespacedName {
	if p == nil {
		return types.NamespacedName{}
	}
	return types.NamespacedName{Namespace: p.Meta.Namespace, Name: p.Meta.Name}
}

// buildScope assembles the CEL/template evaluation scope for one unit from
// its immutable per-unit Scope, the stream, and the final result.
func buildScope(u *unit, st *filter.Stream, result string) audit.Scope {
	s := audit.Scope{
		Result:   result,
		Matched:  buildMatch(u, &st.Request),
		Response: audit.Response{Status: st.Response.Status},
	}
	if u.Scope != nil {
		s.Scope = *u.Scope
	}
	return s
}

// buildMatch reports the RuleMatch clause that fired, populated only with
// the dimensions that clause actually constrained — reconstructed from the
// MatchIndex precomputed at unit resolution.
func buildMatch(u *unit, req *httpreq.HTTPRequest) audit.Match {
	m := audit.Match{Host: req.Host}
	if u.MatchIndex < 0 || u.MatchIndex >= len(u.Rule.Matches) {
		return m
	}
	rm := &u.Rule.Matches[u.MatchIndex]
	if len(rm.Methods) > 0 {
		m.Method = req.Method
	}
	if len(rm.Paths) > 0 {
		m.Path = req.Path
	}
	if len(rm.Ports) > 0 {
		m.Port = req.Port
	}
	if len(rm.Headers) > 0 {
		m.Headers = make(map[string]string, len(rm.Headers))
		for _, h := range rm.Headers {
			m.Headers[h.Name] = req.Headers[h.Name]
		}
	}
	if len(rm.QueryParams) > 0 {
		m.QueryParams = make(map[string]string, len(rm.QueryParams))
		for _, q := range rm.QueryParams {
			if vals, ok := req.Query[q.Name]; ok && len(vals) > 0 {
				m.QueryParams[q.Name] = vals[0]
			}
		}
	}
	return m
}
