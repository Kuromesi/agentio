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
package securityprofile

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// A matched resolution must carry the per-stream audit logger. Nothing else
// wires it: the logger left the static logger list when the units stopped
// travelling through StreamInfo.Metadata, so if the resolver forgets it, audit
// events silently never fire and only the end-to-end delivery tests notice.
func TestResolverSuppliesStreamLoggerWhenPolicyMatches(t *testing.T) {
	regs := claimAll(t, nil)

	p := compile(t, regs, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	resolve := NewResolver(benchStore{profiles: []*Profile{p}}, regs, nil)

	res, err := resolve(context.Background(), inputs.Pod{}, testRequest("example.com"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.Units) != 1 {
		t.Fatalf("units = %d, want 1", len(res.Units))
	}
	if res.StreamLogger == nil {
		t.Fatal("resolution carries no stream logger; audit events would never fire")
	}
}

// A projection failure fails the request closed, but the profile still
// matched and its audit entries still describe a stream worth recording —
// with result="error", which is exactly the case an operator writes an audit
// rule for. Returning the logger alongside the error keeps this symmetric
// with an engine-eval failure, which the adapter already audits.
func TestResolverSuppliesStreamLoggerWhenProjectionFails(t *testing.T) {
	boom := errors.New("malformed")
	regs, err := filter.Build(filter.Define(filter.Descriptor[string]{
		Name:   block.FilterName,
		Phases: filter.PhaseRequestHeaders,
		New:    func(filter.RuleConfig[string]) filter.Filter { return nopFilter{} },
	}, func(json.RawMessage) (string, error) { return "", boom }))
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	p := compile(t, regs, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	resolve := NewResolver(benchStore{profiles: []*Profile{p}}, regs, nil)

	res, err := resolve(context.Background(), inputs.Pod{}, testRequest("example.com"))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the wrapped projection error", err)
	}
	if len(res.Units) != 0 {
		t.Errorf("units = %d, want 0: a failed projection must not be evaluated", len(res.Units))
	}
	if res.StreamLogger == nil {
		t.Fatal("resolution carries no stream logger; a resolve failure would never be audited")
	}
}

// The zero resolutions must stay zero: a nil logger is how the adapter knows
// there is nothing to log, and a non-nil logger over zero units would emit an
// empty audit pass for every unmatched request.
func TestResolverOmitsStreamLoggerWhenNothingMatches(t *testing.T) {
	regs := claimAll(t, nil)

	for _, tc := range []struct {
		name  string
		store benchStore
	}{
		{name: "no profiles match the pod", store: benchStore{}},
		{
			name:  "profile matches but no rule fires",
			store: benchStore{profiles: []*Profile{compile(t, regs, "p", "ns", "1", nil)}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolve := NewResolver(tc.store, regs, nil)
			res, err := resolve(context.Background(), inputs.Pod{}, testRequest("example.com"))
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if len(res.Units) != 0 {
				t.Fatalf("units = %d, want 0", len(res.Units))
			}
			if res.StreamLogger != nil {
				t.Fatalf("stream logger = %T, want nil when no policy applies", res.StreamLogger)
			}
		})
	}
}

// A nil sink must not reach the logger: NewResolver substitutes the no-op sink
// so callers that do not audit need no branch, and Enqueue never runs against
// a nil interface.
func TestResolverNilSinkBecomesNoop(t *testing.T) {
	regs := claimAll(t, nil)

	p := compile(t, regs, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	resolve := NewResolver(benchStore{profiles: []*Profile{p}}, regs, nil)

	res, err := resolve(context.Background(), inputs.Pod{}, testRequest("example.com"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	l, ok := res.StreamLogger.(*streamLogger)
	if !ok {
		t.Fatalf("stream logger = %T, want *streamLogger", res.StreamLogger)
	}
	if l.sink == nil {
		t.Fatal("nil sink was passed through; Enqueue would panic on a matched audit entry")
	}
}
