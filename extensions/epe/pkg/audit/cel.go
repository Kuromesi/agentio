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
package audit

import (
	"github.com/google/cel-go/cel"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/openkruise/agentio/extensions/epe/pkg/eval"
	"github.com/openkruise/agentio/extensions/epe/pkg/metrics"
)

// EvalWhen evaluates a compiled when expression against the Scope. An audit
// entry with no `when` has no condition and always fires.
//
// The nil check is not a copy of the one eval.EvalBool already performs; it is
// here for its other effect. Go evaluates s.Activation() before entering
// EvalBool, so without this return the variable bag is built even for an entry
// that never had a condition — roughly 700 ns for the memoised base plus 225 ns
// for the audit child, and buildScope's caller loops over every entry of the
// unit. A when-less audit is the ordinary configuration, so this is the common
// path, not the edge case.
func EvalWhen(prog cel.Program, s *Scope) (bool, error) {
	if prog == nil {
		return true, nil
	}
	return eval.EvalBool(prog, s.Activation())
}

var (
	// EvalDroppedTotal counts entries dropped before reaching a Sink
	// (failed `when` evaluation or no sink registered). Transport-level
	// drops are counted by the owning Sink.
	EvalDroppedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "epe_audit_eval_dropped_total",
			Help: "Audit entries dropped before reaching the Sink.",
		},
		[]string{"reason"}, // when_eval | no_sink
	)
)

func init() {
	metrics.Registry.MustRegister(
		EvalDroppedTotal,
	)
}
