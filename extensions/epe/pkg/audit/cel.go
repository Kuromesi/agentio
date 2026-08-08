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

	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/metrics"
)

// EvalWhen evaluates a compiled when expression against the Scope.
func EvalWhen(prog cel.Program, s *Scope) (bool, error) {
	if prog == nil {
		return true, nil
	}
	act, release := s.Activation()
	defer release()
	return eval.EvalBool(prog, act)
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
