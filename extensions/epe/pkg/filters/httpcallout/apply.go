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
package httpcallout

import (
	"fmt"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// decisionAction translates a validated Decision into the engine's action. It
// assumes Decision.Validate already ran; the guards it repeats are the ones a
// translation cannot proceed without, not a second validation pass.
func decisionAction(phase Phase, d Decision) (filter.Action, error) {
	if phase != PhaseRequest && phase != PhaseResponse {
		return filter.Action{}, fmt.Errorf("unknown callout phase %q", phase)
	}

	switch d.Action {
	case ActionRespond:
		return respondAction(d)
	case ActionContinue:
		return continueAction(phase, d)
	default:
		return filter.Action{}, fmt.Errorf("unknown callout action %q", d.Action)
	}
}

// respondAction builds the terminal reply. filter.Stop takes no mutations by
// design: the message the callout rejected never goes anywhere, so mutating it
// would be meaningless.
func respondAction(d Decision) (filter.Action, error) {
	if d.Response == nil {
		return filter.Action{}, fmt.Errorf("respond action has no response")
	}
	if d.Response.StatusCode == nil {
		return filter.Action{}, fmt.Errorf("respond action has no response status")
	}
	ops, err := headerOps(d.Response.Headers)
	if err != nil {
		return filter.Action{}, err
	}
	reply := filter.Reply{
		Status:    *d.Response.StatusCode,
		HeaderOps: ops,
		// Reason is the only audit channel a respond decision has; Details is
		// where the engine can carry it (RESPONSE_CODE_DETAILS). Validate has
		// already bounded it to what Envoy tolerates on that path.
		Details: d.Reason,
	}
	if d.Response.Body != nil {
		reply.Body = []byte(*d.Response.Body)
	}
	return filter.Stop(reply), nil
}

// continueAction folds the phase-appropriate mutation, or none at all when the
// callout changed nothing.
func continueAction(phase Phase, d Decision) (filter.Action, error) {
	var (
		headers []HeaderMutation
		body    *string
		status  *int
	)
	if phase == PhaseRequest {
		if d.Request != nil {
			headers, body = d.Request.Headers, d.Request.Body
		}
	} else if d.Response != nil {
		headers, body, status = d.Response.Headers, d.Response.Body, d.Response.StatusCode
	}

	ops, err := headerOps(headers)
	if err != nil {
		return filter.Action{}, err
	}
	if ops == nil && body == nil && status == nil {
		return filter.Continue(), nil
	}

	mutation := filter.Mutation{HeaderOps: ops, StatusCode: status}
	// nil leaves the body alone; non-nil, including empty, replaces it — the
	// same contract filter.Mutation.Body documents.
	if body != nil {
		mutation.Body = []byte(*body)
	}
	return filter.Continue(mutation), nil
}

// headerOps folds wire mutations into engine ops, lower-casing each name.
// Decision.Validate rejects a bad name but cannot rewrite its own receiver, so
// this is the one place that normalizes case.
func headerOps(mutations []HeaderMutation) ([]filter.HeaderOp, error) {
	if len(mutations) == 0 {
		return nil, nil
	}
	ops := make([]filter.HeaderOp, 0, len(mutations))
	for idx, mutation := range mutations {
		kind, known := opKinds[mutation.Operation]
		if !known {
			return nil, fmt.Errorf("header mutation %d has unknown operation %q", idx, mutation.Operation)
		}
		name, err := filter.ValidateHeaderName(kind, mutation.Name)
		if err != nil {
			return nil, fmt.Errorf("header mutation %d: %w", idx, err)
		}
		op := filter.HeaderOp{Kind: kind, Name: name}
		if mutation.Value != nil {
			op.Value = *mutation.Value
		}
		ops = append(ops, op)
	}
	return ops, nil
}
