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
	"reflect"
	"strings"
	"testing"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

func TestDecisionActionContinueWithoutMutations(t *testing.T) {
	for _, phase := range []Phase{PhaseRequest, PhaseResponse} {
		t.Run(string(phase), func(t *testing.T) {
			act, err := decisionAction(phase, Decision{
				Version: ProtocolVersion,
				Phase:   phase,
				Action:  ActionContinue,
			})
			if err != nil {
				t.Fatalf("decisionAction: %v", err)
			}
			if !act.Equal(filter.Continue()) {
				t.Fatalf("action = %#v, want a bare Continue", act)
			}
		})
	}
}

// TestDecisionActionEmptyMutationObjectIsStillANoOp pins that an object carrying
// no operations and no body produces no mutation, rather than an empty one the
// engine would fold for nothing.
func TestDecisionActionEmptyMutationObjectIsStillANoOp(t *testing.T) {
	act, err := decisionAction(PhaseRequest, Decision{
		Version: ProtocolVersion,
		Phase:   PhaseRequest,
		Action:  ActionContinue,
		Request: &RequestMutation{},
	})
	if err != nil {
		t.Fatalf("decisionAction: %v", err)
	}
	if !act.Equal(filter.Continue()) {
		t.Fatalf("action = %#v, want a bare Continue", act)
	}
}

func TestDecisionActionRequestContinueMutates(t *testing.T) {
	value := "true"
	body := `{"input":"rewritten"}`
	act, err := decisionAction(PhaseRequest, Decision{
		Version: ProtocolVersion,
		Phase:   PhaseRequest,
		Action:  ActionContinue,
		Request: &RequestMutation{
			Headers: []HeaderMutation{
				{Operation: HeaderSet, Name: "X-Reviewed", Value: &value},
				{Operation: HeaderAppend, Name: "X-Trace", Value: &value},
				{Operation: HeaderRemove, Name: "X-Internal"},
			},
			Body: &body,
		},
	})
	if err != nil {
		t.Fatalf("decisionAction: %v", err)
	}
	want := filter.Continue(filter.Mutation{
		HeaderOps: []filter.HeaderOp{
			// Names arrive in whatever case the remote chose; folding happens
			// here, because Decision.Validate cannot rewrite its own receiver.
			{Kind: filter.HeaderSet, Name: "x-reviewed", Value: "true"},
			{Kind: filter.HeaderAdd, Name: "x-trace", Value: "true"},
			{Kind: filter.HeaderRemove, Name: "x-internal"},
		},
		Body: []byte(body),
	})
	if !act.Equal(want) {
		t.Fatalf("action = %#v, want %#v", act.Mutations(), want.Mutations())
	}
}

// TestDecisionActionBodyPointerSemantics pins nil vs empty: filter.Mutation.Body
// uses the same contract, so an omitted body must not become a clear.
func TestDecisionActionBodyPointerSemantics(t *testing.T) {
	value := "x"
	t.Run("omitted body leaves the message unchanged", func(t *testing.T) {
		act, err := decisionAction(PhaseRequest, Decision{
			Version: ProtocolVersion,
			Phase:   PhaseRequest,
			Action:  ActionContinue,
			Request: &RequestMutation{Headers: []HeaderMutation{{Operation: HeaderSet, Name: "x-a", Value: &value}}},
		})
		if err != nil {
			t.Fatalf("decisionAction: %v", err)
		}
		if got := act.Mutations()[0].Body; got != nil {
			t.Fatalf("body = %#v, want nil meaning unchanged", got)
		}
	})

	t.Run("empty body clears it", func(t *testing.T) {
		empty := ""
		act, err := decisionAction(PhaseRequest, Decision{
			Version: ProtocolVersion,
			Phase:   PhaseRequest,
			Action:  ActionContinue,
			Request: &RequestMutation{Body: &empty},
		})
		if err != nil {
			t.Fatalf("decisionAction: %v", err)
		}
		got := act.Mutations()[0].Body
		if got == nil || len(got) != 0 {
			t.Fatalf("body = %#v, want a non-nil empty slice meaning replace", got)
		}
	})
}

func TestDecisionActionResponseContinueCarriesStatus(t *testing.T) {
	status := 418
	value := "demo"
	act, err := decisionAction(PhaseResponse, Decision{
		Version: ProtocolVersion,
		Phase:   PhaseResponse,
		Action:  ActionContinue,
		Response: &ResponseMutation{
			StatusCode: &status,
			Headers:    []HeaderMutation{{Operation: HeaderSet, Name: "X-Reviewed", Value: &value}},
		},
	})
	if err != nil {
		t.Fatalf("decisionAction: %v", err)
	}
	mutations := act.Mutations()
	if len(mutations) != 1 {
		t.Fatalf("mutations = %#v, want exactly one", mutations)
	}
	if mutations[0].StatusCode == nil || *mutations[0].StatusCode != status {
		t.Fatalf("status = %#v, want %d", mutations[0].StatusCode, status)
	}
	want := []filter.HeaderOp{{Kind: filter.HeaderSet, Name: "x-reviewed", Value: "demo"}}
	if !reflect.DeepEqual(mutations[0].HeaderOps, want) {
		t.Fatalf("header ops = %#v, want %#v", mutations[0].HeaderOps, want)
	}
}

// TestDecisionActionStatusOnlyResponseContinue pins that a lone status override
// is a real mutation, not a no-op.
func TestDecisionActionStatusOnlyResponseContinue(t *testing.T) {
	status := 503
	act, err := decisionAction(PhaseResponse, Decision{
		Version:  ProtocolVersion,
		Phase:    PhaseResponse,
		Action:   ActionContinue,
		Response: &ResponseMutation{StatusCode: &status},
	})
	if err != nil {
		t.Fatalf("decisionAction: %v", err)
	}
	if len(act.Mutations()) != 1 || act.Mutations()[0].StatusCode == nil {
		t.Fatalf("mutations = %#v, want one carrying the status", act.Mutations())
	}
}

// TestDecisionActionRespondStopsWithTheReason is the reason path: Reason is the
// only audit channel a respond decision has, and it lands in Reply.Details,
// which feeds RESPONSE_CODE_DETAILS.
func TestDecisionActionRespondStopsWithTheReason(t *testing.T) {
	status := 403
	contentType := "application/json"
	body := `{"error":"denied"}`

	for _, phase := range []Phase{PhaseRequest, PhaseResponse} {
		t.Run(string(phase), func(t *testing.T) {
			act, err := decisionAction(phase, Decision{
				Version: ProtocolVersion,
				Phase:   phase,
				Action:  ActionRespond,
				Reason:  "secret detected in prompt",
				Response: &ResponseMutation{
					StatusCode: &status,
					Headers:    []HeaderMutation{{Operation: HeaderSet, Name: "Content-Type", Value: &contentType}},
					Body:       &body,
				},
			})
			if err != nil {
				t.Fatalf("decisionAction: %v", err)
			}
			if act.Kind() != filter.KindStop {
				t.Fatalf("kind = %v, want KindStop", act.Kind())
			}
			reply, stopping := act.Reply()
			if !stopping {
				t.Fatal("KindStop action carried no reply")
			}
			want := filter.Reply{
				Status:    403,
				HeaderOps: []filter.HeaderOp{{Kind: filter.HeaderSet, Name: "content-type", Value: "application/json"}},
				Body:      []byte(body),
				Details:   "secret detected in prompt",
			}
			if !reflect.DeepEqual(reply, want) {
				t.Fatalf("reply = %#v, want %#v", reply, want)
			}
			if len(act.Mutations()) != 0 {
				t.Fatalf("a Stop action carried mutations: %#v", act.Mutations())
			}
		})
	}
}

func TestDecisionActionRespondWithoutOptionalFields(t *testing.T) {
	status := 429
	act, err := decisionAction(PhaseRequest, Decision{
		Version:  ProtocolVersion,
		Phase:    PhaseRequest,
		Action:   ActionRespond,
		Response: &ResponseMutation{StatusCode: &status},
	})
	if err != nil {
		t.Fatalf("decisionAction: %v", err)
	}
	reply, _ := act.Reply()
	if !reflect.DeepEqual(reply, filter.Reply{Status: 429}) {
		t.Fatalf("reply = %#v, want only a status", reply)
	}
}

func TestDecisionActionRejectsUntranslatableDecisions(t *testing.T) {
	value := "v"
	for _, tc := range []struct {
		name     string
		phase    Phase
		decision Decision
		wantErr  string
	}{
		{
			name:     "respond without a response",
			phase:    PhaseRequest,
			decision: Decision{Action: ActionRespond},
			wantErr:  "response",
		},
		{
			name:     "respond without a status",
			phase:    PhaseRequest,
			decision: Decision{Action: ActionRespond, Response: &ResponseMutation{}},
			wantErr:  "status",
		},
		{
			name:     "unknown action",
			phase:    PhaseRequest,
			decision: Decision{Action: Action("allow")},
			wantErr:  "action",
		},
		{
			name:     "unknown phase",
			phase:    Phase("trailers"),
			decision: Decision{Action: ActionContinue},
			wantErr:  "phase",
		},
		{
			name:  "unknown header operation",
			phase: PhaseRequest,
			decision: Decision{Action: ActionContinue, Request: &RequestMutation{Headers: []HeaderMutation{
				{Operation: HeaderOperation("replace"), Name: "x-a", Value: &value},
			}}},
			wantErr: "operation",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decisionAction(tc.phase, tc.decision); err == nil ||
				!strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
				t.Fatalf("error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}
