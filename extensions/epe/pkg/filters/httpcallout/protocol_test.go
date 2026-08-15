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
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

func TestInvocationMarshalsRequestContract(t *testing.T) {
	invocation := Invocation{
		Version: ProtocolVersion,
		Phase:   PhaseRequest,
		Source: SourceContext{
			Namespace: "default",
			Pod:       "agent-0",
			IP:        "10.0.0.8",
			Labels:    map[string]string{"app": "agent"},
		},
		Policy: PolicyContext{Scope: "default/profile", Rule: "inspect", Ordinal: 2},
		Request: &HTTPRequest{
			ID:          "req-123",
			Method:      "POST",
			Scheme:      "https",
			Host:        "api.example.com",
			Port:        443,
			Path:        "/v1/run",
			RawQuery:    "debug=true",
			ContentType: "application/json",
			Headers:     map[string]string{"x-tenant": "demo"},
			Body:        stringPointer(`{"input":"hi"}`),
		},
	}

	got := marshalJSONObject(t, invocation)
	want := unmarshalJSONObject(t, `{
		"version":"0.1",
		"phase":"request",
		"source":{
			"namespace":"default",
			"pod":"agent-0",
			"ip":"10.0.0.8",
			"labels":{"app":"agent"}
		},
		"policy":{"scope":"default/profile","rule":"inspect","ordinal":2},
		"request":{
			"id":"req-123",
			"method":"POST",
			"scheme":"https",
			"host":"api.example.com",
			"port":443,
			"path":"/v1/run",
			"rawQuery":"debug=true",
			"contentType":"application/json",
			"headers":{"x-tenant":"demo"},
			"body":"{\"input\":\"hi\"}"
		}
	}`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("marshaled invocation = %#v, want %#v", got, want)
	}
	if _, found := got["requestId"]; found {
		t.Fatal("request ID remained duplicated at the invocation top level")
	}

	source := got["source"].(map[string]any)
	if _, found := source["token"]; found {
		t.Fatal("source context exposed a token field")
	}
	request := got["request"].(map[string]any)
	if _, found := request["bodyBase64"]; found {
		t.Fatal("request used the AWS-style bodyBase64 field")
	}
	if request["body"] != `{"input":"hi"}` {
		t.Fatalf("request body = %#v, want ordinary UTF-8 JSON text", request["body"])
	}
}

func TestInvocationOmitsHiddenRequestHeadersButKeepsContentType(t *testing.T) {
	got := marshalJSONObject(t, Invocation{
		Version: ProtocolVersion,
		Phase:   PhaseResponse,
		Request: &HTTPRequest{
			ContentType: "application/json; charset=utf-8",
		},
		Response: &HTTPResponse{
			StatusCode:  200,
			ContentType: "text/plain",
			Headers:     map[string]string{"x-upstream": "demo"},
			Body:        stringPointer("response"),
		},
	})
	request := got["request"].(map[string]any)
	if _, found := request["headers"]; found {
		t.Fatal("nil request headers were disclosed instead of omitted")
	}
	if got := request["contentType"]; got != "application/json; charset=utf-8" {
		t.Errorf("request contentType = %#v, want it preserved independently of headers", got)
	}
	// The two directions are independent: hiding request headers must not hide
	// response headers the operator did ask for.
	response := got["response"].(map[string]any)
	if _, found := response["headers"]; !found {
		t.Fatal("disclosed response headers were omitted")
	}
}

// TestInvocationOmitsHiddenResponseHeadersButKeepsStatusAndContentType is the
// wire bite for the response direction: under the default mode the header map is
// absent from the document rather than present and empty, while the two fields a
// scanner needs survive.
func TestInvocationOmitsHiddenResponseHeadersButKeepsStatusAndContentType(t *testing.T) {
	got := marshalJSONObject(t, Invocation{
		Version: ProtocolVersion,
		Phase:   PhaseResponse,
		Request: &HTTPRequest{},
		Response: &HTTPResponse{
			StatusCode:  503,
			ContentType: "text/plain; charset=utf-8",
			Body:        stringPointer("upstream down"),
		},
	})
	response := got["response"].(map[string]any)
	if _, found := response["headers"]; found {
		t.Fatalf("hidden response headers were disclosed as %#v instead of omitted", response["headers"])
	}
	if response["contentType"] != "text/plain; charset=utf-8" {
		t.Errorf("response contentType = %#v, want it preserved independently of headers", response["contentType"])
	}
	if response["statusCode"] != float64(503) {
		t.Errorf("response statusCode = %#v, want 503 preserved independently of headers", response["statusCode"])
	}
}

// TestInvocationRequestBodyPresenceIsExplicit pins the pointer contract: the
// request phase always carries a body key, including for an empty body, while
// the response phase omits it so the correlation view cannot be mistaken for a
// request that happened to have no body.
func TestInvocationRequestBodyPresenceIsExplicit(t *testing.T) {
	empty := marshalJSONObject(t, Invocation{
		Version: ProtocolVersion,
		Phase:   PhaseRequest,
		Request: &HTTPRequest{Body: stringPointer("")},
	})
	body, found := empty["request"].(map[string]any)["body"]
	if !found || body != "" {
		t.Fatalf("request-phase empty body = (%#v, %v), want a present empty string", body, found)
	}

	correlation := marshalJSONObject(t, Invocation{
		Version:  ProtocolVersion,
		Phase:    PhaseResponse,
		Request:  &HTTPRequest{},
		Response: &HTTPResponse{StatusCode: 200, Headers: map[string]string{}},
	})
	if _, found := correlation["request"].(map[string]any)["body"]; found {
		t.Fatal("response-phase request view carried a body key")
	}
}

// TestInvocationBodyPresenceIsThreeStatedOnTheWire pins that the pointer carries
// a distinction JSON cannot otherwise express. A scanner reading "collected and
// empty" as "never collected" — or the reverse — would be reasoning about a
// message it never saw, so the two must not render alike in either direction.
func TestInvocationBodyPresenceIsThreeStatedOnTheWire(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		collected := marshalJSONObject(t, Invocation{
			Version: ProtocolVersion,
			Phase:   PhaseRequest,
			Request: &HTTPRequest{Body: stringPointer("")},
		})["request"].(map[string]any)
		notCollected := marshalJSONObject(t, Invocation{
			Version: ProtocolVersion,
			Phase:   PhaseRequest,
			Request: &HTTPRequest{},
		})["request"].(map[string]any)

		body, found := collected["body"]
		if !found {
			t.Error("a collected empty body was omitted from the document")
		} else if body != "" {
			t.Errorf("collected body = %#v, want a present empty string", body)
		}
		if _, found := notCollected["body"]; found {
			t.Errorf("an uncollected body rendered as %#v, want the key absent", notCollected["body"])
		}
	})

	t.Run("response", func(t *testing.T) {
		collected := marshalJSONObject(t, Invocation{
			Version:  ProtocolVersion,
			Phase:    PhaseResponse,
			Request:  &HTTPRequest{},
			Response: &HTTPResponse{StatusCode: 200, Body: stringPointer("")},
		})["response"].(map[string]any)
		notCollected := marshalJSONObject(t, Invocation{
			Version:  ProtocolVersion,
			Phase:    PhaseResponse,
			Request:  &HTTPRequest{},
			Response: &HTTPResponse{StatusCode: 200},
		})["response"].(map[string]any)

		body, found := collected["body"]
		if !found {
			t.Error("a collected empty response body was omitted from the document")
		} else if body != "" {
			t.Errorf("collected response body = %#v, want a present empty string", body)
		}
		if _, found := notCollected["body"]; found {
			t.Errorf("an uncollected response body rendered as %#v, want the key absent", notCollected["body"])
		}
	})
}

func TestInvocationValidateAcceptsPhaseShapes(t *testing.T) {
	tests := []Invocation{
		{
			Version: ProtocolVersion,
			Phase:   PhaseRequest,
			Request: &HTTPRequest{Body: stringPointer("request")},
		},
		{
			// An empty request body is a present body, not an absent one.
			Version: ProtocolVersion,
			Phase:   PhaseRequest,
			Request: &HTTPRequest{Body: stringPointer("")},
		},
		{
			// No body at all is legal too, now that collection is opt-in per
			// phase. Whether EPE should have attached one is the config's
			// business, not this contract's.
			Version: ProtocolVersion,
			Phase:   PhaseRequest,
			Request: &HTTPRequest{},
		},
		{
			// The same third state on the response side.
			Version:  ProtocolVersion,
			Phase:    PhaseResponse,
			Request:  &HTTPRequest{},
			Response: &HTTPResponse{StatusCode: 200},
		},
		{
			Version:  ProtocolVersion,
			Phase:    PhaseResponse,
			Request:  &HTTPRequest{},
			Response: &HTTPResponse{StatusCode: 200, Headers: map[string]string{}, Body: stringPointer("response")},
		},
		{
			// Hidden response headers are the default, so a nil map is a valid
			// invocation rather than an incomplete one.
			Version:  ProtocolVersion,
			Phase:    PhaseResponse,
			Request:  &HTTPRequest{},
			Response: &HTTPResponse{StatusCode: 200, Body: stringPointer("response")},
		},
	}
	for _, invocation := range tests {
		if err := invocation.Validate(); err != nil {
			t.Errorf("Validate(%s): %v", invocation.Phase, err)
		}
	}
}

// TestInvocationValidateEnforcesResponsePhaseRequestView pins the correlation
// view: a response-phase invocation must not carry the request body or request
// headers, so the response half never depends on EPE retaining them.
func TestInvocationValidateEnforcesResponsePhaseRequestView(t *testing.T) {
	base := func() Invocation {
		return Invocation{
			Version:  ProtocolVersion,
			Phase:    PhaseResponse,
			Request:  &HTTPRequest{ID: "req-1", Method: "POST"},
			Response: &HTTPResponse{StatusCode: 200, Headers: map[string]string{}},
		}
	}
	t.Run("body present", func(t *testing.T) {
		inv := base()
		inv.Request.Body = stringPointer("")
		if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), "body") {
			t.Fatalf("Validate error = %v, want one naming the body", err)
		}
	})
	t.Run("headers present", func(t *testing.T) {
		inv := base()
		inv.Request.Headers = map[string]string{"x-tenant": "demo"}
		if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), "header") {
			t.Fatalf("Validate error = %v, want one naming the headers", err)
		}
	})
}

func TestInvocationValidateRejectsInvalidContract(t *testing.T) {
	valid := Invocation{
		Version: ProtocolVersion,
		Phase:   PhaseRequest,
		Request: &HTTPRequest{Body: stringPointer("request")},
	}
	tests := []struct {
		name    string
		mutate  func(*Invocation)
		wantErr string
	}{
		{
			name:    "wrong version",
			mutate:  func(i *Invocation) { i.Version = "v2" },
			wantErr: "version",
		},
		{
			name:    "unknown phase",
			mutate:  func(i *Invocation) { i.Phase = Phase("trailers") },
			wantErr: "phase",
		},
		{
			name:    "missing request",
			mutate:  func(i *Invocation) { i.Request = nil },
			wantErr: "request",
		},
		{
			name: "response present in request phase",
			mutate: func(i *Invocation) {
				i.Response = &HTTPResponse{StatusCode: 200, Headers: map[string]string{}}
			},
			wantErr: "response",
		},
		{
			name: "response missing in response phase",
			mutate: func(i *Invocation) {
				i.Phase = PhaseResponse
				i.Request.Body = nil
			},
			wantErr: "response",
		},
		{
			name: "non utf8 request body",
			mutate: func(i *Invocation) {
				i.Request.Body = stringPointer(string([]byte{0xff}))
			},
			wantErr: "utf-8",
		},
		{
			name: "non utf8 response body",
			mutate: func(i *Invocation) {
				i.Phase = PhaseResponse
				i.Request.Body = nil
				i.Response = &HTTPResponse{StatusCode: 200, Headers: map[string]string{}, Body: stringPointer(string([]byte{0xff}))}
			},
			wantErr: "utf-8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invocation := valid
			request := *valid.Request
			invocation.Request = &request
			tt.mutate(&invocation)
			if err := invocation.Validate(); err == nil || !strings.Contains(strings.ToLower(err.Error()), tt.wantErr) {
				t.Fatalf("Validate error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestDecisionMarshalsRequestContinueContract(t *testing.T) {
	body := `{"input":"rewritten"}`
	value := "true"
	decision := Decision{
		Version:   ProtocolVersion,
		Phase:     PhaseRequest,
		RequestID: "req-123",
		Action:    actionPtr(ActionContinue),
		Request: &RequestMutation{
			Headers: []HeaderMutation{{
				Operation: HeaderSet,
				Name:      "x-reviewed",
				Value:     &value,
			}},
			Body: &body,
		},
	}

	got := marshalJSONObject(t, decision)
	want := unmarshalJSONObject(t, `{
		"version":"0.1",
		"phase":"request",
		"requestId":"req-123",
		"action":"continue",
		"request":{
			"headers":[
				{"operation":"set","name":"x-reviewed","value":"true"}
			],
			"body":"{\"input\":\"rewritten\"}"
		}
	}`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("marshaled decision = %#v, want %#v", got, want)
	}
}

func TestDecisionMarshalsRequestRespondContract(t *testing.T) {
	status := 403
	contentType := "application/json"
	body := `{"error":"denied"}`
	got := marshalJSONObject(t, Decision{
		Version:   ProtocolVersion,
		Phase:     PhaseRequest,
		RequestID: "req-123",
		Action:    actionPtr(ActionRespond),
		Response: &ResponseMutation{
			StatusCode: &status,
			Headers: []HeaderMutation{{
				Operation: HeaderSet,
				Name:      "content-type",
				Value:     &contentType,
			}},
			Body: &body,
		},
	})
	want := unmarshalJSONObject(t, `{
		"version":"0.1",
		"phase":"request",
		"requestId":"req-123",
		"action":"respond",
		"response":{
			"statusCode":403,
			"headers":[
				{"operation":"set","name":"content-type","value":"application/json"}
			],
			"body":"{\"error\":\"denied\"}"
		}
	}`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("marshaled decision = %#v, want %#v", got, want)
	}
}

func TestDecisionOmitsEmptyReason(t *testing.T) {
	status := 403
	withReason := marshalJSONObject(t, Decision{
		Version:  ProtocolVersion,
		Action:   actionPtr(ActionRespond),
		Reason:   "secret detected",
		Response: &ResponseMutation{StatusCode: &status},
	})
	if withReason["reason"] != "secret detected" {
		t.Fatalf("reason = %#v, want it serialized", withReason["reason"])
	}

	withoutReason := marshalJSONObject(t, Decision{
		Version:  ProtocolVersion,
		Action:   actionPtr(ActionRespond),
		Response: &ResponseMutation{StatusCode: &status},
	})
	if _, found := withoutReason["reason"]; found {
		t.Fatal("empty reason was serialized instead of omitted")
	}
}

func TestDecisionDistinguishesOmittedAndEmptyBody(t *testing.T) {
	omitted := marshalJSONObject(t, Decision{
		Version: ProtocolVersion,
		Action:  actionPtr(ActionContinue),
		Request: &RequestMutation{},
	})
	if _, found := omitted["request"].(map[string]any)["body"]; found {
		t.Fatal("nil body was serialized instead of meaning unchanged")
	}

	empty := ""
	cleared := marshalJSONObject(t, Decision{
		Version: ProtocolVersion,
		Action:  actionPtr(ActionContinue),
		Request: &RequestMutation{Body: &empty},
	})
	body, found := cleared["request"].(map[string]any)["body"]
	if !found || body != "" {
		t.Fatalf("explicit empty body = (%#v, %v), want present empty string", body, found)
	}
}

// invocationFor builds a minimal valid invocation for the phase, so decision
// tests exercise the echo rules against something Invocation.Validate accepts.
func invocationFor(phase Phase, requestID string) Invocation {
	inv := Invocation{
		Version: ProtocolVersion,
		Phase:   phase,
		Request: &HTTPRequest{ID: requestID, Body: stringPointer("request")},
	}
	if phase == PhaseResponse {
		// The response phase sees the correlation view only.
		inv.Request.Body = nil
		inv.Response = &HTTPResponse{StatusCode: 200, Headers: map[string]string{}, Body: stringPointer("response")}
	}
	return inv
}

func stringPointer(value string) *string { return &value }

// actionPtr spells out an action a decision could also have left absent. Tests
// state it explicitly so the cases that deliberately omit it stand out.
func actionPtr(a Action) *Action { return &a }

// TestDecisionOmittedActionIsAContinue pins a deliberate leniency: the endpoint
// is a third party, so an observing callout may answer without restating the only
// action it ever takes. The safety of that rests on omission reaching nothing but
// the permissive outcome, so the last two cases matter as much as the first —
// silence must not be able to carry a respond, a deny, or a response mutation
// into a phase that forbids one.
func TestDecisionOmittedActionIsAContinue(t *testing.T) {
	const requestID = "req-123"
	bare := func(phase Phase) Decision {
		return Decision{Version: ProtocolVersion, Phase: phase, RequestID: requestID}
	}

	for _, phase := range []Phase{PhaseRequest, PhaseResponse} {
		t.Run(string(phase)+" phase", func(t *testing.T) {
			decision := bare(phase)
			if err := decision.Validate(invocationFor(phase, requestID)); err != nil {
				t.Fatalf("Validate with no action = %v, want nil", err)
			}
			act, err := decisionAction(phase, decision)
			if err != nil {
				t.Fatalf("decisionAction with no action = %v, want nil", err)
			}
			if act.Kind() != filter.KindContinue {
				t.Errorf("action kind = %v, want continue", act.Kind())
			}
		})
	}

	t.Run("the key is absent on the wire", func(t *testing.T) {
		if _, found := marshalJSONObject(t, bare(PhaseRequest))["action"]; found {
			t.Error("an omitted action was marshalled as a present key")
		}
	})

	t.Run("silence cannot carry a response mutation into the request phase", func(t *testing.T) {
		status := 403
		decision := bare(PhaseRequest)
		decision.Response = &ResponseMutation{StatusCode: &status}
		if err := decision.Validate(invocationFor(PhaseRequest, requestID)); err == nil {
			t.Fatal("an actionless decision carried a response mutation into the request phase")
		}
	})

	t.Run("silence cannot carry a reason", func(t *testing.T) {
		decision := bare(PhaseRequest)
		decision.Reason = "denied"
		if err := decision.Validate(invocationFor(PhaseRequest, requestID)); err == nil {
			t.Fatal("an actionless decision carried a reason, which is respond-only")
		}
	})
}

func TestDecisionValidateAcceptsPhaseContracts(t *testing.T) {
	headerValue := "value"
	status := 201
	empty := ""
	const requestID = "req-123"
	tests := []struct {
		name     string
		phase    Phase
		decision Decision
	}{
		{
			name:  "request no-op",
			phase: PhaseRequest,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseRequest,
				RequestID: requestID,
				Action:    actionPtr(ActionContinue),
			},
		},
		{
			name:  "request mutation",
			phase: PhaseRequest,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseRequest,
				RequestID: requestID,
				Action:    actionPtr(ActionContinue),
				Request: &RequestMutation{
					Headers: []HeaderMutation{
						{Operation: HeaderSet, Name: "x-a", Value: &headerValue},
						{Operation: HeaderAppend, Name: "x-a", Value: &empty},
						{Operation: HeaderRemove, Name: "x-b"},
					},
					Body: &empty,
				},
			},
		},
		{
			name:  "request mutation removing a framing header",
			phase: PhaseRequest,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseRequest,
				RequestID: requestID,
				Action:    actionPtr(ActionContinue),
				Request: &RequestMutation{Headers: []HeaderMutation{
					{Operation: HeaderRemove, Name: "Content-Length"},
					{Operation: HeaderRemove, Name: "transfer-encoding"},
				}},
			},
		},
		{
			name:  "response mutation setting set-cookie",
			phase: PhaseResponse,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseResponse,
				RequestID: requestID,
				Action:    actionPtr(ActionContinue),
				Response: &ResponseMutation{Headers: []HeaderMutation{
					{Operation: HeaderSet, Name: "Set-Cookie", Value: &headerValue},
				}},
			},
		},
		{
			name:  "request respond",
			phase: PhaseRequest,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseRequest,
				RequestID: requestID,
				Action:    actionPtr(ActionRespond),
				Response:  &ResponseMutation{StatusCode: &status},
			},
		},
		{
			name:  "request respond with reason",
			phase: PhaseRequest,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseRequest,
				RequestID: requestID,
				Action:    actionPtr(ActionRespond),
				Reason:    "secret detected in prompt",
				Response:  &ResponseMutation{StatusCode: &status},
			},
		},
		{
			name:  "response respond",
			phase: PhaseResponse,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseResponse,
				RequestID: requestID,
				Action:    actionPtr(ActionRespond),
				Response:  &ResponseMutation{StatusCode: &status},
			},
		},
		{
			name:  "response respond with non-ascii reason",
			phase: PhaseResponse,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseResponse,
				RequestID: requestID,
				Action:    actionPtr(ActionRespond),
				Reason:    "检测到 泄露 secret",
				Response:  &ResponseMutation{StatusCode: &status},
			},
		},
		{
			name:  "reason at the byte cap",
			phase: PhaseRequest,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseRequest,
				RequestID: requestID,
				Action:    actionPtr(ActionRespond),
				Reason:    strings.Repeat("a", 256),
				Response:  &ResponseMutation{StatusCode: &status},
			},
		},
		{
			name:  "response respond with empty reason",
			phase: PhaseResponse,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseResponse,
				RequestID: requestID,
				Action:    actionPtr(ActionRespond),
				Reason:    "",
				Response:  &ResponseMutation{StatusCode: &status},
			},
		},
		{
			name:  "response no-op",
			phase: PhaseResponse,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseResponse,
				RequestID: requestID,
				Action:    actionPtr(ActionContinue),
			},
		},
		{
			name:  "response mutation",
			phase: PhaseResponse,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseResponse,
				RequestID: requestID,
				Action:    actionPtr(ActionContinue),
				Response: &ResponseMutation{
					StatusCode: &status,
					Headers:    []HeaderMutation{{Operation: HeaderSet, Name: "x-reviewed", Value: &headerValue}},
					Body:       &empty,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.decision.Validate(invocationFor(tt.phase, requestID)); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestDecisionValidateAcceptsEmptyRequestIDEcho(t *testing.T) {
	decision := Decision{
		Version: ProtocolVersion,
		Phase:   PhaseRequest,
		Action:  actionPtr(ActionContinue),
	}
	if err := decision.Validate(invocationFor(PhaseRequest, "")); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestDecisionMarshalsRequestIDEvenWhenEmpty(t *testing.T) {
	got := marshalJSONObject(t, Decision{
		Version: ProtocolVersion,
		Phase:   PhaseRequest,
		Action:  actionPtr(ActionContinue),
	})
	value, found := got["requestId"]
	if !found || value != "" {
		t.Fatalf("requestId = (%#v, %v), want a present empty string", value, found)
	}
	if got["phase"] != string(PhaseRequest) {
		t.Fatalf("phase = %#v, want %q", got["phase"], PhaseRequest)
	}
}

func TestDecisionValidateRejectsInvalidContract(t *testing.T) {
	value := "value"
	statusOK := 200
	statusLow := 199
	statusHigh := 600
	nonUTF8 := string([]byte{0xff})
	invalidHeaderValue := "safe\r\nx-injected: value"
	const requestID = "req-123"

	// echo fills in the correlation fields a well-behaved callout returns, so
	// each case below isolates the one thing it means to break.
	echo := func(phase Phase, d Decision) Decision {
		d.Phase = phase
		d.RequestID = requestID
		return d
	}

	tests := []struct {
		name     string
		inv      Invocation
		decision Decision
		wantErr  string
	}{
		{
			name:     "unknown phase",
			inv:      Invocation{Version: ProtocolVersion, Phase: Phase("trailers"), Request: &HTTPRequest{ID: requestID}},
			decision: echo(Phase("trailers"), Decision{Version: ProtocolVersion, Action: actionPtr(ActionContinue)}),
			wantErr:  "phase",
		},
		{
			name:     "wrong version",
			inv:      invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{Version: "v2", Action: actionPtr(ActionContinue)}),
			wantErr:  "version",
		},
		{
			name:     "unknown action",
			inv:      invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{Version: ProtocolVersion, Action: actionPtr(Action("allow"))}),
			wantErr:  "action",
		},
		{
			name:     "mismatched phase echo",
			inv:      invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseResponse, Decision{Version: ProtocolVersion, Action: actionPtr(ActionContinue)}),
			wantErr:  "phase",
		},
		{
			name:     "mismatched response phase echo",
			inv:      invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseRequest, Decision{Version: ProtocolVersion, Action: actionPtr(ActionContinue)}),
			wantErr:  "phase",
		},
		{
			name:     "missing phase echo",
			inv:      invocationFor(PhaseRequest, requestID),
			decision: echo(Phase(""), Decision{Version: ProtocolVersion, Action: actionPtr(ActionContinue)}),
			wantErr:  "phase",
		},
		{
			name: "mismatched request id echo",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseRequest,
				RequestID: "req-999",
				Action:    actionPtr(ActionContinue),
			},
			wantErr: "request id",
		},
		{
			name: "missing request id echo",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: Decision{
				Version: ProtocolVersion,
				Phase:   PhaseRequest,
				Action:  actionPtr(ActionContinue),
			},
			wantErr: "request id",
		},
		{
			name: "request id echoed when the request had none",
			inv:  invocationFor(PhaseRequest, ""),
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseRequest,
				RequestID: requestID,
				Action:    actionPtr(ActionContinue),
			},
			wantErr: "request id",
		},
		{
			name: "response object on request continue",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version: ProtocolVersion,
				Action:  actionPtr(ActionContinue),
				Response: &ResponseMutation{
					StatusCode: &statusOK,
				},
			}),
			wantErr: "response",
		},
		{
			name: "request object on response continue",
			inv:  invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{
				Version: ProtocolVersion,
				Action:  actionPtr(ActionContinue),
				Request: &RequestMutation{},
			}),
			wantErr: "request",
		},
		{
			name:     "respond without response",
			inv:      invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{Version: ProtocolVersion, Action: actionPtr(ActionRespond)}),
			wantErr:  "response",
		},
		{
			name:     "response-phase respond without response",
			inv:      invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{Version: ProtocolVersion, Action: actionPtr(ActionRespond)}),
			wantErr:  "response",
		},
		{
			name: "respond without status",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version:  ProtocolVersion,
				Action:   actionPtr(ActionRespond),
				Response: &ResponseMutation{},
			}),
			wantErr: "status",
		},
		{
			name: "response-phase respond without status",
			inv:  invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{
				Version:  ProtocolVersion,
				Action:   actionPtr(ActionRespond),
				Response: &ResponseMutation{},
			}),
			wantErr: "status",
		},
		{
			name: "respond with request mutation",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version:  ProtocolVersion,
				Action:   actionPtr(ActionRespond),
				Request:  &RequestMutation{},
				Response: &ResponseMutation{StatusCode: &statusOK},
			}),
			wantErr: "request",
		},
		{
			name: "response-phase respond with request mutation",
			inv:  invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{
				Version:  ProtocolVersion,
				Action:   actionPtr(ActionRespond),
				Request:  &RequestMutation{},
				Response: &ResponseMutation{StatusCode: &statusOK},
			}),
			wantErr: "request",
		},
		{
			name: "request-phase continue with reason",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version: ProtocolVersion,
				Action:  actionPtr(ActionContinue),
				Reason:  "just so you know",
			}),
			wantErr: "reason",
		},
		{
			name: "response-phase continue with reason",
			inv:  invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{
				Version: ProtocolVersion,
				Action:  actionPtr(ActionContinue),
				Reason:  "just so you know",
			}),
			wantErr: "reason",
		},
		{
			name: "reason over the byte cap",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version:  ProtocolVersion,
				Action:   actionPtr(ActionRespond),
				Reason:   strings.Repeat("a", 257),
				Response: &ResponseMutation{StatusCode: &statusOK},
			}),
			wantErr: "reason",
		},
		{
			name: "reason with a control byte",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version:  ProtocolVersion,
				Action:   actionPtr(ActionRespond),
				Reason:   "blocked\nby policy",
				Response: &ResponseMutation{StatusCode: &statusOK},
			}),
			wantErr: "control",
		},
		{
			name: "reason with delete",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version:  ProtocolVersion,
				Action:   actionPtr(ActionRespond),
				Reason:   "blocked\x7fby policy",
				Response: &ResponseMutation{StatusCode: &statusOK},
			}),
			wantErr: "control",
		},
		{
			name: "reason not valid utf8",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version:  ProtocolVersion,
				Action:   actionPtr(ActionRespond),
				Reason:   nonUTF8,
				Response: &ResponseMutation{StatusCode: &statusOK},
			}),
			wantErr: "utf-8",
		},
		{
			name: "status below final response range",
			inv:  invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{
				Version:  ProtocolVersion,
				Action:   actionPtr(ActionContinue),
				Response: &ResponseMutation{StatusCode: &statusLow},
			}),
			wantErr: "status",
		},
		{
			name: "status above response range",
			inv:  invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{
				Version:  ProtocolVersion,
				Action:   actionPtr(ActionContinue),
				Response: &ResponseMutation{StatusCode: &statusHigh},
			}),
			wantErr: "status",
		},
		{
			name: "invalid header name",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version: ProtocolVersion,
				Action:  actionPtr(ActionContinue),
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderSet, Name: "bad header", Value: &value,
				}}},
			}),
			wantErr: "invalid name",
		},
		{
			name: "pseudo header",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version: ProtocolVersion,
				Action:  actionPtr(ActionContinue),
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderSet, Name: ":path", Value: &value,
				}}},
			}),
			wantErr: "invalid name",
		},
		{
			name: "host header",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version: ProtocolVersion,
				Action:  actionPtr(ActionContinue),
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderSet, Name: "Host", Value: &value,
				}}},
			}),
			wantErr: "host",
		},
		{
			name: "unknown header operation",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version: ProtocolVersion,
				Action:  actionPtr(ActionContinue),
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderOperation("replace"), Name: "x-a", Value: &value,
				}}},
			}),
			wantErr: "operation",
		},
		{
			name: "set without value",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version: ProtocolVersion,
				Action:  actionPtr(ActionContinue),
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderSet, Name: "x-a",
				}}},
			}),
			wantErr: "value",
		},
		{
			name: "remove with value",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version: ProtocolVersion,
				Action:  actionPtr(ActionContinue),
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderRemove, Name: "x-a", Value: &value,
				}}},
			}),
			wantErr: "value",
		},
		{
			name: "invalid header value",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version: ProtocolVersion,
				Action:  actionPtr(ActionContinue),
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderSet, Name: "x-a", Value: &invalidHeaderValue,
				}}},
			}),
			wantErr: "header value",
		},
		{
			name: "non utf8 request replacement",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version: ProtocolVersion,
				Action:  actionPtr(ActionContinue),
				Request: &RequestMutation{Body: &nonUTF8},
			}),
			wantErr: "utf-8",
		},
		{
			name: "non utf8 response replacement",
			inv:  invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{
				Version:  ProtocolVersion,
				Action:   actionPtr(ActionContinue),
				Response: &ResponseMutation{Body: &nonUTF8},
			}),
			wantErr: "utf-8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.decision.Validate(tt.inv); err == nil || !strings.Contains(strings.ToLower(err.Error()), tt.wantErr) {
				t.Fatalf("Validate error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestDecisionValidateRejectsForbiddenHeaderNames covers the shared name policy
// a remote callout must obey, mirroring what headermutation enforces locally.
func TestDecisionValidateRejectsForbiddenHeaderNames(t *testing.T) {
	value := "value"
	const requestID = "req-123"
	for _, tc := range []struct {
		name      string
		operation HeaderOperation
		header    string
		wantErr   string
	}{
		{name: "x-envoy set", operation: HeaderSet, header: "X-Envoy-Foo", wantErr: "reserved by envoy"},
		{name: "x-envoy append", operation: HeaderAppend, header: "x-envoy-bar", wantErr: "reserved by envoy"},
		{name: "x-envoy remove", operation: HeaderRemove, header: "X-Envoy", wantErr: "reserved by envoy"},
		{name: "x-envoy no hyphen remove", operation: HeaderRemove, header: "x-envoyer", wantErr: "reserved by envoy"},
		{name: "connection set", operation: HeaderSet, header: "Connection", wantErr: "connection-scoped"},
		{name: "keep-alive append", operation: HeaderAppend, header: "Keep-Alive", wantErr: "connection-scoped"},
		{name: "proxy-connection remove", operation: HeaderRemove, header: "proxy-connection", wantErr: "connection-scoped"},
		{name: "upgrade remove", operation: HeaderRemove, header: "Upgrade", wantErr: "connection-scoped"},
		{name: "te remove", operation: HeaderRemove, header: "TE", wantErr: "connection-scoped"},
		{name: "trailer remove", operation: HeaderRemove, header: "Trailer", wantErr: "connection-scoped"},
		{name: "proxy-authenticate remove", operation: HeaderRemove, header: "Proxy-Authenticate", wantErr: "connection-scoped"},
		{name: "content-encoding remove", operation: HeaderRemove, header: "Content-Encoding", wantErr: "connection-scoped"},
		{name: "content-length set", operation: HeaderSet, header: "Content-Length", wantErr: "message framing"},
		{name: "content-length append", operation: HeaderAppend, header: "content-length", wantErr: "message framing"},
		{name: "transfer-encoding set", operation: HeaderSet, header: "Transfer-Encoding", wantErr: "message framing"},
		{name: "transfer-encoding append", operation: HeaderAppend, header: "transfer-encoding", wantErr: "message framing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutation := HeaderMutation{Operation: tc.operation, Name: tc.header}
			if tc.operation != HeaderRemove {
				mutation.Value = &value
			}
			decision := Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseRequest,
				RequestID: requestID,
				Action:    actionPtr(ActionContinue),
				Request:   &RequestMutation{Headers: []HeaderMutation{mutation}},
			}
			err := decision.Validate(invocationFor(PhaseRequest, requestID))
			if err == nil {
				t.Fatal("Validate succeeded, want an error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
			if !strings.Contains(err.Error(), "header mutation 0") {
				t.Errorf("error = %q, want it to name the offending index", err.Error())
			}
		})
	}
}

// A respond decision is rendered as an ext_proc ImmediateResponse, and Envoy
// applies those header mutations while the local reply holds only :status, which
// is itself unremovable; content-type and content-length arrive afterwards. A
// removal there can never reach a header, so it is rejected rather than accepted
// and silently ignored. A response-phase continue mutates the real upstream
// response, where removal works — that is the discriminator below.
func TestDecisionValidateRejectsRemovalsOnLocalResponses(t *testing.T) {
	status := 403
	const requestID = "req-123"
	removal := HeaderMutation{Operation: HeaderRemove, Name: "x-upstream"}

	for _, tc := range []struct {
		name  string
		phase Phase
	}{
		{name: "request-phase respond", phase: PhaseRequest},
		{name: "response-phase respond", phase: PhaseResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision := Decision{
				Version:   ProtocolVersion,
				Phase:     tc.phase,
				RequestID: requestID,
				Action:    actionPtr(ActionRespond),
				Response:  &ResponseMutation{StatusCode: &status, Headers: []HeaderMutation{removal}},
			}
			err := decision.Validate(invocationFor(tc.phase, requestID))
			if err == nil {
				t.Fatal("Validate succeeded, want an error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "local response") {
				t.Errorf("error = %q, want it to say the removal cannot reach a local response", err.Error())
			}
			if !strings.Contains(err.Error(), "header mutation 0") {
				t.Errorf("error = %q, want it to name the offending index", err.Error())
			}
		})
	}

	t.Run("response-phase continue keeps removals", func(t *testing.T) {
		decision := Decision{
			Version:   ProtocolVersion,
			Phase:     PhaseResponse,
			RequestID: requestID,
			Action:    actionPtr(ActionContinue),
			Response:  &ResponseMutation{Headers: []HeaderMutation{removal}},
		}
		if err := decision.Validate(invocationFor(PhaseResponse, requestID)); err != nil {
			t.Fatalf("Validate on an upstream response removal = %v, want nil", err)
		}
	})
}

func marshalJSONObject(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return unmarshalJSONObject(t, string(raw))
}

func unmarshalJSONObject(t *testing.T, raw string) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return value
}
