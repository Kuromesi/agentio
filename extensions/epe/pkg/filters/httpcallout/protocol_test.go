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
			Body:        `{"input":"hi"}`,
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
			Body:        "request",
		},
		Response: &HTTPResponse{
			StatusCode:  200,
			ContentType: "text/plain",
			Headers:     map[string]string{},
			Body:        "response",
		},
	})
	request := got["request"].(map[string]any)
	if _, found := request["headers"]; found {
		t.Fatal("nil request headers were disclosed instead of omitted")
	}
	if got := request["contentType"]; got != "application/json; charset=utf-8" {
		t.Errorf("request contentType = %#v, want it preserved independently of headers", got)
	}
	response := got["response"].(map[string]any)
	if _, found := response["headers"]; !found {
		t.Fatal("response headers field was omitted")
	}
}

func TestInvocationValidateAcceptsPhaseShapes(t *testing.T) {
	tests := []Invocation{
		{
			Version: ProtocolVersion,
			Phase:   PhaseRequest,
			Request: &HTTPRequest{Body: "request"},
		},
		{
			Version:  ProtocolVersion,
			Phase:    PhaseResponse,
			Request:  &HTTPRequest{Body: "request"},
			Response: &HTTPResponse{StatusCode: 200, Headers: map[string]string{}, Body: "response"},
		},
	}
	for _, invocation := range tests {
		if err := invocation.Validate(); err != nil {
			t.Errorf("Validate(%s): %v", invocation.Phase, err)
		}
	}
}

func TestInvocationValidateRejectsInvalidContract(t *testing.T) {
	valid := Invocation{
		Version: ProtocolVersion,
		Phase:   PhaseRequest,
		Request: &HTTPRequest{Body: "request"},
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
			},
			wantErr: "response",
		},
		{
			name: "non utf8 request body",
			mutate: func(i *Invocation) {
				i.Request.Body = string([]byte{0xff})
			},
			wantErr: "utf-8",
		},
		{
			name: "non utf8 response body",
			mutate: func(i *Invocation) {
				i.Phase = PhaseResponse
				i.Response = &HTTPResponse{StatusCode: 200, Headers: map[string]string{}, Body: string([]byte{0xff})}
			},
			wantErr: "utf-8",
		},
		{
			name: "nil response headers",
			mutate: func(i *Invocation) {
				i.Phase = PhaseResponse
				i.Response = &HTTPResponse{StatusCode: 200}
			},
			wantErr: "headers",
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
		Action:    ActionContinue,
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
		Action:    ActionRespond,
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
		Action:   ActionRespond,
		Reason:   "secret detected",
		Response: &ResponseMutation{StatusCode: &status},
	})
	if withReason["reason"] != "secret detected" {
		t.Fatalf("reason = %#v, want it serialized", withReason["reason"])
	}

	withoutReason := marshalJSONObject(t, Decision{
		Version:  ProtocolVersion,
		Action:   ActionRespond,
		Response: &ResponseMutation{StatusCode: &status},
	})
	if _, found := withoutReason["reason"]; found {
		t.Fatal("empty reason was serialized instead of omitted")
	}
}

func TestDecisionDistinguishesOmittedAndEmptyBody(t *testing.T) {
	omitted := marshalJSONObject(t, Decision{
		Version: ProtocolVersion,
		Action:  ActionContinue,
		Request: &RequestMutation{},
	})
	if _, found := omitted["request"].(map[string]any)["body"]; found {
		t.Fatal("nil body was serialized instead of meaning unchanged")
	}

	empty := ""
	cleared := marshalJSONObject(t, Decision{
		Version: ProtocolVersion,
		Action:  ActionContinue,
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
		Request: &HTTPRequest{ID: requestID, Body: "request"},
	}
	if phase == PhaseResponse {
		inv.Response = &HTTPResponse{StatusCode: 200, Headers: map[string]string{}, Body: "response"}
	}
	return inv
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
				Action:    ActionContinue,
			},
		},
		{
			name:  "request mutation",
			phase: PhaseRequest,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseRequest,
				RequestID: requestID,
				Action:    ActionContinue,
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
				Action:    ActionContinue,
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
				Action:    ActionContinue,
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
				Action:    ActionRespond,
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
				Action:    ActionRespond,
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
				Action:    ActionRespond,
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
				Action:    ActionRespond,
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
				Action:    ActionRespond,
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
				Action:    ActionRespond,
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
				Action:    ActionContinue,
			},
		},
		{
			name:  "response mutation",
			phase: PhaseResponse,
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseResponse,
				RequestID: requestID,
				Action:    ActionContinue,
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
		Action:  ActionContinue,
	}
	if err := decision.Validate(invocationFor(PhaseRequest, "")); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestDecisionMarshalsRequestIDEvenWhenEmpty(t *testing.T) {
	got := marshalJSONObject(t, Decision{
		Version: ProtocolVersion,
		Phase:   PhaseRequest,
		Action:  ActionContinue,
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
			decision: echo(Phase("trailers"), Decision{Version: ProtocolVersion, Action: ActionContinue}),
			wantErr:  "phase",
		},
		{
			name:     "wrong version",
			inv:      invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{Version: "v2", Action: ActionContinue}),
			wantErr:  "version",
		},
		{
			name:     "unknown action",
			inv:      invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{Version: ProtocolVersion, Action: Action("allow")}),
			wantErr:  "action",
		},
		{
			name:     "mismatched phase echo",
			inv:      invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseResponse, Decision{Version: ProtocolVersion, Action: ActionContinue}),
			wantErr:  "phase",
		},
		{
			name:     "mismatched response phase echo",
			inv:      invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseRequest, Decision{Version: ProtocolVersion, Action: ActionContinue}),
			wantErr:  "phase",
		},
		{
			name:     "missing phase echo",
			inv:      invocationFor(PhaseRequest, requestID),
			decision: echo(Phase(""), Decision{Version: ProtocolVersion, Action: ActionContinue}),
			wantErr:  "phase",
		},
		{
			name: "mismatched request id echo",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: Decision{
				Version:   ProtocolVersion,
				Phase:     PhaseRequest,
				RequestID: "req-999",
				Action:    ActionContinue,
			},
			wantErr: "request id",
		},
		{
			name: "missing request id echo",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: Decision{
				Version: ProtocolVersion,
				Phase:   PhaseRequest,
				Action:  ActionContinue,
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
				Action:    ActionContinue,
			},
			wantErr: "request id",
		},
		{
			name: "response object on request continue",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
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
				Action:  ActionContinue,
				Request: &RequestMutation{},
			}),
			wantErr: "request",
		},
		{
			name:     "respond without response",
			inv:      invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{Version: ProtocolVersion, Action: ActionRespond}),
			wantErr:  "response",
		},
		{
			name:     "response-phase respond without response",
			inv:      invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{Version: ProtocolVersion, Action: ActionRespond}),
			wantErr:  "response",
		},
		{
			name: "respond without status",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version:  ProtocolVersion,
				Action:   ActionRespond,
				Response: &ResponseMutation{},
			}),
			wantErr: "status",
		},
		{
			name: "response-phase respond without status",
			inv:  invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{
				Version:  ProtocolVersion,
				Action:   ActionRespond,
				Response: &ResponseMutation{},
			}),
			wantErr: "status",
		},
		{
			name: "respond with request mutation",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version:  ProtocolVersion,
				Action:   ActionRespond,
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
				Action:   ActionRespond,
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
				Action:  ActionContinue,
				Reason:  "just so you know",
			}),
			wantErr: "reason",
		},
		{
			name: "response-phase continue with reason",
			inv:  invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
				Reason:  "just so you know",
			}),
			wantErr: "reason",
		},
		{
			name: "reason over the byte cap",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version:  ProtocolVersion,
				Action:   ActionRespond,
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
				Action:   ActionRespond,
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
				Action:   ActionRespond,
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
				Action:   ActionRespond,
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
				Action:   ActionContinue,
				Response: &ResponseMutation{StatusCode: &statusLow},
			}),
			wantErr: "status",
		},
		{
			name: "status above response range",
			inv:  invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{
				Version:  ProtocolVersion,
				Action:   ActionContinue,
				Response: &ResponseMutation{StatusCode: &statusHigh},
			}),
			wantErr: "status",
		},
		{
			name: "invalid header name",
			inv:  invocationFor(PhaseRequest, requestID),
			decision: echo(PhaseRequest, Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
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
				Action:  ActionContinue,
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
				Action:  ActionContinue,
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
				Action:  ActionContinue,
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
				Action:  ActionContinue,
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
				Action:  ActionContinue,
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
				Action:  ActionContinue,
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
				Action:  ActionContinue,
				Request: &RequestMutation{Body: &nonUTF8},
			}),
			wantErr: "utf-8",
		},
		{
			name: "non utf8 response replacement",
			inv:  invocationFor(PhaseResponse, requestID),
			decision: echo(PhaseResponse, Decision{
				Version:  ProtocolVersion,
				Action:   ActionContinue,
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
				Action:    ActionContinue,
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
				Action:    ActionRespond,
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
			Action:    ActionContinue,
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
