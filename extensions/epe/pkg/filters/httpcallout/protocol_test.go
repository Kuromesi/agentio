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
		Version: ProtocolVersion,
		Action:  ActionContinue,
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
		Version: ProtocolVersion,
		Action:  ActionRespond,
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

func TestDecisionValidateAcceptsPhaseContracts(t *testing.T) {
	headerValue := "value"
	status := 201
	empty := ""
	tests := []struct {
		name     string
		phase    Phase
		decision Decision
	}{
		{
			name:  "request no-op",
			phase: PhaseRequest,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
			},
		},
		{
			name:  "request mutation",
			phase: PhaseRequest,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
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
			name:  "request respond",
			phase: PhaseRequest,
			decision: Decision{
				Version:  ProtocolVersion,
				Action:   ActionRespond,
				Response: &ResponseMutation{StatusCode: &status},
			},
		},
		{
			name:  "response no-op",
			phase: PhaseResponse,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
			},
		},
		{
			name:  "response mutation",
			phase: PhaseResponse,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
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
			if err := tt.decision.Validate(tt.phase); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestDecisionValidateRejectsInvalidContract(t *testing.T) {
	value := "value"
	statusOK := 200
	statusLow := 199
	statusHigh := 600
	nonUTF8 := string([]byte{0xff})
	invalidHeaderValue := "safe\r\nx-injected: value"
	tests := []struct {
		name     string
		phase    Phase
		decision Decision
		wantErr  string
	}{
		{
			name:     "unknown phase",
			phase:    Phase("trailers"),
			decision: Decision{Version: ProtocolVersion, Action: ActionContinue},
			wantErr:  "phase",
		},
		{
			name:     "wrong version",
			phase:    PhaseRequest,
			decision: Decision{Version: "v2", Action: ActionContinue},
			wantErr:  "version",
		},
		{
			name:     "unknown action",
			phase:    PhaseRequest,
			decision: Decision{Version: ProtocolVersion, Action: Action("allow")},
			wantErr:  "action",
		},
		{
			name:  "response object on request continue",
			phase: PhaseRequest,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
				Response: &ResponseMutation{
					StatusCode: &statusOK,
				},
			},
			wantErr: "response",
		},
		{
			name:  "request object on response continue",
			phase: PhaseResponse,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
				Request: &RequestMutation{},
			},
			wantErr: "request",
		},
		{
			name:  "respond during response phase",
			phase: PhaseResponse,
			decision: Decision{
				Version:  ProtocolVersion,
				Action:   ActionRespond,
				Response: &ResponseMutation{StatusCode: &statusOK},
			},
			wantErr: "response phase",
		},
		{
			name:     "respond without response",
			phase:    PhaseRequest,
			decision: Decision{Version: ProtocolVersion, Action: ActionRespond},
			wantErr:  "response",
		},
		{
			name:  "respond without status",
			phase: PhaseRequest,
			decision: Decision{
				Version:  ProtocolVersion,
				Action:   ActionRespond,
				Response: &ResponseMutation{},
			},
			wantErr: "status",
		},
		{
			name:  "respond with request mutation",
			phase: PhaseRequest,
			decision: Decision{
				Version:  ProtocolVersion,
				Action:   ActionRespond,
				Request:  &RequestMutation{},
				Response: &ResponseMutation{StatusCode: &statusOK},
			},
			wantErr: "request",
		},
		{
			name:  "status below final response range",
			phase: PhaseResponse,
			decision: Decision{
				Version:  ProtocolVersion,
				Action:   ActionContinue,
				Response: &ResponseMutation{StatusCode: &statusLow},
			},
			wantErr: "status",
		},
		{
			name:  "status above response range",
			phase: PhaseResponse,
			decision: Decision{
				Version:  ProtocolVersion,
				Action:   ActionContinue,
				Response: &ResponseMutation{StatusCode: &statusHigh},
			},
			wantErr: "status",
		},
		{
			name:  "invalid header name",
			phase: PhaseRequest,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderSet, Name: "bad header", Value: &value,
				}}},
			},
			wantErr: "header name",
		},
		{
			name:  "pseudo header",
			phase: PhaseRequest,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderSet, Name: ":path", Value: &value,
				}}},
			},
			wantErr: "header name",
		},
		{
			name:  "host header",
			phase: PhaseRequest,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderSet, Name: "Host", Value: &value,
				}}},
			},
			wantErr: "host",
		},
		{
			name:  "unknown header operation",
			phase: PhaseRequest,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderOperation("replace"), Name: "x-a", Value: &value,
				}}},
			},
			wantErr: "operation",
		},
		{
			name:  "set without value",
			phase: PhaseRequest,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderSet, Name: "x-a",
				}}},
			},
			wantErr: "value",
		},
		{
			name:  "remove with value",
			phase: PhaseRequest,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderRemove, Name: "x-a", Value: &value,
				}}},
			},
			wantErr: "value",
		},
		{
			name:  "invalid header value",
			phase: PhaseRequest,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
				Request: &RequestMutation{Headers: []HeaderMutation{{
					Operation: HeaderSet, Name: "x-a", Value: &invalidHeaderValue,
				}}},
			},
			wantErr: "header value",
		},
		{
			name:  "non utf8 request replacement",
			phase: PhaseRequest,
			decision: Decision{
				Version: ProtocolVersion,
				Action:  ActionContinue,
				Request: &RequestMutation{Body: &nonUTF8},
			},
			wantErr: "utf-8",
		},
		{
			name:  "non utf8 response replacement",
			phase: PhaseResponse,
			decision: Decision{
				Version:  ProtocolVersion,
				Action:   ActionContinue,
				Response: &ResponseMutation{Body: &nonUTF8},
			},
			wantErr: "utf-8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.decision.Validate(tt.phase); err == nil || !strings.Contains(strings.ToLower(err.Error()), tt.wantErr) {
				t.Fatalf("Validate error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
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
