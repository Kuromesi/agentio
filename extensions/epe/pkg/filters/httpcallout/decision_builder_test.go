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
	"testing"
)

func TestDecisionBuilderWireContract(t *testing.T) {
	for _, tc := range []struct {
		name    string
		builder *DecisionBuilder
		want    string
	}{
		{
			name:    "minimal",
			builder: Continue(PhaseRequest),
			want:    `{"version":"0.1"}`,
		},
		{
			name: "request mutations",
			builder: Continue(PhaseRequest).
				SetHeader("x-verdict", "allowed").
				AppendHeader("x-tag", "").
				RemoveHeader("x-old").Body(""),
			want: `{"version":"0.1","request":{"headers":[{"operation":"set","name":"x-verdict","value":"allowed"},{"operation":"append","name":"x-tag","value":""},{"operation":"remove","name":"x-old"}],"body":""}}`,
		},
		{
			name:    "response mutations",
			builder: Continue(PhaseResponse).SetHeader("x-verdict", "allowed").StatusCode(201).Body("changed"),
			want:    `{"version":"0.1","response":{"statusCode":201,"headers":[{"operation":"set","name":"x-verdict","value":"allowed"}],"body":"changed"}}`,
		},
		{
			name:    "deny request",
			builder: Respond(PhaseRequest, 403).Reason("blocked_destination").Body("blocked"),
			want:    `{"version":"0.1","action":"respond","reason":"blocked_destination","response":{"statusCode":403,"body":"blocked"}}`,
		},
		{
			name:    "deny response",
			builder: Respond(PhaseResponse, 403).SetHeader("content-type", "text/plain").Body("blocked"),
			want:    `{"version":"0.1","action":"respond","response":{"statusCode":403,"headers":[{"operation":"set","name":"content-type","value":"text/plain"}],"body":"blocked"}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := tc.builder.Build()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != tc.want {
				t.Fatalf("got %s; want %s", raw, tc.want)
			}
		})
	}
}

func TestDecisionBuilderRejectsInvalidDecisions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		builder *DecisionBuilder
	}{
		{"unknown phase", Continue("unknown")},
		{"request status", Continue(PhaseRequest).StatusCode(201)},
		{"continue reason", Continue(PhaseResponse).Reason("denied")},
		{"invalid status", Respond(PhaseRequest, 99)},
		{"local removal", Respond(PhaseResponse, 403).RemoveHeader("x-old")},
		{"invalid header", Continue(PhaseRequest).SetHeader("x-test", "bad\r\nvalue")},
		{"invalid body", Continue(PhaseResponse).Body(string([]byte{0xff}))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.builder.Build(); err == nil {
				t.Fatal("invalid decision accepted")
			}
		})
	}
}

func TestDecisionBuilderPreservesPreviousBuild(t *testing.T) {
	b := Continue(PhaseResponse).SetHeader("x-first", "one").Body("first").StatusCode(200)
	first, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.SetHeader("x-second", "two").Body("second").StatusCode(201).Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Response.Headers) != 1 || *first.Response.Body != "first" || *first.Response.StatusCode != 200 {
		t.Fatalf("previous build changed: %+v", first.Response)
	}
	second.Response.Headers[0].Name = "x-changed"
	if first.Response.Headers[0].Name != "x-first" {
		t.Fatal("builds share header storage")
	}
}
