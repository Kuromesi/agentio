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
	"reflect"
	"testing"

	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

// TestAuditScopeActivationShadowsResult is the shadow guard: audit.Scope
// MUST override the embedded inputs.Scope.Activation so the audit-only
// `result` variable is exposed to CEL. The current audit activation does
// NOT expose a `matched` variable (the CEL when-env only declares
// result/request/pod/profile/rule), so this guard also pins its absence.
func TestAuditScopeActivationShadowsResult(t *testing.T) {
	s := &Scope{Result: "blocked"}
	act, release := s.Activation()
	defer release()
	tests := []struct {
		name    string
		key     string
		present bool
		want    any
	}{
		{name: "result present", key: "result", present: true, want: "blocked"},
		{name: "matched absent", key: "matched", present: false},
		{name: "request present", key: "request", present: true},
		{name: "pod present", key: "pod", present: true},
		{name: "profile present", key: "profile", present: true},
		{name: "rule present", key: "rule", present: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, ok := act[tt.key]
			if ok != tt.present {
				t.Fatalf("key %q presence: want %v, got %v", tt.key, tt.present, ok)
			}
			if tt.want != nil && v != tt.want {
				t.Errorf("key %q: want %v, got %v", tt.key, tt.want, v)
			}
		})
	}
}

// TestScopeActivation_AllFieldsPopulated proves Scope.Activation carries
// the expected variable shapes for every scope field.
func TestScopeActivation_AllFieldsPopulated(t *testing.T) {
	s := &Scope{
		Scope: inputs.Scope{
			Request: inputs.RequestFrom(httpreq.HTTPRequest{Host: "example.com", Port: 443, Path: "/api/v1/data", Scheme: "https", Method: "POST", Query: map[string][]string{"tag": {"urgent"}}, Headers: map[string]string{"x-request-id": "abc"}}),
			Pod: inputs.Pod{
				Name:      "agent-1",
				Namespace: "default",
				IP:        "10.0.0.5",
				Labels:    map[string]string{"app": "ai"},
			},
			Profile: inputs.Profile{Name: "p1", Namespace: "ns"},
			Rule:    inputs.Rule{Name: "r1"},
		},
		Result: "blocked",
	}

	act, release := s.Activation()
	defer release()

	// Verify top-level result.
	if act["result"] != "blocked" {
		t.Errorf("result: want blocked, got %v", act["result"])
	}

	// Verify request map.
	reqMap := act["request"].(map[string]any)
	if reqMap["host"] != "example.com" {
		t.Errorf("request.host: %v", reqMap["host"])
	}
	if reqMap["port"] != int64(443) {
		t.Errorf("request.port: %v", reqMap["port"])
	}
	if reqMap["path"] != "/api/v1/data" {
		t.Errorf("request.path: %v", reqMap["path"])
	}
	if reqMap["method"] != "POST" {
		t.Errorf("request.method: %v", reqMap["method"])
	}
	if reqMap["scheme"] != "https" {
		t.Errorf("request.scheme: %v", reqMap["scheme"])
	}

	headers := reqMap["headers"].(map[string]string)
	if headers["x-request-id"] != "abc" {
		t.Errorf("headers: %v", headers)
	}

	qp := reqMap["queryParams"].(map[string]string)
	if qp["tag"] != "urgent" {
		t.Errorf("queryParams: %v", qp)
	}

	// Verify pod map.
	podMap := act["pod"].(map[string]any)
	if podMap["name"] != "agent-1" {
		t.Errorf("pod.name: %v", podMap["name"])
	}
	if podMap["namespace"] != "default" {
		t.Errorf("pod.namespace: %v", podMap["namespace"])
	}
	if podMap["ip"] != "10.0.0.5" {
		t.Errorf("pod.ip: %v", podMap["ip"])
	}
	labels := podMap["labels"].(map[string]string)
	if labels["app"] != "ai" {
		t.Errorf("labels: %v", labels)
	}

	// Verify profile map.
	profileMap := act["profile"].(map[string]string)
	if profileMap["name"] != "p1" || profileMap["namespace"] != "ns" {
		t.Errorf("profile: %v", profileMap)
	}

	// Verify rule map.
	ruleMap := act["rule"].(map[string]string)
	if ruleMap["name"] != "r1" {
		t.Errorf("rule: %v", ruleMap)
	}
}

// TestScope_MatchedCriteriaAccessor pins the template-compatibility
// accessor: documented webhook templates reference {{ .MatchedCriteria.* }},
// which must keep rendering via MatchedCriteria.
func TestScope_MatchedCriteriaAccessor(t *testing.T) {
	s := &Scope{Matched: Match{Host: "example.com", Method: "GET"}}
	got := s.MatchedCriteria()
	if !reflect.DeepEqual(s.Matched, got) {
		t.Errorf("MatchedCriteria: want %+v, got %+v", s.Matched, got)
	}
}
