// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package processor

import (
	"context"
	"errors"
	"testing"

	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	extensions "github.com/openkruise/agentio/api/extensions/v1"
	sandbox "github.com/openkruise/agentio/api/sandbox/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

const testUID = "Kubernetes//Pod/demo/client"

type memorySource struct {
	values map[string]*anypb.Any
	calls  []string
	err    error
}

func (s *memorySource) Demand(_ context.Context, typ, name string) (*xdsclient.Resource, error) {
	s.calls = append(s.calls, typ+"/"+name)
	if s.err != nil {
		return nil, s.err
	}
	value := s.values[typ+"/"+name]
	if value == nil {
		return nil, xdsclient.ErrNotFound
	}
	for _, watch := range Watches() {
		if watch.TypeURL == typ {
			view, err := watch.Transform(value)
			return &xdsclient.Resource{Value: view}, err
		}
	}
	return nil, errors.New("unexpected resource type")
}
func pack(t *testing.T, value proto.Message) *anypb.Any {
	t.Helper()
	a, err := anypb.New(value)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func sniPolicy(t *testing.T, pattern string, action extensions.SniAction) *anypb.Any {
	return pack(
		t,
		&extensions.SniTrafficPolicy{
			Rules: []*extensions.SniRule{{Match: &extensions.SniMatch{Sni: []string{pattern}}, Action: action}},
		},
	)
}
func sourceWorkload(t *testing.T, policy *anypb.Any) *anypb.Any {
	w := &workload.Workload{Uid: testUID, Name: "client", Namespace: "demo"}
	if policy != nil {
		w.Extensions = []*workload.Extension{{Name: "sni", Config: policy}}
	}
	return pack(t, w)
}
func action(result Result) string {
	tls, _ := result.Metadata["tls"].(map[string]any)
	value, _ := tls["action"].(string)
	return value
}
func TestPolicyDecisions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		sni     string
		want    string
		mode    extensions.SniAction
		deny    bool
	}{
		{"exact", "api.example.com", "api.example.com", "terminate", extensions.SniAction_SNI_ACTION_TLS_TERMINATION, false},
		{"wildcard", "*.example.com", "nested.api.example.com", "terminate", extensions.SniAction_SNI_ACTION_TLS_TERMINATION, false},
		{"apex excluded", "*.example.com", "example.com", "passthrough", extensions.SniAction_SNI_ACTION_TLS_TERMINATION, false},
		{"boundary", "*.example.com", "notexample.com", "passthrough", extensions.SniAction_SNI_ACTION_TLS_TERMINATION, false},
		{"any", "*", "elsewhere.com", "terminate", extensions.SniAction_SNI_ACTION_TLS_TERMINATION, false},
		{"passthrough", "api.example.com", "api.example.com", "passthrough", extensions.SniAction_SNI_ACTION_PASSTHROUGH, false},
		{"deny", "api.example.com", "api.example.com", "", extensions.SniAction_SNI_ACTION_DENY, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &memorySource{
				values: map[string]*anypb.Any{
					model.WorkloadType + "/" + testUID: sourceWorkload(t, sniPolicy(t, tc.pattern, tc.mode)),
				},
			}
			result, err := NewPolicyHandler(
				source,
				"Kubernetes",
			).Handle(
				t.Context(),
				Request{
					Source:  Source{Workload: WorkloadIdentity{Name: "client", Namespace: "demo"}},
					Headers: ConnectHeaders{SNI: tc.sni},
				},
			)
			if err != nil || action(result) != tc.want ||
				(result.DenyStatus == envoytype.StatusCode_Forbidden) != tc.deny {
				t.Fatalf("got %+v, %v", result, err)
			}
			if len(source.calls) != 1 {
				t.Fatalf("demands: %v", source.calls)
			}
		})
	}
}
func TestSandboxBindingAndMissingResources(t *testing.T) {
	for _, tc := range []struct {
		name            string
		host            string
		missingWorkload bool
		missingSandbox  bool
		want            string
		deny            bool
	}{
		{name: "owned", host: testUID, want: "terminate"},
		{name: "wrong host", host: "another", deny: true},
		{name: "unassigned", deny: true},
		{name: "deleted sandbox", missingSandbox: true, deny: true},
		{name: "deleted workload", missingWorkload: true, deny: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]*anypb.Any{}
			if !tc.missingWorkload {
				values[model.WorkloadType+"/"+testUID] = sourceWorkload(t, nil)
			}
			if !tc.missingSandbox {
				values[model.SandboxType+"/kruise:one"] = pack(
					t,
					&sandbox.Sandbox{
						Uid:      "kruise:one",
						Attester: &sandbox.Sandbox_Attester{WorkloadUid: tc.host},
						Extensions: []*anypb.Any{
							sniPolicy(t, "*.example.com", extensions.SniAction_SNI_ACTION_TLS_TERMINATION),
						},
					},
				)
			}
			got, err := NewPolicyHandler(
				&memorySource{values: values},
				"Kubernetes",
			).Handle(
				t.Context(),
				Request{
					Source: Source{
						Workload:  WorkloadIdentity{Name: "client", Namespace: "demo"},
						SandboxID: "kruise:one",
					},
					Headers: ConnectHeaders{SNI: "api.example.com"},
				},
			)
			if err != nil || action(got) != tc.want || (got.DenyStatus != 0) != tc.deny {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}
func TestNoSNIAndDemandFailure(t *testing.T) {
	source := &memorySource{err: errors.New("ADS unavailable")}
	handler := NewPolicyHandler(source, "Kubernetes")
	got, err := handler.Handle(t.Context(), Request{})
	if err != nil || got.Metadata != nil || got.DenyStatus != 0 || len(source.calls) != 0 {
		t.Fatalf("no SNI: %+v, %v, %v", got, err, source.calls)
	}
	got, err = handler.Handle(t.Context(), Request{Headers: ConnectHeaders{SNI: "api.example.com"}})
	if err != nil || got.DenyStatus != envoytype.StatusCode_Forbidden {
		t.Fatalf("missing identity: %+v %v", got, err)
	}
	_, err = handler.Handle(
		t.Context(),
		Request{
			Source:  Source{Workload: WorkloadIdentity{Name: "client", Namespace: "demo"}},
			Headers: ConnectHeaders{SNI: "api.example.com"},
		},
	)
	if !errors.Is(err, source.err) {
		t.Fatalf("demand failure swallowed: %v", err)
	}
}
