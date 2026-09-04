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

package model

import "testing"

func TestNormalizedObjectResourceNames(t *testing.T) {
	sandbox := Sandbox{UID: "pod-uid"}
	if got := sandbox.ResourceName(); got != "pod-uid" {
		t.Fatalf("sandbox name = %q", got)
	}
	service := Service{Namespace: "demo", Hostname: "api.demo.svc.cluster.local"}
	if got := service.ResourceName(); got != "demo/api.demo.svc.cluster.local" {
		t.Fatalf("service name = %q", got)
	}
	endpoint := Endpoint{ServiceKey: service.ResourceName(), Address: "10.0.0.1", Port: 8080}
	if got := endpoint.ResourceName(); got != "demo/api.demo.svc.cluster.local/10.0.0.1:8080" {
		t.Fatalf("endpoint name = %q", got)
	}
	gateway := Gateway{Namespace: "agentio-system", Name: "egress"}
	if got := gateway.ResourceName(); got != "agentio-system/egress" {
		t.Fatalf("gateway name = %q", got)
	}
}

func TestEndpointTargetRefMakesHostNetworkIdentityUnique(t *testing.T) {
	base := Endpoint{
		ServiceKey: "demo/api.demo.svc.cluster.local", SourceKey: "demo/api-abc",
		Address: "10.0.0.1", PortName: "http", Port: 8080, HasTargetRef: true,
	}
	podA := base
	podA.TargetUID = "pod-a-uid"
	podA.TargetNamespace = "demo"
	podA.TargetName = "pod-a"
	podB := base
	podB.TargetUID = "pod-b-uid"
	podB.TargetNamespace = "demo"
	podB.TargetName = "pod-b"

	if podA.ResourceName() == podB.ResourceName() {
		t.Fatalf("targetRef endpoints collide: %q", podA.ResourceName())
	}
}
