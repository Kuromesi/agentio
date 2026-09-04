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

package compiler

import (
	"reflect"
	"strings"
	"testing"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestNewWorkloadSandboxBindingsExtensionPreservesRuntimeNeutralBindings(t *testing.T) {
	workload := projectionTestWorkload()
	workload.SourceUID = "pod-activation-1"
	workload.SandboxBindings = []model.SandboxBinding{
		{SandboxUID: "sandbox-a"},
		{SandboxUID: "sandbox-b"},
	}

	extension, err := newWorkloadSandboxBindingsExtension(workload)
	if err != nil {
		t.Fatal(err)
	}
	if got := extension.GetName(); got != "sandbox-bindings" {
		t.Fatalf("extension name = %q, want sandbox-bindings", got)
	}
	bindings := &extensionsv1.WorkloadSandboxBindings{}
	if err := extension.GetConfig().UnmarshalTo(bindings); err != nil {
		t.Fatalf("unmarshal bindings: %v", err)
	}
	if got := bindings.GetSourceUid(); got != "pod-activation-1" {
		t.Fatalf("source UID = %q, want pod-activation-1", got)
	}
	want := []string{"sandbox-a", "sandbox-b"}
	got := make([]string, 0, len(bindings.GetSandboxes()))
	for _, binding := range bindings.GetSandboxes() {
		got = append(got, binding.GetSandboxUid())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sandbox bindings = %v, want %v", got, want)
	}
}

func TestBuildWDSAddressIncludesSandboxBindings(t *testing.T) {
	workload := projectionTestWorkload()
	workload.SourceUID = "pod-activation-1"
	resources, err := buildWDSAddress(wdsProjection{Workload: workload})
	if err != nil {
		t.Fatal(err)
	}
	address := &workloadv1.Address{}
	if err := resources[0].Value.UnmarshalTo(address); err != nil {
		t.Fatal(err)
	}
	var bindings *extensionsv1.WorkloadSandboxBindings
	for _, extension := range address.GetWorkload().GetExtensions() {
		if extension.GetName() != "sandbox-bindings" {
			continue
		}
		bindings = &extensionsv1.WorkloadSandboxBindings{}
		if err := extension.GetConfig().UnmarshalTo(bindings); err != nil {
			t.Fatalf("unmarshal bindings: %v", err)
		}
	}
	if bindings == nil {
		t.Fatal("sandbox-bindings extension is missing")
	}
	if got := bindings.GetSourceUid(); got != "pod-activation-1" {
		t.Fatalf("source UID = %q, want pod-activation-1", got)
	}
	if got := bindings.GetSandboxes(); len(got) != 1 || got[0].GetSandboxUid() != "sandbox-a" {
		t.Fatalf("sandbox bindings = %+v, want sandbox-a", got)
	}
}

func TestBuildWDSAddressPublishesCanonicalIdentity(t *testing.T) {
	workload := projectionTestWorkload()
	workload.CanonicalName = "client-api"
	workload.CanonicalRevision = "v2"

	resources, err := buildWDSAddress(wdsProjection{Workload: workload})
	if err != nil {
		t.Fatal(err)
	}
	address := &workloadv1.Address{}
	if err := resources[0].Value.UnmarshalTo(address); err != nil {
		t.Fatal(err)
	}
	if got := address.GetWorkload().GetCanonicalName(); got != "client-api" {
		t.Fatalf("canonical name = %q, want client-api", got)
	}
	if got := address.GetWorkload().GetCanonicalRevision(); got != "v2" {
		t.Fatalf("canonical revision = %q, want v2", got)
	}
}

func TestBuildWDSAddressPublishesDiscoveryOnlyWorkloadWithoutSandboxBinding(t *testing.T) {
	workload := projectionTestWorkload()
	workload.Principal = model.Principal{}
	workload.SandboxBindings = nil

	resources, err := buildWDSAddress(wdsProjection{Workload: workload})
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 {
		t.Fatalf("resources = %d, want one discovery-only Address", len(resources))
	}
	address := &workloadv1.Address{}
	if err := resources[0].Value.UnmarshalTo(address); err != nil {
		t.Fatal(err)
	}
	wireWorkload := address.GetWorkload()
	if wireWorkload == nil {
		t.Fatal("Address does not contain a Workload")
	}
	if got := wireWorkload.GetServiceAccount(); got != "" {
		t.Fatalf("service account = %q, want empty", got)
	}
	if got := extensionNames(wireWorkload.GetExtensions()); len(got) != 0 {
		t.Fatalf("extensions = %v, want none", got)
	}
	if resources[0].Facts.Workload == nil {
		t.Fatal("discovery-only Address lost its Workload facts")
	}
	if got := resources[0].Facts.Workload.SandboxUID; got != "" {
		t.Fatalf("sandbox UID fact = %q, want empty", got)
	}
}

func TestSingleSandboxBindingRejectsAmbiguousWorkloadProjection(t *testing.T) {
	for _, test := range []struct {
		name     string
		bindings []model.SandboxBinding
		want     bool
	}{
		{
			name: "none",
		},
		{
			name:     "empty",
			bindings: []model.SandboxBinding{{}},
		},
		{
			name: "one",
			bindings: []model.SandboxBinding{{
				SandboxUID: "sandbox-a",
			}},
			want: true,
		},
		{
			name: "multiple",
			bindings: []model.SandboxBinding{
				{SandboxUID: "sandbox-a"},
				{SandboxUID: "sandbox-b"},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := singleSandboxBinding(model.Workload{SandboxBindings: test.bindings})
			got := err == nil
			if got != test.want {
				t.Fatalf("singleSandboxBinding() valid = %v, want %v (error: %v)", got, test.want, err)
			}
		})
	}
}

func TestBuildPreservesEmptyNetworkAddressAlias(t *testing.T) {
	workload := projectionTestWorkload()
	resources, err := buildWDSAddress(wdsProjection{
		Workload: workload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 {
		t.Fatalf("resources = %d, want one canonical Address", len(resources))
	}
	for _, resource := range resources {
		if got, want := resource.Aliases, []string{"/10.0.0.1"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s aliases = %v, want %v", resource.Key.TypeURL, got, want)
		}
	}
}

func TestProjectWorkloadIdentityRejectsUnsupportedPrincipal(t *testing.T) {
	workload := projectionTestWorkload()
	workload.Principal = model.Principal{
		Kind:        "workload-v1",
		TrustDomain: "cluster.local",
	}
	_, _, err := projectWorkloadIdentity(workload)
	if err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("projectWorkloadIdentity() error = %v, want unsupported attester principal", err)
	}
}

func TestBuildRejectsServiceAccountNamespaceMismatch(t *testing.T) {
	workload := projectionTestWorkload()
	workload.Principal.ServiceAccount.Namespace = "other"
	_, err := buildWDSAddress(wdsProjection{Workload: workload})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("buildWDSAddress() error = %v, want namespace mismatch", err)
	}
}

func TestBuildProjectsHostNetworkMode(t *testing.T) {
	workload := projectionTestWorkload()
	workload.HostNetwork = true

	resources, err := buildWDSAddress(wdsProjection{
		Workload: workload,
	})
	if err != nil {
		t.Fatal(err)
	}
	address := &workloadv1.Address{}
	if err := resources[0].Value.UnmarshalTo(address); err != nil {
		t.Fatal(err)
	}
	if got := address.GetWorkload().GetNetworkMode(); got != workloadv1.NetworkMode_HOST_NETWORK {
		t.Fatalf("network mode = %v, want HOST_NETWORK", got)
	}
}

func TestBuildWDSAddressOmitsNodeSubjectWithoutPlacement(t *testing.T) {
	resources, err := buildWDSAddress(wdsProjection{Workload: projectionTestWorkload()})
	if err != nil {
		t.Fatal(err)
	}
	if resources[0].Facts.Workload == nil || resources[0].Facts.Workload.NodeName != "" {
		t.Fatalf("node-less workload facts = %+v", resources[0].Facts)
	}
	if !resources[0].IsWorkloadAddress() {
		t.Fatal("node-less workload must remain a workload address via its sandbox subject")
	}

	placed := projectionTestWorkload()
	placed.NodeName = "node-a"
	resources, err = buildWDSAddress(wdsProjection{Workload: placed})
	if err != nil {
		t.Fatal(err)
	}
	if resources[0].Facts.Workload == nil || resources[0].Facts.Workload.NodeName != "node-a" {
		t.Fatal("placed workload lost its node fact")
	}
}

func projectionTestWorkload() model.Workload {
	return model.Workload{
		UID:       "cluster//Pod/demo/client",
		Namespace: "demo",
		Name:      "client",
		Addresses: []string{"10.0.0.1"},
		Ready:     true,
		SandboxBindings: []model.SandboxBinding{
			{
				SandboxUID: "sandbox-a",
			},
		},
		Principal: model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      "demo",
				ServiceAccount: "client",
			},
		},
	}
}
