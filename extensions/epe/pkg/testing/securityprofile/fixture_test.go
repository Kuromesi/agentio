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

package securityprofile

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

const tokenTransformationProfileYAML = `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: token-transformation
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: transform
    match:
    - domains:
      - example.com
    actions:
      block: {}
      tokenTransformation:
        credentialRef:
          kind: Secret
          name: validation-credential
          namespace: external-credentials
        apiKey:
          valueTemplate: 'Bearer {{ .Token }}'
`

const inputsAndTypedCredentialProfileYAML = `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: typed-credential
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  inputs:
  - name: routing
    configMap:
      name: credential-routing
  rules:
  - name: transform
    match:
    - domains: [example.com]
    actions:
      tokenTransformation:
        credentialRef:
          credentialProvider:
            name: provider
            parameters:
              tenant:
                cel: inputs["routing"][request.host]
        apiKey:
          valueTemplate: 'Bearer {{ .Token }}'
`

func TestFixture_AcceptsInputsAndTypedCredentialParameters(t *testing.T) {
	if err := NewFixture(t).ValidateYAML(inputsAndTypedCredentialProfileYAML); err != nil {
		t.Fatalf("valid inputs/typed credential profile rejected: %v", err)
	}
}

// TestFixture_AdmissionPreservesCredentialRefNamespace mirrors the E2E
// apiserver accept case: the profile passes validation, defaulting fills
// priority, and the credentialRef namespace survives the round trip.
func TestFixture_AdmissionPreservesCredentialRefNamespace(t *testing.T) {
	f := NewFixture(t)
	if err := f.ValidateYAML(tokenTransformationProfileYAML); err != nil {
		t.Fatalf("valid tokenTransformation profile rejected: %v", err)
	}

	un, err := parseProfileDocument(tokenTransformationProfileYAML)
	if err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	schemas, err := loadSchemas()
	if err != nil {
		t.Fatalf("load CRD schemas: %v", err)
	}
	if err := schemas.applyDefaults(un); err != nil {
		t.Fatalf("apply defaults: %v", err)
	}

	sp := &v1alpha1.SecurityProfile{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.Object, sp); err != nil {
		t.Fatalf("convert to typed: %v", err)
	}
	if sp.Spec.Priority == nil || *sp.Spec.Priority != v1alpha1.DefaultSecurityProfilePriority {
		t.Errorf("defaulted priority = %v, want %d", sp.Spec.Priority, v1alpha1.DefaultSecurityProfilePriority)
	}
	if sp.Spec.Rules[0].Actions.TokenTransformation == nil {
		t.Fatal("tokenTransformation lost in round trip")
	}

	ref := sp.Spec.Rules[0].Actions.TokenTransformation.CredentialRef
	if ref.Namespace != "external-credentials" {
		t.Errorf("credentialRef namespace = %q, want external-credentials", ref.Namespace)
	}
}

// TestFixture_CRDPriorityDefaultMatchesAPIConstant guards against the
// checked-in CRD manifest drifting from the agents-api marker: the
// structural schema default for spec.priority must equal the Go constant.
func TestFixture_CRDPriorityDefaultMatchesAPIConstant(t *testing.T) {
	schemas, err := loadSchemas()
	if err != nil {
		t.Fatalf("load CRD schemas: %v", err)
	}
	for _, kind := range []string{kindSecurityProfile, kindGlobalSecurityProfile} {
		gvk := schema.GroupVersionKind{Group: "agents.kruise.io", Version: "v1alpha1", Kind: kind}
		structural, ok := schemas.structural[gvk]
		if !ok {
			t.Fatalf("no structural schema for %v", gvk)
		}
		priority, ok := structural.Properties["spec"].Properties["priority"]
		if !ok {
			t.Fatalf("%s: spec.priority missing from CRD schema", kind)
		}
		var got int64
		switch v := priority.Default.Object.(type) {
		case int64:
			got = v
		case float64:
			got = int64(v)
		default:
			t.Fatalf("%s: spec.priority default = %T(%v), want a number", kind, v, v)
		}
		if got != int64(v1alpha1.DefaultSecurityProfilePriority) {
			t.Errorf("%s: CRD priority default = %d, want %d (agents-api constant)",
				kind, got, v1alpha1.DefaultSecurityProfilePriority)
		}
	}
}
