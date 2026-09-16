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

package policy

import (
	"strings"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestCompileSNIProfileSandboxUIDAssociation(t *testing.T) {
	for _, test := range []struct {
		name        string
		declaredUID string
		selectedUID *string
		wantUID     string
		wantErr     bool
	}{
		{
			name:        "canonical UID",
			declaredUID: "kruise:sandbox-a",
			wantUID:     "kruise:sandbox-a",
		},
		{
			name:        "selector does not infer UID",
			selectedUID: stringPtr("sandbox-a"),
		},
		{
			name:        "canonical UID with raw selector",
			declaredUID: "kruise:sandbox-a",
			selectedUID: stringPtr("sandbox-a"),
			wantUID:     "kruise:sandbox-a",
		},
		{
			name:        "UID and selector are independent constraints",
			declaredUID: "workload:instance-a",
			selectedUID: stringPtr("sandbox-a"),
			wantUID:     "workload:instance-a",
		},
		{
			name:        "declared whitespace",
			declaredUID: "kruise:sandbox-a ",
			wantErr:     true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			selector := map[string]string{}
			if test.selectedUID != nil {
				selector[agentsv1alpha1.LabelSandboxID] = *test.selectedUID
			}
			compiled, err := CompileSNIProfile(model.SecurityProfile{
				Name:       "profile",
				Namespace:  "demo",
				SandboxUID: test.declaredUID,
				Spec:       securitySpec(nil, selector),
			})
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "sandbox UID") {
					t.Fatalf("CompileSNIProfile() error = %v, want sandbox UID error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CompileSNIProfile(): %v", err)
			}
			attachment := compiled.PolicyAttachment()
			if attachment == nil || attachment.Target.SandboxUID != test.wantUID {
				t.Fatalf("compiled/attachment = %+v / %+v, want exact Sandbox UID %q", compiled, attachment, test.wantUID)
			}
		})
	}
}

func TestCompileSNIProfileNormalizesHTTPSDomains(t *testing.T) {
	priority := int32(10)
	compiled, err := CompileSNIProfile(model.SecurityProfile{
		Name:      "profile",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Priority: &priority,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Rules: []agentsv1alpha1.SecurityRule{{
				Name: "hosts",
				Match: []agentsv1alpha1.RuleMatch{
					{Domains: []string{"API.Example.COM.", "*.Example.com", "api.example.com"}, Schemes: []string{"HTTPS"}},
					{Domains: []string{"http-only.example.com"}, Schemes: []string{"http"}},
				},
			}},
		},
	})
	if err != nil {
		t.Fatalf("compile SNI profiles: %v", err)
	}
	if compiled == nil || compiled.ResourceName() != "demo/profile" {
		t.Fatalf("compiled profiles = %+v", compiled)
	}
	got := compiled.Policy.GetRules()[0]
	want := []string{"api.example.com", "*.example.com"}
	if got.GetAction() != extensionsv1.SniAction_SNI_ACTION_TLS_TERMINATION || len(got.GetMatch().GetSni()) != len(want) {
		t.Fatalf("SNI rule = %+v", got)
	}
	for i := range want {
		if got.GetMatch().GetSni()[i] != want[i] {
			t.Fatalf("SNI hosts = %v, want %v", got.GetMatch().GetSni(), want)
		}
	}
}

func TestCompileSNIProfileRejectsPartialWildcard(t *testing.T) {
	_, err := CompileSNIProfile(model.SecurityProfile{
		Name:      "bad",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{
			Name:  "bad",
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*foo.example.com"}}},
		}}},
	})
	if err == nil {
		t.Fatal("partial wildcard was accepted")
	}
}

func securitySpec(priority *int32, selector map[string]string) agentsv1alpha1.SecurityProfileSpec {
	return agentsv1alpha1.SecurityProfileSpec{
		Priority: priority,
		Selector: metav1.LabelSelector{MatchLabels: selector},
		Rules:    []agentsv1alpha1.SecurityRule{{Name: "rule", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}}}},
	}
}
