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
	"slices"
	"sort"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestSecurityProfileAttachment(t *testing.T) {
	profile := model.SecurityProfile{
		Name:      "http-only",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "app",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"client"},
			}}},
			Rules: []agentsv1alpha1.SecurityRule{{Match: []agentsv1alpha1.RuleMatch{{Schemes: []string{"http"}}}}},
		}}
	attachment, err := SecurityProfileAttachment(profile)
	if err != nil || attachment == nil {
		t.Fatalf("HTTP-only attachment: %v, %v", attachment, err)
	}
	if attachment.Name != "namespaced/demo/http-only" ||
		attachment.Priority != agentsv1alpha1.DefaultSecurityProfilePriority {
		t.Fatalf("unexpected attachment: %+v", attachment)
	}
	for _, tc := range []struct {
		namespace string
		app       string
		want      bool
	}{
		{"demo", "client", true}, {"other", "client", false}, {"demo", "other", false},
	} {
		if got := attachment.Selects(
			model.Workload{Namespace: tc.namespace, Labels: map[string]string{"app": tc.app}},
		); got != tc.want {
			t.Errorf("selection %+v = %v", tc, got)
		}
	}
	profile.Global, profile.Namespace = true, ""
	global, err := SecurityProfileAttachment(profile)
	if err != nil || global.Name != "global/http-only" ||
		!global.Selects(model.Workload{Namespace: "other", Labels: map[string]string{"app": "client"}}) {
		t.Fatalf("global attachment: %+v, %v", global, err)
	}

	profile.Spec.Priority = new(int32(-1))
	if _, err := SecurityProfileAttachment(profile); err == nil {
		t.Fatal("negative priority accepted")
	}
	profile.Spec.Priority = nil
	profile.Spec.Selector.MatchExpressions[0].Operator = "Invalid"
	if _, err := SecurityProfileAttachment(profile); err == nil {
		t.Fatal("invalid selector accepted")
	}
}

func TestSecurityProfileAttachmentOrder(t *testing.T) {
	profiles := []model.SecurityProfile{
		{Name: "same", Namespace: "demo"},
		{
			Name:      "specific",
			Namespace: "demo",
			Spec: agentsv1alpha1.SecurityProfileSpec{
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			},
		},
		{Name: "same", Global: true},
		{Name: "old", Namespace: "demo", CreationTime: time.Unix(-1, 0)},
		{Name: "first", Namespace: "demo", Spec: agentsv1alpha1.SecurityProfileSpec{Priority: new(int32(0))}},
		{Name: "same", Namespace: "another"},
	}
	var attachments []PolicyAttachment
	for _, profile := range profiles {
		if profile.CreationTime.IsZero() {
			profile.CreationTime = time.Unix(0, 0)
		}
		attachment, err := SecurityProfileAttachment(profile)
		if err != nil {
			t.Fatal(err)
		}
		attachments = append(attachments, *attachment)
	}
	sort.Slice(attachments, func(i, j int) bool { return policyAttachmentLess(attachments[i], attachments[j]) })
	var names []string
	for _, attachment := range attachments {
		names = append(names, attachment.Name)
	}
	want := []string{
		"namespaced/demo/first",
		"namespaced/demo/old",
		"global/same",
		"namespaced/another/same",
		"namespaced/demo/same",
		"namespaced/demo/specific",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("order %v, want %v", names, want)
	}
}

func TestCompileSecurityProfileWithoutSNI(t *testing.T) {
	profile := model.SecurityProfile{
		Name:      "http-only",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Rules: []agentsv1alpha1.SecurityRule{{Match: []agentsv1alpha1.RuleMatch{{Schemes: []string{"http"}}}}},
		},
	}
	compiled, err := CompileSecurityProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.ResourceName() != profile.ResourceName() || compiled.SNIPolicy != nil {
		t.Fatalf("expected a named profile without an SNI projection: %+v", compiled)
	}
	if compiled.PolicyAttachment() == nil {
		t.Fatal("shared profile has no binding metadata")
	}
}

func TestCompiledSecurityProfileEquality(t *testing.T) {
	base := CompiledSecurityProfile{Name: "namespaced/demo/http-only"}
	if !base.Equals(base) {
		t.Fatal("profiles without SNI or attachment must compare equal")
	}
	bound := base
	bound.Attachment = &PolicyAttachment{Kind: PolicyKindSecurityProfile, Name: base.Name}
	if base.Equals(bound) || bound.Equals(base) {
		t.Fatal("adding or removing binding metadata must change the profile")
	}
	clone := bound
	attachment := *bound.Attachment
	clone.Attachment = &attachment
	if !bound.Equals(clone) {
		t.Fatal("equivalent binding metadata must compare equal without SNI")
	}
	changed := bound
	changed.Name = "namespaced/demo/other"
	if bound.Equals(changed) {
		t.Fatal("resource identity must participate in equality")
	}
	changed = bound
	changed.SNIPolicy = &extensionsv1.SniTrafficPolicy{}
	if bound.Equals(changed) || changed.Equals(bound) {
		t.Fatal("adding or removing an SNI projection must change the profile")
	}
	clone = changed
	clone.SNIPolicy = &extensionsv1.SniTrafficPolicy{}
	if !changed.Equals(clone) {
		t.Fatal("equivalent SNI projections must compare equal")
	}
}
