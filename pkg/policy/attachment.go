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
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

const (
	globalPolicyAttachmentIndexKey     = "@global"
	namespacePolicyAttachmentKeyPrefix = "ns/"
	sandboxPolicyAttachmentKeyPrefix   = "uid/"
)

// PolicyKind identifies a typed consumer of the shared payload-free
// attachment projection.
type PolicyKind = model.PolicyKind

const (
	PolicyKindAuthorization = model.PolicyKindAuthorization
	PolicyKindEgressPolicy  = model.PolicyKindEgressPolicy
	PolicyKindSNIPolicy     = model.PolicyKindSNIPolicy
)

// AttachmentTarget describes selector-derived policy attachment (global, namespaces, or label selector).
type AttachmentTarget struct {
	// Kind restricts the payload consumer; empty allows both Workload and Sandbox.
	Kind       TargetKind
	Global     bool
	Namespaces []string
	SandboxUID string
	Selector   metav1.LabelSelector
}

// PolicyAttachment is the payload-free binding projection of a typed policy.
type PolicyAttachment struct {
	Kind            PolicyKind
	Name            string
	Target          AttachmentTarget
	Priority        int32
	CreationTime    time.Time
	SourceName      string
	SourceNamespace string

	// selector is compiled once at the producer boundary. Target.Selector is
	// its canonical source of truth and is the only form used for equality.
	selector labels.Selector
}

func (p PolicyAttachment) ResourceName() string {
	return (model.PolicyRef{
		Kind: p.Kind,
		Name: p.Name,
	}).ResourceName()
}

func (p PolicyAttachment) Equals(other PolicyAttachment) bool {
	return p.Kind == other.Kind &&
		p.Name == other.Name &&
		p.Target.Kind == other.Target.Kind &&
		p.Target.Global == other.Target.Global &&
		equalStrings(p.Target.Namespaces, other.Target.Namespaces) &&
		apiequality.Semantic.DeepEqual(p.Target.Selector, other.Target.Selector) &&
		p.Target.SandboxUID == other.Target.SandboxUID &&
		p.Priority == other.Priority &&
		p.CreationTime.Equal(other.CreationTime) &&
		p.SourceName == other.SourceName &&
		p.SourceNamespace == other.SourceNamespace
}

// NewPolicyAttachment validates and normalizes one immutable attachment.
func NewPolicyAttachment(attachment PolicyAttachment) (PolicyAttachment, error) {
	attachment.Target.Namespaces = append([]string(nil), attachment.Target.Namespaces...)
	attachment.Target.Selector = *attachment.Target.Selector.DeepCopy()
	if err := validateAttachmentValues("namespace", attachment.Target.Namespaces); err != nil {
		return PolicyAttachment{}, err
	}
	sort.Strings(attachment.Target.Namespaces)
	if err := attachment.validate(); err != nil {
		return PolicyAttachment{}, err
	}
	if attachment.selector == nil {
		selector, err := metav1.LabelSelectorAsSelector(&attachment.Target.Selector)
		if err != nil {
			return PolicyAttachment{}, fmt.Errorf("policy attachment %s selector: %w", attachment.Name, err)
		}
		attachment.selector = selector
	}
	return attachment, nil
}

func (p PolicyAttachment) validate() error {
	if err := (model.PolicyRef{
		Kind: p.Kind,
		Name: p.Name,
	}).Validate(); err != nil {
		return fmt.Errorf("policy attachment: %w", err)
	}
	if p.Target.Kind != "" && p.Target.Kind != PolicyTargetWorkload && p.Target.Kind != PolicyTargetSandbox {
		return fmt.Errorf("policy attachment %s has unknown target kind %q", p.Name, p.Target.Kind)
	}
	modes := 0
	if p.Target.Global {
		modes++
	}
	if len(p.Target.Namespaces) > 0 {
		modes++
	}
	if p.Target.SandboxUID != "" {
		modes++
		if _, err := policySandboxUID(p.Target.SandboxUID, p.Target.Selector); err != nil {
			return fmt.Errorf("policy attachment %s: %w", p.Name, err)
		}
	}
	if modes != 1 {
		return fmt.Errorf("policy attachment %s must use exactly one target mode", p.Name)
	}
	return nil
}

func validateAttachmentValues(kind string, values []string) error {
	seen := sets.NewWithLength[string](len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("policy attachment %s is empty", kind)
		}
		if seen.Contains(value) {
			return fmt.Errorf("policy attachment %s %q is duplicated", kind, value)
		}
		seen.Insert(value)
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func selectorEmpty(selector metav1.LabelSelector) bool {
	return len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0
}

func policySandboxUID(declared string, selector metav1.LabelSelector) (string, error) {
	selected, selectedSet := selector.MatchLabels[agentsv1alpha1.LabelSandboxID]
	if declared != "" && strings.TrimSpace(declared) != declared {
		return "", fmt.Errorf("sandbox UID %q contains surrounding whitespace", declared)
	}
	if selectedSet && (selected == "" || strings.TrimSpace(selected) != selected) {
		return "", fmt.Errorf("sandbox UID selector value %q is invalid", selected)
	}
	if declared != "" && selectedSet && declared != selected {
		return "", fmt.Errorf("sandbox UID %q conflicts with selector value %q", declared, selected)
	}
	if declared != "" {
		return declared, nil
	}
	return selected, nil
}

func containsString(values []string, value string) bool {
	_, found := slices.BinarySearch(values, value)
	return found
}

// Selects reports whether this attachment applies to the sandbox.
func (p PolicyAttachment) Selects(sandbox model.Sandbox) bool {
	return p.selects(PolicyTargetSandbox, sandbox.UID, sandbox.Namespace, sandbox.Labels)
}

func (p PolicyAttachment) selects(kind TargetKind, uid, namespace string, targetLabels map[string]string) bool {
	if p.Target.Kind != "" && p.Target.Kind != kind {
		return false
	}
	if p.Target.SandboxUID != "" && (kind != PolicyTargetSandbox || p.Target.SandboxUID != uid) {
		return false
	}
	if p.Target.SandboxUID == "" && !p.Target.Global && !containsString(p.Target.Namespaces, namespace) {
		return false
	}
	selector := p.selector
	if selector == nil {
		var err error
		selector, err = metav1.LabelSelectorAsSelector(&p.Target.Selector)
		if err != nil {
			return false
		}
	}
	return selector.Matches(labels.Set(targetLabels))
}

func (p PolicyAttachment) specificity() int {
	if p.Target.SandboxUID != "" {
		return 3
	}
	if !selectorEmpty(p.Target.Selector) {
		return 2
	}
	if len(p.Target.Namespaces) > 0 {
		return 1
	}
	return 0
}

func policyAttachmentLess(left, right PolicyAttachment) bool {
	if left.Priority != right.Priority {
		return left.Priority < right.Priority
	}
	if left.specificity() != right.specificity() {
		return left.specificity() > right.specificity()
	}
	if !left.CreationTime.Equal(right.CreationTime) {
		return left.CreationTime.Before(right.CreationTime)
	}
	if left.SourceName != right.SourceName {
		return left.SourceName < right.SourceName
	}
	if left.SourceNamespace != right.SourceNamespace {
		return left.SourceNamespace < right.SourceNamespace
	}
	return left.Name < right.Name
}
