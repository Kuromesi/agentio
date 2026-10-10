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
	"maps"
	"slices"
	"sort"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// BindingGroup contains the ordered resource names for one typed policy
// consumer.
type BindingGroup struct {
	Kind  PolicyKind
	Names []string
}

// Bindings contains the ordered policy references for one policy target.
type Bindings struct {
	TargetUID string
	Groups    []BindingGroup
}

// ResourceName identifies the target whose policy references are resolved.
func (b Bindings) ResourceName() string { return b.TargetUID }

// Equals compares ordered policy references.
func (b Bindings) Equals(other Bindings) bool {
	if b.TargetUID != other.TargetUID || len(b.Groups) != len(other.Groups) {
		return false
	}
	for index := range b.Groups {
		if b.Groups[index].Kind != other.Groups[index].Kind ||
			!equalStrings(b.Groups[index].Names, other.Groups[index].Names) {
			return false
		}
	}
	return true
}

// PolicyNames returns the ordered names for a kind; callers must not mutate the slice.
func (b Bindings) PolicyNames(kind PolicyKind) []string {
	for _, group := range b.Groups {
		if group.Kind == kind {
			// Returned slice is shared with the caller; treat it as read-only.
			return group.Names
		}
	}
	return nil
}

func attachmentIndexKeys(attachment PolicyAttachment) []string {
	switch {
	case attachment.Target.Global:
		return []string{globalPolicyAttachmentIndexKey}
	default:
		result := make([]string, 0, len(attachment.Target.Namespaces))
		for _, namespace := range attachment.Target.Namespaces {
			result = append(result, namespacePolicyAttachmentKeyPrefix+namespace)
		}
		return result
	}
}

// NewWorkloadPolicyBindingsCollection selects shared policies from the Workload's
// namespace and labels. It does not depend on Sandbox discovery or lifecycle.
func NewWorkloadPolicyBindingsCollection(
	workloads krt.Collection[model.Workload],
	attachments krt.Collection[PolicyAttachment],
	options krt.OptionsBuilder,
) krt.Collection[Bindings] {
	targets := krt.NewCollection(workloads, func(_ krt.HandlerContext, workload model.Workload) *policyTarget {
		return &policyTarget{UID: workload.UID, Namespace: workload.Namespace, Labels: workload.Labels}
	}, options.WithName("workload-policy-targets")...)
	byTarget := krt.NewIndex(attachments, "workloadPolicyAttachmentsByTarget", attachmentIndexKeys)
	namespaceMatches := newWorkloadPolicyMatches(targets, attachments, byTarget, false, options)
	globalMatches := newWorkloadPolicyMatches(targets, attachments, byTarget, true, options)
	return krt.NewCollection(targets, func(ctx krt.HandlerContext, workload policyTarget) *Bindings {
		local := krt.FetchOne(ctx, namespaceMatches, krt.FilterKey(workload.UID))
		global := krt.FetchOne(ctx, globalMatches, krt.FilterKey(workload.UID))
		if !local.matchesWorkload(workload) || !global.matchesWorkload(workload) {
			// Keep the previous binding until both scopes reflect the same labels.
			ctx.DiscardResult()
			return nil
		}
		matchedByName := make(map[string]PolicyAttachment, len(local.Attachments)+len(global.Attachments))
		for _, group := range []*workloadPolicyMatches{local, global} {
			for _, attachment := range group.Attachments {
				matchedByName[attachment.ResourceName()] = attachment
			}
		}
		return bindingsFromMatches(workload.UID, matchedByName)
	}, options.WithName("workload-policy-bindings")...)
}

// Only namespace and labels affect selection; other Workload changes skip matching.
type policyTarget struct {
	UID       string
	Namespace string
	Labels    map[string]string
}

func (t policyTarget) ResourceName() string { return t.UID }

func (t policyTarget) Equals(other policyTarget) bool {
	return t.UID == other.UID && t.Namespace == other.Namespace && maps.Equal(t.Labels, other.Labels)
}

// Cache each scope independently so a global change cannot rescan namespace policies.
type workloadPolicyMatches struct {
	Target      policyTarget
	Attachments []PolicyAttachment
}

func (m workloadPolicyMatches) ResourceName() string { return m.Target.UID }

func (m *workloadPolicyMatches) matchesWorkload(workload policyTarget) bool {
	return m != nil && m.Target.Equals(workload)
}

func (m workloadPolicyMatches) Equals(other workloadPolicyMatches) bool {
	return m.Target.Equals(other.Target) && slices.EqualFunc(m.Attachments, other.Attachments, PolicyAttachment.Equals)
}

func newWorkloadPolicyMatches(
	workloads krt.Collection[policyTarget],
	attachments krt.Collection[PolicyAttachment],
	byTarget krt.Index[string, PolicyAttachment],
	global bool,
	options krt.OptionsBuilder,
) krt.Collection[workloadPolicyMatches] {
	name := "workload-namespace-policy-matches"
	if global {
		name = "workload-global-policy-matches"
	}
	return krt.NewCollection(workloads, func(ctx krt.HandlerContext, workload policyTarget) *workloadPolicyMatches {
		key := namespacePolicyAttachmentKeyPrefix + workload.Namespace
		if global {
			key = globalPolicyAttachmentIndexKey
		}
		// KRT checks both old and new selectors when invalidating matching targets.
		matched := krt.Fetch(ctx, attachments, krt.FilterIndex(byTarget, key), krt.FilterGeneric(func(value any) bool {
			return value.(PolicyAttachment).selects(workload.Namespace, workload.Labels)
		}))
		sort.Slice(matched, func(i, j int) bool { return policyAttachmentLess(matched[i], matched[j]) })
		return &workloadPolicyMatches{Target: workload, Attachments: matched}
	}, options.WithName(name)...)
}

func bindingsFromMatches(uid string, matchedByName map[string]PolicyAttachment) *Bindings {
	matched := make([]PolicyAttachment, 0, len(matchedByName))
	for _, attachment := range matchedByName {
		matched = append(matched, attachment)
	}
	sort.Slice(matched, func(i, j int) bool { return policyAttachmentLess(matched[i], matched[j]) })
	byKind := make(map[PolicyKind][]string)
	for _, attachment := range matched {
		byKind[attachment.Kind] = append(byKind[attachment.Kind], attachment.Name)
	}
	kinds := make([]PolicyKind, 0, len(byKind))
	for kind := range byKind {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	groups := make([]BindingGroup, 0, len(kinds))
	for _, kind := range kinds {
		groups = append(groups, BindingGroup{Kind: kind, Names: byKind[kind]})
	}
	return &Bindings{TargetUID: uid, Groups: groups}
}
