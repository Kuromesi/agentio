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

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// PolicyBindingGroup contains the ordered resource names for one typed policy
// consumer.
type PolicyBindingGroup struct {
	Kind  PolicyKind
	Names []string
}

// PolicyTargetKind distinguishes policy owners, even when their UIDs coincide.
type PolicyTargetKind string

const (
	PolicyTargetWorkload PolicyTargetKind = "workload"
	PolicyTargetSandbox  PolicyTargetKind = "sandbox"
)

func PolicyBindingsKey(kind PolicyTargetKind, uid string) string { return string(kind) + "/" + uid }

// PolicyBindings contains the ordered policy references for one Workload or Sandbox.
type PolicyBindings struct {
	TargetKind    PolicyTargetKind
	TargetUID     string
	Groups        []PolicyBindingGroup
	Unresolved    []model.PolicyRef
	InvalidReason string
}

func (b PolicyBindings) ResourceName() string { return PolicyBindingsKey(b.TargetKind, b.TargetUID) }

func (b PolicyBindings) Equals(other PolicyBindings) bool {
	if b.TargetKind != other.TargetKind || b.TargetUID != other.TargetUID || b.InvalidReason != other.InvalidReason ||
		len(b.Groups) != len(other.Groups) || len(b.Unresolved) != len(other.Unresolved) {
		return false
	}
	for index := range b.Groups {
		if b.Groups[index].Kind != other.Groups[index].Kind ||
			!equalStrings(b.Groups[index].Names, other.Groups[index].Names) {
			return false
		}
	}
	for index := range b.Unresolved {
		if b.Unresolved[index] != other.Unresolved[index] {
			return false
		}
	}
	return true
}

func (b PolicyBindings) Valid() bool {
	return b.InvalidReason == "" && len(b.Unresolved) == 0
}

func (b PolicyBindings) PolicyNames(kind PolicyKind) []string {
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
	case attachment.Target.SandboxUID != "":
		return []string{sandboxPolicyAttachmentKeyPrefix + attachment.Target.SandboxUID}
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

// NewPolicyBindingsCollection matches each source independently and joins their
// results under kind-qualified keys. Workloads never inherit Sandbox references.
func NewPolicyBindingsCollection(
	workloads krt.Collection[model.Workload],
	sandboxes krt.Collection[model.Sandbox],
	attachments krt.Collection[PolicyAttachment],
	options krt.OptionsBuilder,
) krt.Collection[PolicyBindings] {
	byTarget := krt.NewIndex(attachments, "policyAttachmentsByTarget", attachmentIndexKeys)
	workloadBindings := krt.NewCollection(workloads, func(ctx krt.HandlerContext, workload model.Workload) *PolicyBindings {
		if workload.SandboxManaged {
			return nil
		}
		return resolvePolicyBindings(ctx, PolicyTargetWorkload, workload.UID, workload.Namespace, workload.Labels, nil, attachments, byTarget)
	}, options.WithName("workload-policy-bindings")...)
	sandboxBindings := krt.NewCollection(sandboxes, func(ctx krt.HandlerContext, sandbox model.Sandbox) *PolicyBindings {
		if err := sandbox.Validate(); err != nil {
			return &PolicyBindings{TargetKind: PolicyTargetSandbox, TargetUID: sandbox.UID,
				Unresolved: append([]model.PolicyRef(nil), sandbox.PolicyRefs...), InvalidReason: err.Error()}
		}
		return resolvePolicyBindings(ctx, PolicyTargetSandbox, sandbox.UID, sandbox.Namespace, sandbox.Labels, sandbox.PolicyRefs, attachments, byTarget)
	}, options.WithName("sandbox-policy-bindings")...)
	return krt.JoinCollection([]krt.Collection[PolicyBindings]{workloadBindings, sandboxBindings}, options.WithName("policy-bindings")...)
}

func resolvePolicyBindings(ctx krt.HandlerContext, kind PolicyTargetKind, uid, namespace string, targetLabels map[string]string,
	references []model.PolicyRef, attachments krt.Collection[PolicyAttachment], byTarget krt.Index[string, PolicyAttachment],
) *PolicyBindings {
	keys := []string{globalPolicyAttachmentIndexKey, namespacePolicyAttachmentKeyPrefix + namespace}
	if kind == PolicyTargetSandbox {
		keys = append(keys, sandboxPolicyAttachmentKeyPrefix+uid)
	}
	matchedByName := make(map[string]PolicyAttachment)
	for _, key := range keys {
		for _, attachment := range krt.Fetch(ctx, attachments, krt.FilterIndex(byTarget, key)) {
			if attachment.selects(kind, uid, namespace, targetLabels) {
				matchedByName[attachment.ResourceName()] = attachment
			}
		}
	}
	matched := make([]PolicyAttachment, 0, len(matchedByName))
	for _, attachment := range matchedByName {
		matched = append(matched, attachment)
	}
	sort.Slice(matched, func(i, j int) bool { return policyAttachmentLess(matched[i], matched[j]) })
	byKind := make(map[PolicyKind][]string)
	seen := sets.New[string]()
	unresolved := make([]model.PolicyRef, 0)
	for _, reference := range references {
		key := reference.ResourceName()
		attachment := krt.FetchOne(ctx, attachments, krt.FilterKey(key))
		if attachment == nil || (attachment.Target.Kind != "" && attachment.Target.Kind != kind) {
			unresolved = append(unresolved, reference)
			continue
		}
		if seen.Contains(key) {
			continue
		}
		seen.Insert(key)
		byKind[reference.Kind] = append(byKind[reference.Kind], reference.Name)
	}
	for _, attachment := range matched {
		key := attachment.ResourceName()
		if seen.Contains(key) {
			continue
		}
		seen.Insert(key)
		byKind[attachment.Kind] = append(byKind[attachment.Kind], attachment.Name)
	}
	kinds := make([]PolicyKind, 0, len(byKind))
	for kind := range byKind {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	groups := make([]PolicyBindingGroup, 0, len(kinds))
	for _, kind := range kinds {
		groups = append(groups, PolicyBindingGroup{Kind: kind, Names: byKind[kind]})
	}
	return &PolicyBindings{TargetKind: kind, TargetUID: uid, Groups: groups, Unresolved: unresolved}
}
