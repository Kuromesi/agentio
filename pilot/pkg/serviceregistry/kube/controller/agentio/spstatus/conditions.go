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

package spstatus

import (
	"fmt"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pilot/pkg/model/kstatus"
	"istio.io/istio/pkg/slices"
)

// ConditionResolvedRefs reports whether every credentialRef resolves. The
// agents-api only predefines Accepted and Programmed
// (securityprofile_types.go:587-593); this follows the Gateway API split where
// syntax problems land on Accepted and reference problems land on ResolvedRefs
// (pilot/pkg/config/kube/gateway/conditions.go:148-164).
const ConditionResolvedRefs = "ResolvedRefs"

// Reasons used when a condition is True, plus the derived NotAccepted.
const (
	ReasonAccepted     = "Accepted"
	ReasonResolvedRefs = "ResolvedRefs"
	ReasonProgrammed   = "Programmed"
	ReasonNotAccepted  = "NotAccepted"
)

// BuildStatus turns validation output into the desired SecurityProfileStatus.
//
// All three conditions are emitted on every call. This is required, not
// cosmetic: the writer uses server-side apply, so a condition we owned
// previously but stop declaring is pruned by the apiserver.
//
// Programmed follows Accepted only. An unresolved credentialRef leaves
// Programmed True — ResolvedRefs carries that problem on its own, so the
// RestrictedSecretsScope default (which makes SecretNotFound common for
// profiles outside the control plane namespace) does not contaminate a second
// condition.
func BuildStatus(
	sp *agentsv1alpha1.SecurityProfile,
	specErrs []SpecError,
	refErrs []RefError,
) agentsv1alpha1.SecurityProfileStatus {
	gen := sp.Generation
	conds := sp.Status.Conditions

	accepted := metav1.Condition{
		Type:               agentsv1alpha1.SecurityProfileConditionAccepted,
		Status:             metav1.ConditionTrue,
		Reason:             ReasonAccepted,
		Message:            "Rule chain compiled",
		ObservedGeneration: gen,
		LastTransitionTime: metav1.Now(),
	}
	if len(specErrs) > 0 {
		e := specErrs[0]
		accepted.Status = metav1.ConditionFalse
		accepted.Reason = e.Reason
		accepted.Message = summarize(e.Field, e.Message, len(specErrs))
	}

	resolved := metav1.Condition{
		Type:               ConditionResolvedRefs,
		Status:             metav1.ConditionTrue,
		Reason:             ReasonResolvedRefs,
		Message:            "All references resolved",
		ObservedGeneration: gen,
		LastTransitionTime: metav1.Now(),
	}
	if len(refErrs) > 0 {
		e := refErrs[0]
		resolved.Status = metav1.ConditionFalse
		resolved.Reason = e.Reason
		resolved.Message = summarize(e.Field, e.Message, len(refErrs))
	}

	programmed := metav1.Condition{
		Type:               agentsv1alpha1.SecurityProfileConditionProgrammed,
		Status:             metav1.ConditionTrue,
		Reason:             ReasonProgrammed,
		Message:            "Profile distributed to the data plane",
		ObservedGeneration: gen,
		LastTransitionTime: metav1.Now(),
	}
	if accepted.Status != metav1.ConditionTrue {
		programmed.Status = metav1.ConditionFalse
		programmed.Reason = ReasonNotAccepted
		programmed.Message = "Profile was not accepted"
	}

	// UpdateConditionIfChanged preserves LastTransitionTime while the status
	// value is unchanged (pilot/pkg/model/kstatus/helper.go:60-68).
	for _, c := range []metav1.Condition{accepted, programmed, resolved} {
		conds = kstatus.UpdateConditionIfChanged(conds, c)
	}

	// Sort by type so the SSA patch body is byte-identical across reconciles
	// when nothing changed.
	conds = slices.SortBy(conds, func(c metav1.Condition) string { return c.Type })

	return agentsv1alpha1.SecurityProfileStatus{
		ObservedGeneration: gen,
		Conditions:         conds,
	}
}

func summarize(field, msg string, total int) string {
	out := fmt.Sprintf("%s: %s", field, msg)
	if total > 1 {
		out = fmt.Sprintf("%s (and %d more problem(s))", out, total-1)
	}
	return out
}
