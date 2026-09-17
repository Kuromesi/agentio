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
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// workloadSandboxPolicies is computed once per bound Workload, shared by all ADS
// clients, and removed when the binding disappears. Source policies stay immutable.
type workloadSandboxPolicies struct {
	WorkloadUID        string
	AuthorizationNames []string
	SNIPolicy          *extensionsv1.SniTrafficPolicy
	EgressPolicies     *extensionsv1.EgressPolicies
	GatewayReferences  []string
}

func (p workloadSandboxPolicies) ResourceName() string { return p.WorkloadUID }

func (p workloadSandboxPolicies) Equals(other workloadSandboxPolicies) bool {
	return p.WorkloadUID == other.WorkloadUID &&
		slices.Equal(p.AuthorizationNames, other.AuthorizationNames) &&
		slices.Equal(p.GatewayReferences, other.GatewayReferences) && proto.Equal(p.SNIPolicy, other.SNIPolicy) &&
		proto.Equal(p.EgressPolicies, other.EgressPolicies)
}

// This collection is an optional branch of the compiler graph. Native Sandbox
// resources keep their existing path; neither path depends on ADS connections.
func newSandboxWorkloadPolicies(
	inputs Inputs,
	policies policyCollections,
	failures *failureRecorder,
	options collectionOptions,
) krt.Collection[workloadSandboxPolicies] {
	if inputs.NativeSandboxPolicies {
		return krt.NewStaticCollection[workloadSandboxPolicies](
			nil,
			nil,
			options("sandbox-workload-policies-disabled")...)
	}
	byWorkload := krt.NewIndex(inputs.Sandboxes, "compatibilitySandboxesByWorkload", func(s model.Sandbox) []string {
		if s.Attester != nil && s.Attester.WorkloadUID != "" {
			return []string{s.Attester.WorkloadUID}
		}
		return nil
	})
	clearFailureOnSourceDelete(inputs.Workloads, failures, "SandboxWorkloadPolicies")
	return krt.NewCollection(
		inputs.Workloads,
		func(ctx krt.HandlerContext, workload model.Workload) *workloadSandboxPolicies {
			bound := krt.Fetch(ctx, inputs.Sandboxes, krt.FilterIndex(byWorkload, workload.UID))
			currentInput := func() bool {
				current := inputs.Workloads.GetKey(workload.UID)
				return current != nil && current.Equals(workload)
			}
			var result *workloadSandboxPolicies
			var err error
			switch len(bound) {
			case 0:
			case 1:
				result, err = sandboxAsWorkload(ctx, workload, bound[0], policies)
			default:
				err = fmt.Errorf(
					"%d Sandboxes bind this Workload; compatibility requires one Sandbox per Workload",
					len(bound),
				)
			}
			if err != nil {
				failures.recordIf("SandboxWorkloadPolicies", workload.UID, err, currentInput)
			} else {
				failures.clearIf("SandboxWorkloadPolicies", workload.UID, currentInput)
			}
			return result
		},
		options("sandbox-workload-policies")...)
}

// sandboxAsWorkload adapts existing Sandbox bindings and compiled bodies. It
// never re-matches Pod labels, resolves peers, or parses source policies.
func sandboxAsWorkload(
	ctx krt.HandlerContext,
	workload model.Workload,
	sandbox model.Sandbox,
	policies policyCollections,
) (*workloadSandboxPolicies, error) {
	result := &workloadSandboxPolicies{WorkloadUID: workload.UID}
	if compiled := krt.FetchOne(
		ctx,
		policies.trafficPolicies,
		krt.FilterKey(model.SandboxTrafficPolicyName(sandbox.UID)),
	); compiled != nil {
		result.addAuthorizationReferences(compiled)
	}
	appendSNI := func(p *extensionsv1.SniTrafficPolicy) {
		if len(p.GetRules()) == 0 {
			return
		}
		if result.SNIPolicy == nil {
			result.SNIPolicy = &extensionsv1.SniTrafficPolicy{}
		}
		// Compiled bodies are immutable: share rule pointers rather than cloning.
		result.SNIPolicy.Rules = append(result.SNIPolicy.Rules, p.Rules...)
	}
	if compiled := krt.FetchOne(
		ctx,
		policies.sniPolicies,
		krt.FilterKey(model.SandboxSecurityProfileName(sandbox.UID)),
	); compiled != nil {
		appendSNI(compiled.Policy)
	}
	var policyErr error
	bindings := krt.FetchOne(ctx, policies.policyBindings, krt.FilterKey(sandbox.UID))
	if bindings != nil {
		for _, name := range bindings.PolicyNames(model.PolicyKindTrafficPolicy) {
			compiled := krt.FetchOne(ctx, policies.trafficPolicies, krt.FilterKey(name))
			if compiled == nil {
				policyErr = errors.Join(policyErr, fmt.Errorf("TrafficPolicy %q is unavailable", name))
			} else {
				result.addAuthorizationReferences(compiled)
			}
		}
		for _, name := range bindings.PolicyNames(model.PolicyKindSNIPolicy) {
			compiled := krt.FetchOne(ctx, policies.sniPolicies, krt.FilterKey(name))
			if compiled == nil {
				policyErr = errors.Join(policyErr, fmt.Errorf("SNI policy %q is unavailable", name))
				continue
			}
			appendSNI(compiled.Policy)
		}
		if names := bindings.PolicyNames(model.PolicyKindEgressPolicy); len(names) > 0 {
			compiled := krt.Fetch(ctx, policies.egressPolicies, krt.FilterKeys(append([]string(nil), names...)...))
			effective, keys, err := policy.SelectEgressPolicies(names, compiled)
			if err == nil {
				// Preserve the legacy representation, including DENY actions that
				// cannot be represented by native Sandbox EgressRouting.
				result.EgressPolicies, result.GatewayReferences = effective, keys
			}
			policyErr = errors.Join(policyErr, err)
		}
	}
	return result, policyErr
}

// Only selector policies need explicit Workload references. Namespace and global
// scopes are evaluated by the legacy data plane without per-Workload attachment.
func (p *workloadSandboxPolicies) addAuthorizationReferences(compiled *policy.CompiledTrafficPolicy) {
	for _, authorization := range compiled.AsAuthorization {
		if authorization.Policy.Scope == securityv1.Scope_WORKLOAD_SELECTOR {
			p.AuthorizationNames = append(p.AuthorizationNames, authorization.Name)
		}
	}
}
