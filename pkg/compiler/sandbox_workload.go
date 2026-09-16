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
	"crypto/sha256"
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
	Resources          []model.Resource
}

func (p workloadSandboxPolicies) ResourceName() string { return p.WorkloadUID }

func (p workloadSandboxPolicies) Equals(other workloadSandboxPolicies) bool {
	return p.WorkloadUID == other.WorkloadUID &&
		slices.Equal(p.AuthorizationNames, other.AuthorizationNames) &&
		slices.Equal(p.GatewayReferences, other.GatewayReferences) && proto.Equal(p.SNIPolicy, other.SNIPolicy) &&
		proto.Equal(p.EgressPolicies, other.EgressPolicies) && slices.EqualFunc(p.Resources, other.Resources, model.Resource.Equals)
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
		return krt.NewStaticCollection[workloadSandboxPolicies](nil, nil, options("sandbox-workload-policies-disabled")...)
	}
	byWorkload := krt.NewIndex(inputs.Sandboxes, "compatibilitySandboxesByWorkload", func(s model.Sandbox) []string {
		if s.Attester != nil && s.Attester.WorkloadUID != "" {
			return []string{s.Attester.WorkloadUID}
		}
		return nil
	})
	clearFailureOnSourceDelete(inputs.Workloads, failures, "SandboxWorkloadPolicies")
	return krt.NewCollection(inputs.Workloads, func(ctx krt.HandlerContext, workload model.Workload) *workloadSandboxPolicies {
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
			// Old proxies cannot identify the originating Sandbox. Do not union
			// policies or pick an arbitrary owner: deny in the legacy projection.
			result = &workloadSandboxPolicies{WorkloadUID: workload.UID}
			err = result.setAuthorizations(workload.Namespace, []*securityv1.TrafficPolicy{nil})
			err = errors.Join(err, fmt.Errorf("%d Sandboxes bind this Workload; compatibility requires one Sandbox per Workload", len(bound)))
		}
		if err != nil {
			failures.recordIf("SandboxWorkloadPolicies", workload.UID, err, currentInput)
		} else {
			failures.clearIf("SandboxWorkloadPolicies", workload.UID, currentInput)
		}
		return result
	}, options("sandbox-workload-policies")...)
}

// sandboxAsWorkload adapts existing Sandbox bindings and compiled bodies. It
// never re-matches Pod labels, resolves peers, or parses source policies.
func sandboxAsWorkload(ctx krt.HandlerContext, workload model.Workload, sandbox model.Sandbox, policies policyCollections) (*workloadSandboxPolicies, error) {
	result := &workloadSandboxPolicies{WorkloadUID: workload.UID}
	var ordered []*securityv1.TrafficPolicy
	if compiled := krt.FetchOne(ctx, policies.trafficPolicies, krt.FilterKey(model.SandboxTrafficPolicyName(sandbox.UID))); compiled != nil {
		ordered = append(ordered, compiled.Policy)
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
	if compiled := krt.FetchOne(ctx, policies.sniPolicies, krt.FilterKey(model.SandboxSecurityProfileName(sandbox.UID))); compiled != nil {
		appendSNI(compiled.Policy)
	}
	var policyErr error
	bindings := krt.FetchOne(ctx, policies.policyBindings, krt.FilterKey(policy.BindingsKey(policy.PolicyTargetSandbox, sandbox.UID)))
	if bindings != nil {
		for _, name := range bindings.PolicyNames(model.PolicyKindTrafficPolicy) {
			compiled := krt.FetchOne(ctx, policies.trafficPolicies, krt.FilterKey(name))
			if compiled == nil {
				ordered = append(ordered, nil)
			} else {
				ordered = append(ordered, compiled.Policy)
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
	policyErr = errors.Join(policyErr, result.setAuthorizations(workload.Namespace, ordered))
	return result, policyErr
}

func (p *workloadSandboxPolicies) setAuthorizations(namespace string, ordered []*securityv1.TrafficPolicy) error {
	authorizations, err := policy.SandboxAsAuthorizations("sandbox-"+workloadPolicyID(p.WorkloadUID), namespace, ordered)
	if err != nil {
		return err
	}
	for _, authorization := range authorizations {
		resource, err := authorizationResource(authorization)
		if err != nil {
			return err
		}
		p.Resources = append(p.Resources, resource)
		p.AuthorizationNames = append(p.AuthorizationNames, authorization.Name)
	}
	return nil
}

// Workload UIDs can contain '/'; a stable digest keeps generated names canonical.
func workloadPolicyID(workloadUID string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(workloadUID)))
}

func newSandboxWorkloadResources(policies krt.Collection[workloadSandboxPolicies], options collectionOptions) krt.Collection[model.Resource] {
	return krt.NewManyCollection(policies, func(_ krt.HandlerContext, p workloadSandboxPolicies) []model.Resource {
		return p.Resources
	}, options("sandbox-workload-resources")...)
}
