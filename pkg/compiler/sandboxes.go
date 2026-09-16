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

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// Invalid policies are omitted independently. Runtime metadata and other policies
// continue to be published; failed updates do not retain an earlier policy version.
func newSandboxResources(
	sandboxes krt.Collection[model.Sandbox],
	policies policyCollections,
	failures *failureRecorder,
	options collectionOptions,
) krt.Collection[model.Resource] {
	for _, kind := range []string{"SandboxResource", "SandboxInlinePolicies", "SandboxEgressPolicy", "SandboxSharedPolicies"} {
		clearFailureOnSourceDelete(sandboxes, failures, kind)
	}
	return krt.NewCollection(sandboxes, func(ctx krt.HandlerContext, sandbox model.Sandbox) *model.Resource {
		payload := &sandboxv1.Sandbox{Uid: sandbox.UID, State: sandboxv1.SandboxState(sandbox.State)}
		if sandbox.Attester != nil {
			payload.Attester = &sandboxv1.Sandbox_Attester{WorkloadUid: sandbox.Attester.WorkloadUID}
		}
		currentInput := func() bool {
			current := sandboxes.GetKey(sandbox.ResourceName())
			return current != nil && current.Equals(sandbox)
		}
		record := func(kind string, err error) {
			if err != nil {
				failures.recordIf(kind, sandbox.UID, err, currentInput)
			} else {
				failures.clearIf(kind, sandbox.UID, currentInput)
			}
		}
		if compiled := krt.FetchOne(
			ctx,
			policies.trafficPolicies,
			krt.FilterKey(model.SandboxTrafficPolicyName(sandbox.UID)),
		); compiled != nil {
			payload.TrafficPolicy = compiled.Policy
		}
		var inlineErr error
		if compiled := krt.FetchOne(
			ctx,
			policies.sniPolicies,
			krt.FilterKey(model.SandboxSecurityProfileName(sandbox.UID)),
		); compiled != nil {
			extension, err := marshalDeterministicAny(compiled.Policy)
			inlineErr = err
			if err == nil {
				payload.Extensions = append(payload.Extensions, extension)
			}
		}
		record("SandboxInlinePolicies", inlineErr)

		facts := &model.SandboxResourceFacts{AttesterWorkloadUID: payload.GetAttester().GetWorkloadUid()}
		bindings := krt.FetchOne(ctx, policies.policyBindings, krt.FilterKey(sandbox.UID))
		var routingErr, sharedErr error
		if bindings != nil {
			payload.EgressRouting, facts.GatewayReferences, routingErr = sandboxEgressRouting(ctx, bindings, policies)
			sharedErr = loadSandboxPolicies(ctx, bindings, policies, payload)
		}
		record("SandboxEgressPolicy", routingErr)
		record("SandboxSharedPolicies", sharedErr)
		facts.TrafficPolicyRefs = payload.PolicyRefs[model.TrafficPolicyType].GetResourceNames()
		value, err := marshalDeterministicAny(payload)
		if err != nil {
			record("SandboxResource", err)
			return nil
		}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.SandboxType, Name: sandbox.UID},
			"",
			value,
			nil,
			model.ResourceFacts{Sandbox: facts},
		)
		if err != nil {
			record("SandboxResource", err)
			return nil
		}
		record("SandboxResource", nil)
		return &resource
	}, options("sandbox-resources")...)
}

func sandboxEgressRouting(
	ctx krt.HandlerContext,
	bindings *policy.Bindings,
	policies policyCollections,
) (*sandboxv1.EgressRouting, []string, error) {
	names := bindings.PolicyNames(model.PolicyKindEgressPolicy)
	if len(names) == 0 {
		return nil, nil, nil
	}
	// FilterKeys sorts its input; binding order must stay immutable.
	fetched := krt.Fetch(ctx, policies.egressPolicies, krt.FilterKeys(append([]string(nil), names...)...))
	effective, gatewayKeys, err := policy.SelectEgressPolicies(names, fetched)
	if err != nil {
		return nil, nil, err
	}
	routing, err := policy.CompileEgressRouting(effective)
	if err != nil {
		return nil, nil, err
	}
	return routing, gatewayKeys, nil
}

// loadSandboxPolicies copies ordered shared references and valid extension bodies.
// Missing or invalid extensions do not suppress other policy families or profiles.
func loadSandboxPolicies(
	ctx krt.HandlerContext,
	bindings *policy.Bindings,
	policies policyCollections,
	payload *sandboxv1.Sandbox,
) error {
	// Bindings already carry control-plane order. Shared body updates must not
	// invalidate the Sandbox, so do not read those bodies here.
	if refs := bindings.PolicyNames(model.PolicyKindTrafficPolicy); len(refs) > 0 {
		payload.PolicyRefs = map[string]*sandboxv1.PolicyReference{
			model.TrafficPolicyType: {ResourceNames: append([]string(nil), refs...)},
		}
	}
	var policyErr error
	for _, name := range bindings.PolicyNames(model.PolicyKindSNIPolicy) {
		compiled := krt.FetchOne(ctx, policies.sniPolicies, krt.FilterKey(name))
		if compiled == nil || compiled.Policy == nil {
			policyErr = errors.Join(policyErr, fmt.Errorf("SNI policy %q is unavailable", name))
			continue
		}
		extension, err := marshalDeterministicAny(compiled.Policy)
		if err != nil {
			policyErr = errors.Join(policyErr, fmt.Errorf("SNI policy %q: %w", name, err))
			continue
		}
		payload.Extensions = append(payload.Extensions, extension)
	}
	return policyErr
}
