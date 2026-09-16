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

package agentio

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/kube/krt"
)

// Mirrors the annotation consumed by EPE; agents-api does not export it yet.
const sandboxSecurityRulesAnnotation = "agents.kruise.io/security-rules"

func bindablePolicyFromSandbox(sandbox *metav1.PartialObjectMetadata) (*BindablePolicy, error) {
	raw := sandbox.Annotations[sandboxSecurityRulesAnnotation]
	if raw == "" {
		return nil, nil
	}
	if sandbox.Namespace == "" || sandbox.Name == "" {
		return nil, fmt.Errorf("Sandbox security rules require namespace and name")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var rules []agentsv1alpha1.SecurityRule
	if err := dec.Decode(&rules); err != nil {
		return nil, fmt.Errorf("decode %s: %w", sandboxSecurityRulesAnnotation, err)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("%s contains no rules", sandboxSecurityRulesAnnotation)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("%s must contain a single JSON rule array", sandboxSecurityRulesAnnotation)
	}
	policy, err := bindablePolicyFromSecurityProfileSpec("Sandbox", sandbox.ObjectMeta,
		&agentsv1alpha1.SecurityProfileSpec{Rules: rules})
	if err != nil || policy == nil {
		return policy, err
	}
	// Three path segments cannot collide with namespaced or global profile names.
	policy.Name = "sandbox/" + sandbox.Namespace + "/" + sandbox.Name
	policy.PodName = sandbox.Name
	// Profile API priorities are non-negative int32 values, negated internally.
	// MinInt32 is below even -MaxInt32, so Sandbox rules always follow every
	// system profile regardless of priority, creation time, or name.
	policy.Priority = math.MinInt32
	return policy, nil
}

func newSandboxBindablePoliciesCollection(
	sandboxes krt.Collection[*metav1.PartialObjectMetadata],
	opts krt.OptionsBuilder,
) krt.Collection[BindablePolicy] {
	return krt.NewCollection(sandboxes, func(ctx krt.HandlerContext, sandbox *metav1.PartialObjectMetadata) *BindablePolicy {
		policy, err := bindablePolicyFromSandbox(sandbox)
		if err != nil {
			log.Warnf("invalid Sandbox SNI policy %s/%s: %v", sandbox.Namespace, sandbox.Name, err)
			// Match EPE's handling of malformed inline rules: retain the previous
			// valid version. Removing the annotation remains a legitimate removal.
			ctx.DiscardResult()
			return nil
		}
		return policy
	}, opts.WithName("SandboxBindablePolicies")...)
}
