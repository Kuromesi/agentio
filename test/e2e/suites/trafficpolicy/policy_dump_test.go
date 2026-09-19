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
//
// This file contains policy-propagation and firewall assertions; generic
// manifest and echo-call helpers live in reusable E2E packages.

package trafficpolicy

import (
	"encoding/json"
	"fmt"
	"strings"
)

type policyDumpView struct {
	found bool
	body  string
}

// inspectPolicyDump reads the workload-scoped view returned by the harness.
// A cached native body alone is not evidence that a policy applies to this workload.
func inspectPolicyDump(content, name string) (policyDumpView, error) {
	var dump struct {
		Workload *struct {
			UID                   string   `json:"uid"`
			Namespace             string   `json:"namespace"`
			AuthorizationPolicies []string `json:"authorizationPolicies"`
			TrafficPolicyRefs     []string `json:"trafficPolicyRefs"`
		} `json:"workload"`

		TrafficPolicies *[]json.RawMessage `json:"trafficPolicies"`
		Policies        []json.RawMessage  `json:"policies"`
	}
	if err := json.Unmarshal([]byte(content), &dump); err != nil {
		return policyDumpView{}, err
	}
	if dump.Workload == nil || dump.Workload.UID == "" {
		return policyDumpView{}, fmt.Errorf("workload identity is absent from config dump")
	}
	if dump.TrafficPolicies != nil {
		refs := dump.Workload.TrafficPolicyRefs
		if refs == nil {
			return policyDumpView{}, fmt.Errorf("workload has no native policy binding yet")
		}
		var target string
		for _, ref := range refs {
			if strings.HasSuffix(ref, "/trafficPolicies/"+name) || ref == "trafficPolicies/"+name {
				target = ref
				break
			}
		}
		if target == "" {
			return policyDumpView{}, nil
		}
		for _, raw := range *dump.TrafficPolicies {
			var policy struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(raw, &policy); err != nil {
				return policyDumpView{}, err
			}
			if policy.Name == target {
				return policyDumpView{found: true, body: string(raw)}, nil
			}
		}
		return policyDumpView{}, fmt.Errorf("referenced policy %q has not arrived", target)
	}

	refs := make(map[string]bool)
	for _, ref := range dump.Workload.AuthorizationPolicies {
		refs[ref] = true
	}
	matchesName := func(policyName string) bool {
		return policyName == name || policyName == name+"-egress" || policyName == name+"-ingress"
	}
	var bodies []json.RawMessage
	for _, raw := range dump.Policies {
		var policy struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			Scope     string `json:"scope"`
		}
		if err := json.Unmarshal(raw, &policy); err != nil {
			return policyDumpView{}, err
		}
		key := policy.Namespace + "/" + policy.Name
		referenced := refs[key]
		if matchesName(policy.Name) &&
			(referenced || policy.Scope == "Global" || policy.Scope == "Namespace" && policy.Namespace == dump.Workload.Namespace) {
			bodies = append(bodies, raw)
			delete(refs, key)
		}
	}
	for ref := range refs {
		_, policyName, _ := strings.Cut(ref, "/")
		if matchesName(policyName) {
			return policyDumpView{}, fmt.Errorf("referenced Authorization %q has not arrived", ref)
		}
	}
	if len(bodies) == 0 {
		return policyDumpView{}, nil
	}
	body, err := json.Marshal(bodies)
	return policyDumpView{found: true, body: string(body)}, err
}
