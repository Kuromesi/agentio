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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var errAggregatedPolicyIdentity = errors.New("legacy Authorization aggregates source policies")

type policyDumpView struct {
	found      bool
	aggregated bool
	body       string
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
		Sandboxes []struct {
			WorkloadUID       string   `json:"workloadUid"`
			TrafficPolicyRefs []string `json:"trafficPolicyRefs"`
		} `json:"sandboxes"`
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
		bound := false
		for _, sandbox := range dump.Sandboxes {
			if sandbox.WorkloadUID == dump.Workload.UID {
				bound = true
				refs = append(refs, sandbox.TrafficPolicyRefs...)
			}
		}
		if !bound && refs == nil {
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

	// Compatibility output always has one aggregate per direction, including
	// terminal defaults. Neither its name nor its lifetime tracks a source policy.
	aggregate := fmt.Sprintf("sandbox-%x", sha256.Sum256([]byte(dump.Workload.UID)))
	refs := make(map[string]bool)
	for _, ref := range dump.Workload.AuthorizationPolicies {
		refs[ref] = true
	}
	var bodies []json.RawMessage
	var named policyDumpView
	for _, raw := range dump.Policies {
		var policy struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			Scope     string `json:"scope"`
			Priority  *int   `json:"priority"`
		}
		if err := json.Unmarshal(raw, &policy); err != nil {
			return policyDumpView{}, err
		}
		referenced := refs[policy.Namespace+"/"+policy.Name]
		if referenced && policy.Priority != nil && *policy.Priority == -1 &&
			(policy.Name == aggregate+"-egress" || policy.Name == aggregate+"-ingress") {
			bodies = append(bodies, raw)
		}
		if (referenced || policy.Scope == "Global" || policy.Scope == "Namespace" && policy.Namespace == dump.Workload.Namespace) &&
			(policy.Name == name || policy.Name == name+"-egress" || policy.Name == name+"-ingress") {
			named = policyDumpView{found: true, body: string(raw)}
		}
	}
	if refs[dump.Workload.Namespace+"/"+aggregate+"-egress"] || refs[dump.Workload.Namespace+"/"+aggregate+"-ingress"] {
		if len(bodies) != 2 {
			return policyDumpView{}, fmt.Errorf("workload compatibility policies have not all arrived")
		}
		body, err := json.Marshal(bodies)
		return policyDumpView{aggregated: true, body: string(body)}, err
	}
	return named, nil
}
