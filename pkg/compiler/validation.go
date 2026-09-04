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
	"fmt"
	"sort"
	"strings"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/util/sets"
)

func validateDiscoveredWorkload(workload model.Workload) error {
	if strings.TrimSpace(workload.UID) == "" {
		return fmt.Errorf("workload UID is required")
	}
	switch workload.Principal.Kind {
	case "":
		if workload.Principal != (model.Principal{}) {
			return fmt.Errorf("principal: identity fields require a kind")
		}
	case model.PrincipalServiceAccount:
	default:
		return fmt.Errorf("principal: unknown identity kind %q", workload.Principal.Kind)
	}
	if err := workload.TunnelProtocol.Validate(); err != nil {
		return err
	}
	seen := sets.NewWithLength[string](len(workload.SandboxBindings))
	for index, binding := range workload.SandboxBindings {
		if err := binding.Validate(); err != nil {
			return fmt.Errorf("sandbox binding %d: %w", index, err)
		}
		if seen.Contains(binding.SandboxUID) {
			return fmt.Errorf("sandbox binding %q is duplicated", binding.SandboxUID)
		}
		seen.Insert(binding.SandboxUID)
	}
	return nil
}

// validatedDomainInputs filters Workloads that are invalid or ambiguously owned.
func validatedDomainInputs(inputs Inputs, failures *failureRecorder, options collectionOptions) Inputs {
	rawWorkloads := inputs.Workloads
	clearFailureOnSourceDelete(rawWorkloads, failures, "Workload")
	workloadsBySandbox := krt.NewIndex(rawWorkloads, "workloadsBySandbox",
		func(workload model.Workload) []string {
			result := make([]string, 0, len(workload.SandboxBindings))
			seen := sets.NewWithLength[string](len(workload.SandboxBindings))
			for _, binding := range workload.SandboxBindings {
				if binding.SandboxUID == "" {
					continue
				}
				if seen.Contains(binding.SandboxUID) {
					continue
				}
				seen.Insert(binding.SandboxUID)
				result = append(result, binding.SandboxUID)
			}
			return result
		})
	inputs.Workloads = krt.NewCollection(rawWorkloads,
		func(ctx krt.HandlerContext, workload model.Workload) *model.Workload {
			if err := validateDiscoveredWorkload(workload); err != nil {
				failures.record("Workload", workload.ResourceName(), err)
				return nil
			}

			conflicts := make([]string, 0)
			for _, binding := range workload.SandboxBindings {
				for _, owner := range krt.Fetch(ctx, rawWorkloads,
					krt.FilterIndex(workloadsBySandbox, binding.SandboxUID)) {
					if owner.UID != workload.UID {
						conflicts = append(conflicts,
							fmt.Sprintf("%s (Sandbox %s)", owner.UID, binding.SandboxUID))
					}
				}
			}
			if len(conflicts) > 0 {
				sort.Strings(conflicts)
				failures.record("Workload", workload.ResourceName(),
					fmt.Errorf("sandbox bindings conflict with active workloads %v", conflicts))
				return nil
			}

			failures.clear("Workload", workload.ResourceName())
			return &workload
		}, options("validated-workloads")...)
	return inputs
}
