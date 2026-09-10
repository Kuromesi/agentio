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
	"strings"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
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
	return nil
}

// validatedDomainInputs validates endpoints and explicit runtimes independently.
func validatedDomainInputs(inputs Inputs, failures *failureRecorder, options collectionOptions) Inputs {
	clearFailureOnSourceDelete(inputs.Workloads, failures, "Workload")
	inputs.Workloads = krt.NewCollection(inputs.Workloads, func(_ krt.HandlerContext, workload model.Workload) *model.Workload {
		if err := validateDiscoveredWorkload(workload); err != nil {
			failures.record("Workload", workload.UID, err)
			return nil
		}
		failures.clear("Workload", workload.UID)
		return &workload
	}, options("validated-workloads")...)
	clearFailureOnSourceDelete(inputs.Sandboxes, failures, "Sandbox")
	inputs.Sandboxes = krt.NewCollection(inputs.Sandboxes, func(_ krt.HandlerContext, sandbox model.Sandbox) *model.Sandbox {
		if err := sandbox.Validate(); err != nil {
			failures.record("Sandbox", sandbox.UID, err)
			return nil
		}
		failures.clear("Sandbox", sandbox.UID)
		return &sandbox
	}, options("validated-sandboxes")...)
	return inputs
}
