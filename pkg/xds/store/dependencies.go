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

package store

import (
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// indexDerivedSelectionChanges wakes dependent watches when Address scope or
// Sandbox gateway dependencies change.
func indexDerivedSelectionChanges(types sets.Set[string], change model.ResourceChange) {
	if change.Key.TypeURL == model.SandboxType && sandboxGatewayFactsChanged([]model.ResourceChange{change}) {
		types.Insert(model.AddressType)
		types.Insert(model.WorkloadType)
	}
	if change.Key.TypeURL != model.AddressType {
		return
	}
	for _, resource := range []*model.Resource{change.Old, change.New} {
		if resource == nil {
			continue
		}
		if resource.Facts.Workload != nil {
			types.Insert(model.WorkloadType)
			types.Insert(model.WorkloadAuthorizationType)
			types.Insert(model.SandboxType)
		}
		if resource.Facts.Service != nil {
			// Service changes must wake Workload watches: on-demand names
			// resolve through Address resources.
			types.Insert(model.WorkloadType)
		}
	}
}

func sandboxGatewayFactsChanged(changes []model.ResourceChange) bool {
	for _, change := range changes {
		if change.Old != nil && change.New != nil && change.Old.Facts.Equal(change.New.Facts) {
			continue
		}
		for _, r := range []*model.Resource{change.Old, change.New} {
			if r != nil && r.Facts.Sandbox != nil && len(r.Facts.Sandbox.GatewayReferences) > 0 {
				return true
			}
		}
	}
	return false
}

// SandboxGatewayFactsChanged reports whether this update can change the
// visibility of gateways referenced by Sandboxes, including attester changes.
func (u Update) SandboxGatewayFactsChanged() bool {
	return sandboxGatewayFactsChanged(u.changesByType[model.SandboxType])
}
