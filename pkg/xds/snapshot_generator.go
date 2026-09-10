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

package xds

import (
	"context"
	"fmt"
	"sort"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// SnapshotGenerator generates precompiled resources from store snapshots and incremental updates.
type SnapshotGenerator struct{}

func (SnapshotGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if request.TypeURL == "" {
		return GeneratedDelta{}, fmt.Errorf("generation type URL is required")
	}
	if request.Full {
		return generateSnapshotDiff(request), nil
	}
	return generateSnapshotIncremental(request), nil
}

func generateSnapshotDiff(request GenerationRequest) GeneratedDelta {
	selected := make(map[string]model.Resource)
	for _, resource := range selectGeneric(
		request.Scope, request.Snapshot, request.TypeURL, selectionNames(request.Subscription),
	) {
		selected[resource.XDSName] = resource
	}
	return diffSelected(request.Subscription, selected)
}

func generateSnapshotIncremental(request GenerationRequest) GeneratedDelta {
	var changes []model.ResourceChange
	if request.Subscription.Wildcard() {
		changes = request.Update.ReadOnlyChangesForType(request.TypeURL)
	} else {
		changes = request.Update.ChangesForNames(request.TypeURL, request.Subscription.Names())
	}

	selected := make(map[string]model.Resource, len(changes))
	removedSet := sets.New[string]()
	for _, change := range changes {
		oldSelected := change.Old != nil && scopeAllows(request.Scope, *change.Old) && request.Subscription.allows(*change.Old)
		newSelected := change.New != nil && scopeAllows(request.Scope, *change.New) && request.Subscription.allows(*change.New)
		if newSelected {
			selected[change.New.XDSName] = *change.New
		}
		if oldSelected && (!newSelected || change.Old.XDSName != change.New.XDSName) {
			if _, sent := request.Subscription.SentVersion(change.Old.XDSName); sent {
				removedSet.Insert(change.Old.XDSName)
			}
		}
	}

	resources := make([]model.Resource, 0, len(selected))
	for name, resource := range selected {
		removedSet.Delete(name)
		if version, found := request.Subscription.SentVersion(name); found && version == resource.Hash {
			continue
		}
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].XDSName < resources[j].XDSName })
	removed := make([]string, 0, len(removedSet))
	for name := range removedSet {
		removed = append(removed, name)
	}
	sort.Strings(removed)
	return GeneratedDelta{Resources: resources, Removed: removed}
}
