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
	"maps"
	"slices"
	"sort"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// Identity retains selection metadata for an observed wire name, never its
// payload. Workloads records scopes whose dependencies made this name visible;
// wildcard Address watches use this evidence to withdraw resources without a
// per-connection table of everything previously sent.
type Identity struct {
	Name      string
	Facts     model.ResourceFacts
	Workloads sets.Set[WorkloadIdentity]
}

// WorkloadIdentity is the part of Workload facts that defines an authenticated
// client scope. It deliberately excludes policy and networking references.
type WorkloadIdentity struct {
	UID       string
	Source    model.SourceRef
	Principal model.Principal
	NodeName  string
}

func workloadIdentity(workload *model.WorkloadResourceFacts) WorkloadIdentity {
	return WorkloadIdentity{
		UID:       workload.WorkloadUID,
		Source:    workload.Source,
		Principal: workload.Principal,
		NodeName:  workload.NodeName,
	}
}

// Candidate identifies a resource to reselect from the current snapshot.
// Identities includes intermediate names and visibility, even across rollbacks.
type Candidate struct {
	Key        model.ResourceKey
	Identities []Identity
}

// Update is an immutable invalidation notice, not a delta to replay. Publications
// may be observed by Demand before their notices are consumed. Merging notices
// therefore unions candidates and never cancels changes by comparing endpoints.
type Update struct {
	version       string
	candidates    map[string][]Candidate
	affectedTypes sets.Set[string]
	full          bool
	fullTypes     sets.Set[string]
}

// Version identifies the most recent publication included in this notice.
func (u Update) Version() string { return u.version }

// Affects reports whether a watched type has candidates or needs a full refresh.
func (u Update) Affects(typeURL string) bool {
	return u.FullFor(typeURL) || u.affectedTypes.Contains(typeURL)
}

// FullFor reports whether a dynamic notification requires a full selection.
func (u Update) FullFor(typeURL string) bool {
	return u.full && (len(u.fullTypes) == 0 || u.fullTypes.Contains(typeURL))
}

// Candidates borrows the immutable, key-ordered invalidation index. Neither the
// slice nor its nested metadata may be modified. Direct Workloads are projected
// from Address candidates, so their source keys retain the Address type URL.
func (u Update) Candidates(typeURL string) []Candidate {
	if typeURL == model.WorkloadType {
		typeURL = model.AddressType
	}
	return u.candidates[typeURL]
}

func updateBetween(before, after model.ResourceSet, changes []model.ResourceChange) Update {
	candidates := make(map[model.ResourceKey]Candidate, len(changes))
	for _, change := range changes {
		for _, resource := range []*model.Resource{change.Old, change.New} {
			if resource != nil {
				addCandidate(candidates, *resource, nil)
			}
		}
		indexDependencies(candidates, before, after, change)
	}
	return indexedUpdate(after.Version(), candidates)
}

func indexedUpdate(version string, candidates map[model.ResourceKey]Candidate) Update {
	u := Update{version: version, candidates: make(map[string][]Candidate), affectedTypes: sets.New[string]()}
	for key, candidate := range candidates {
		u.candidates[key.TypeURL] = append(u.candidates[key.TypeURL], candidate)
		u.affectedTypes.Insert(key.TypeURL)
		if key.TypeURL == model.AddressType {
			u.affectedTypes.Insert(model.WorkloadType)
		}
	}
	for typeURL := range u.candidates {
		sort.Slice(u.candidates[typeURL], func(i, j int) bool {
			return u.candidates[typeURL][i].Key.Name < u.candidates[typeURL][j].Key.Name
		})
	}
	return u
}

func addCandidate(
	index map[model.ResourceKey]Candidate,
	resource model.Resource,
	workload *model.WorkloadResourceFacts,
) {
	candidate := index[resource.Key]
	candidate.Key = resource.Key
	identity := Identity{Name: resource.XDSName, Facts: resource.Facts}
	if workload != nil {
		identity.Workloads = sets.New(workloadIdentity(workload))
	}
	candidate.Identities = mergeIdentity(candidate.Identities, identity)
	index[resource.Key] = candidate
}

func mergeIdentity(identities []Identity, identity Identity) []Identity {
	for i, existing := range identities {
		if existing.Name != identity.Name || !existing.Facts.Equal(identity.Facts) {
			continue
		}
		if len(identity.Workloads) != 0 {
			if identities[i].Workloads == nil {
				identities[i].Workloads = sets.New[WorkloadIdentity]()
			}
			identities[i].Workloads.Merge(identity.Workloads)
		}
		return identities
	}
	return append(identities, identity)
}

// Merge unions already-published invalidations. Only Store.Apply may fold
// unobservable, pre-publication transitions into a net change.
func Merge(older, newer Update) Update {
	candidates := make(map[model.ResourceKey]Candidate)
	for _, u := range []Update{older, newer} {
		for _, batch := range u.candidates {
			for _, incoming := range batch {
				candidate, found := candidates[incoming.Key]
				if !found {
					// Disjoint candidates are immutable and remain shared across
					// subscriber mailboxes and scheduler queues.
					candidates[incoming.Key] = incoming
					continue
				}
				candidate.Identities = slices.Clone(candidate.Identities)
				for i := range candidate.Identities {
					candidate.Identities[i].Workloads = maps.Clone(candidate.Identities[i].Workloads)
				}
				for _, identity := range incoming.Identities {
					candidate.Identities = mergeIdentity(candidate.Identities, identity)
				}
				candidates[incoming.Key] = candidate
			}
		}
	}
	merged := indexedUpdate(newer.version, candidates)
	merged.full = older.full || newer.full
	if merged.full && !(older.full && len(older.fullTypes) == 0 || newer.full && len(newer.fullTypes) == 0) {
		merged.fullTypes = sets.New[string]()
		merged.fullTypes.Merge(older.fullTypes)
		merged.fullTypes.Merge(newer.fullTypes)
	}
	return merged
}

func coalesceChanges(changes []model.ResourceChange) []model.ResourceChange {
	indexed := make(map[model.ResourceKey]model.ResourceChange, len(changes))
	for _, change := range changes {
		if existing, found := indexed[change.Key]; found {
			change.Old = existing.Old
		}
		indexed[change.Key] = change
	}
	result := make([]model.ResourceChange, 0, len(indexed))
	for _, change := range indexed {
		if !sameResource(change.Old, change.New) {
			result = append(result, change)
		}
	}
	return result
}

func sameResource(left, right *model.Resource) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Hash == right.Hash
}
