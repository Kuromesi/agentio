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

package model

import (
	"maps"
	"slices"
	"sort"
	"strings"

	"istio.io/istio/pkg/util/sets"
)

const resourceShardCount = 1024

// resourceTypeIndex shards the otherwise very large Address/Workload maps.
// Applying one key copies one small shard and the fixed-size shard table, while
// unchanged shards remain shared by immutable snapshots already in use.
type resourceTypeIndex struct {
	shards [resourceShardCount]map[string]Resource
	lookup resourceLookupIndex
	facts  resourceLookupIndex
	length int
}

// resourceLookupIndex is sharded so one-key updates copy one shard only.
type resourceLookupIndex struct {
	shards [resourceShardCount]map[string][]string
}

type lookupShardKey struct {
	typeURL string
	kind    byte
	shard   uint16
}

func resourceShard(name string) uint16 {
	// FNV-1a is stable, fast, and sufficient for distributing resource names.
	var hash uint32 = 2166136261
	for i := 0; i < len(name); i++ {
		hash ^= uint32(name[i])
		hash *= 16777619
	}
	return uint16(hash & (resourceShardCount - 1))
}

type resourceFactKind byte

const (
	resourceFactWorkloadUID resourceFactKind = iota + 1
	resourceFactWorkloadPolicies
	resourceFactAttesterWorkloadUID
	resourceFactSourceUID
	resourceFactNode
	resourceFactPrincipal
	resourceFactNamespace
	resourceFactService
	resourceFactGatewayReference
	resourceFactAuthorizationReference
	resourceFactGatewayOwner
	resourceFactAuthorizationGlobal
	resourceFactAuthorizationNamespace
)

func resourceFactIndexKey(kind resourceFactKind, key string) string {
	return string([]byte{byte(kind)}) + "\x00" + key
}

func resourceFactKeys(resource Resource) []string {
	result := make([]string, 0, 8)
	add := func(kind resourceFactKind, key string) {
		if key != "" {
			result = append(result, resourceFactIndexKey(kind, key))
		}
	}
	if workload := resource.Facts.Workload; workload != nil {
		if !workload.SandboxManaged {
			add(resourceFactWorkloadPolicies, "enabled")
		}
		add(resourceFactWorkloadUID, workload.WorkloadUID)
		add(resourceFactSourceUID, workload.SourceUID)
		add(resourceFactNode, workload.NodeName)
		add(resourceFactPrincipal, workload.Principal.String())
		if workload.Principal.Kind == PrincipalServiceAccount {
			add(resourceFactNamespace, workload.Principal.ServiceAccount.Namespace)
		}
		for _, key := range workload.ServiceKeys {
			add(resourceFactService, key)
		}
		for _, key := range workload.GatewayReferences {
			add(resourceFactGatewayReference, key)
		}
		for _, key := range workload.AuthorizationRefs {
			add(resourceFactAuthorizationReference, key)
		}
	}
	if sandbox := resource.Facts.Sandbox; sandbox != nil {
		add(resourceFactAttesterWorkloadUID, sandbox.AttesterWorkloadUID)
		for _, key := range sandbox.GatewayReferences {
			add(resourceFactGatewayReference, key)
		}
	}
	if resource.Facts.Service != nil {
		add(resourceFactService, resource.Facts.Service.ServiceKey)
	}
	add(resourceFactGatewayOwner, resource.Facts.GatewayOwner)
	if authorization := resource.Facts.Authorization; authorization != nil {
		switch authorization.Scope {
		case AuthorizationScopeGlobal:
			add(resourceFactAuthorizationGlobal, "global")
		case AuthorizationScopeNamespace:
			add(resourceFactAuthorizationNamespace, authorization.Namespace)
		}
	}
	return result
}

func workloadQueryFactKeys(query WorkloadQuery) ([]string, bool) {
	keys := make([]string, 0, 7)
	add := func(kind resourceFactKind, key string) bool {
		if key == "" {
			return true
		}
		if strings.TrimSpace(key) == "" {
			return false
		}
		keys = append(keys, resourceFactIndexKey(kind, key))
		return true
	}
	if query.WorkloadPoliciesOnly {
		add(resourceFactWorkloadPolicies, "enabled")
	}
	if !add(resourceFactWorkloadUID, query.WorkloadUID) ||
		!add(resourceFactSourceUID, query.SourceUID) ||
		!add(resourceFactNode, query.NodeName) ||
		!add(resourceFactNamespace, query.Namespace) ||
		!add(resourceFactService, query.ServiceKey) ||
		!add(resourceFactGatewayReference, query.GatewayReference) ||
		!add(resourceFactAuthorizationReference, query.AuthorizationReference) {
		return nil, false
	}
	if query.Principal != nil {
		if err := query.Principal.Validate(); err != nil {
			return nil, false
		}
		keys = append(keys, resourceFactIndexKey(resourceFactPrincipal, query.Principal.String()))
	}
	return keys, len(keys) > 0
}

func smallestPosting(index *resourceLookupIndex, keys []string) []string {
	var candidates []string
	for _, key := range keys {
		names := lookupNames(index, key)
		if len(names) == 0 {
			return nil
		}
		if candidates == nil || len(names) < len(candidates) {
			candidates = names
		}
	}
	return candidates
}

func workloadMatchesQuery(workload *WorkloadResourceFacts, query WorkloadQuery) bool {
	if workload == nil ||
		(query.WorkloadPoliciesOnly && workload.SandboxManaged) ||
		(query.WorkloadUID != "" && workload.WorkloadUID != query.WorkloadUID) ||
		(query.SourceUID != "" && workload.SourceUID != query.SourceUID) ||
		(query.NodeName != "" && workload.NodeName != query.NodeName) ||
		(query.Principal != nil && workload.Principal != *query.Principal) ||
		(query.Namespace != "" && (workload.Principal.Kind != PrincipalServiceAccount ||
			workload.Principal.ServiceAccount.Namespace != query.Namespace)) ||
		!workloadReferencesMatch(workload, query) {
		return false
	}
	return true
}

func indexResourceLookups(index *resourceTypeIndex, resource Resource) {
	appendLookupName(&index.lookup, resource.XDSName, resource.Key.Name)
	for _, alias := range resource.Aliases {
		appendLookupName(&index.lookup, alias, resource.Key.Name)
	}
	for _, key := range resourceFactKeys(resource) {
		appendLookupName(&index.facts, key, resource.Key.Name)
	}
}

func appendLookupName(index *resourceLookupIndex, key, name string) {
	if key == "" || name == "" {
		return
	}
	shardID := resourceShard(key)
	if index.shards[shardID] == nil {
		index.shards[shardID] = make(map[string][]string)
	}
	index.shards[shardID][key] = append(index.shards[shardID][key], name)
}

func finalizeLookupIndex(index *resourceLookupIndex) {
	for shardID := range index.shards {
		for key, names := range index.shards[shardID] {
			sort.Strings(names)
			index.shards[shardID][key] = compactSorted(names)
		}
	}
}

func compactSorted(values []string) []string {
	if len(values) < 2 {
		return values
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if values[read] == values[write-1] {
			continue
		}
		values[write] = values[read]
		write++
	}
	return values[:write]
}

func lookupNames(index *resourceLookupIndex, key string) []string {
	return index.shards[resourceShard(key)][key]
}

func resourcesForNames(index *resourceTypeIndex, names []string) []Resource {
	if len(names) == 0 {
		return nil
	}
	unique := sets.NewWithLength[string](len(names))
	result := make([]Resource, 0, len(names))
	for _, name := range names {
		if unique.Contains(name) {
			continue
		}
		resource, found := index.shards[resourceShard(name)][name]
		if !found {
			continue
		}
		unique.Insert(name)
		result = append(result, resource)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key.Name < result[j].Key.Name })
	return result
}

type resourceLookupEntry struct {
	kind byte
	key  string
}

func resourceLookupEntries(resource *Resource) sets.Set[resourceLookupEntry] {
	entries := sets.New[resourceLookupEntry]()
	if resource == nil {
		return entries
	}
	add := func(kind byte, key string) {
		if key != "" {
			entries.Insert(resourceLookupEntry{kind: kind, key: key})
		}
	}
	add(0, resource.XDSName)
	for _, alias := range resource.Aliases {
		add(0, alias)
	}
	for _, key := range resourceFactKeys(*resource) {
		add(1, key)
	}
	return entries
}

func updateResourceLookupDiff(
	index *resourceTypeIndex,
	oldResource, newResource *Resource,
	typeURL string,
	cloned sets.Set[lookupShardKey],
) {
	oldEntries := resourceLookupEntries(oldResource)
	newEntries := resourceLookupEntries(newResource)
	name := ""
	if newResource != nil {
		name = newResource.Key.Name
	} else if oldResource != nil {
		name = oldResource.Key.Name
	}
	for entry := range oldEntries {
		if newEntries.Contains(entry) {
			continue
		}
		updateLookupMembership(index, entry, name, false, typeURL, cloned)
	}
	for entry := range newEntries {
		if oldEntries.Contains(entry) {
			continue
		}
		updateLookupMembership(index, entry, name, true, typeURL, cloned)
	}
}

func updateLookupMembership(
	index *resourceTypeIndex,
	entry resourceLookupEntry,
	name string,
	add bool,
	typeURL string,
	cloned sets.Set[lookupShardKey],
) {
	lookup := &index.lookup
	if entry.kind == 1 {
		lookup = &index.facts
	}
	outerShardID := resourceShard(entry.key)
	outerCloneKey := lookupShardKey{typeURL: typeURL, kind: entry.kind, shard: outerShardID}
	if !cloned.Contains(outerCloneKey) {
		original := lookup.shards[outerShardID]
		copied := make(map[string][]string, len(original)+1)
		maps.Copy(copied, original)
		lookup.shards[outerShardID] = copied
		cloned.Insert(outerCloneKey)
	}

	names := lookup.shards[outerShardID][entry.key]
	position := sort.SearchStrings(names, name)
	contains := position < len(names) && names[position] == name
	if add == contains {
		return
	}
	if add {
		updated := make([]string, len(names)+1)
		copy(updated, names[:position])
		updated[position] = name
		copy(updated[position+1:], names[position:])
		lookup.shards[outerShardID][entry.key] = updated
		return
	}
	if len(names) == 1 {
		delete(lookup.shards[outerShardID], entry.key)
		return
	}
	updated := make([]string, 0, len(names)-1)
	updated = append(updated, names[:position]...)
	updated = append(updated, names[position+1:]...)
	lookup.shards[outerShardID][entry.key] = updated
}

func workloadReferencesMatch(workload *WorkloadResourceFacts, query WorkloadQuery) bool {
	if (query.ServiceKey != "" && !slices.Contains(workload.ServiceKeys, query.ServiceKey)) ||
		(query.GatewayReference != "" && !slices.Contains(workload.GatewayReferences, query.GatewayReference)) ||
		(query.AuthorizationReference != "" && !slices.Contains(workload.AuthorizationRefs, query.AuthorizationReference)) {
		return false
	}
	return true
}
