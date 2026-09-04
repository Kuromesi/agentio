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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"maps"
	"slices"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"
)

const (
	ClusterType                = "type.googleapis.com/envoy.config.cluster.v3.Cluster"
	EndpointType               = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment"
	ListenerType               = "type.googleapis.com/envoy.config.listener.v3.Listener"
	RouteType                  = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration"
	SecretType                 = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
	ExtensionConfigurationType = "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig"
	ProxyConfigType            = "type.googleapis.com/istio.mesh.v1alpha1.ProxyConfig"
	AddressType                = "type.googleapis.com/istio.workload.Address"
	WorkloadType               = "type.googleapis.com/istio.workload.Workload"
	WorkloadAuthorizationType  = "type.googleapis.com/istio.security.Authorization"
	SniTrafficPolicyType       = "type.googleapis.com/kruise.networking.extensions.v1.SniTrafficPolicy"
)

type AuthorizationScope uint8

const (
	AuthorizationScopeWorkload AuthorizationScope = iota + 1
	AuthorizationScopeNamespace
	AuthorizationScopeGlobal
)

// ResourceFacts is the immutable selection metadata carried beside one wire
// resource. It records domain and graph facts only; pkg/xds decides which
// authenticated client classes may consume them.
type ResourceFacts struct {
	Workload      *WorkloadResourceFacts
	Service       *ServiceResourceFacts
	Authorization *AuthorizationResourceFacts
	GatewayOwner  string
}

type WorkloadResourceFacts struct {
	SandboxUID        string
	NodeName          string
	Principal         Principal
	ServiceKeys       []string
	GatewayReferences []string
	AuthorizationRefs []string
}

type ServiceResourceFacts struct {
	ServiceKey string
}

type AuthorizationResourceFacts struct {
	Scope     AuthorizationScope
	Namespace string
}

// WorkloadQuery matches the conjunction of its populated fields. It is the
// typed query seam over Workload facts; arbitrary cross-family combinations
// are intentionally not representable.
type WorkloadQuery struct {
	SandboxUID             string
	NodeName               string
	Principal              *Principal
	Namespace              string
	ServiceKey             string
	GatewayReference       string
	AuthorizationReference string
}

func (r Resource) IsWorkloadAddress() bool {
	return r.Facts.Workload != nil
}

type ResourceKey struct {
	TypeURL string
	Name    string
}

// ResourceChange is the immutable boundary between the KRT resource graph and
// the push pipeline. New is nil for a deletion. Old is populated on published
// updates so a connection can withdraw a resource whose wire name or scope
// changed without scanning the complete snapshot.
type ResourceChange struct {
	Key ResourceKey
	Old *Resource
	New *Resource
}

// Resource is an immutable, pre-hashed xDS resource; Value is shared by reference and must not be mutated.
type Resource struct {
	Key ResourceKey
	// XDSName is the name exposed on the xDS wire. It may differ from Key.Name
	// when gateway-scoped resources share an Envoy name but not their contents.
	// Empty means Key.Name.
	XDSName string
	Value   *anypb.Any
	Aliases []string
	Hash    string
	Facts   ResourceFacts
}

// ResourceName makes Resource usable as a krt collection member. Type URL and
// name together are what uniquely identify a resource; Key.Name alone is not
// unique across types.
func (r Resource) ResourceName() string {
	return r.Key.TypeURL + "|" + r.Key.Name
}

// Equals reports whether two resources are interchangeable. Hash covers the type
// URL, both names, the encoded value, the aliases, and the selection facts, so hash
// equality is full equality and krt can use it to suppress no-op events.
func (r Resource) Equals(other Resource) bool {
	return r.Hash == other.Hash
}

// NewResource validates and hashes a resource once, at construction. Producers
// should build resources through this function so that assembling a snapshot
// never has to re-encode or re-hash anything.
func NewResource(key ResourceKey, xdsName string, value *anypb.Any, aliases []string, facts ResourceFacts) (Resource, error) {
	return normalizeResource(Resource{
		Key:     key,
		XDSName: xdsName,
		Value:   value,
		Aliases: aliases,
		Facts:   facts,
	})
}

type ResourceSet struct {
	resources map[string]*resourceTypeIndex
	version   string
	length    int
}

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

// NewResourceSet indexes resources by type and name; pre-hashed resources are validated but not re-normalized.
func NewResourceSet(resources []Resource) (ResourceSet, error) {
	result := ResourceSet{resources: make(map[string]*resourceTypeIndex)}
	for _, resource := range resources {
		normalized := resource
		if normalized.Hash == "" {
			var err error
			normalized, err = normalizeResource(resource)
			if err != nil {
				return ResourceSet{}, err
			}
		} else if err := validateResource(normalized); err != nil {
			return ResourceSet{}, err
		}
		index := result.resources[normalized.Key.TypeURL]
		if index == nil {
			index = &resourceTypeIndex{}
			result.resources[normalized.Key.TypeURL] = index
		}
		shardID := resourceShard(normalized.Key.Name)
		if index.shards[shardID] == nil {
			index.shards[shardID] = make(map[string]Resource)
		}
		if _, found := index.shards[shardID][normalized.Key.Name]; found {
			return ResourceSet{}, fmt.Errorf("duplicate resource %s/%s", normalized.Key.TypeURL, normalized.Key.Name)
		}
		index.shards[shardID][normalized.Key.Name] = normalized
		indexResourceLookups(index, normalized)
		index.length++
		result.length++
	}
	for _, index := range result.resources {
		finalizeLookupIndex(&index.lookup)
		finalizeLookupIndex(&index.facts)
	}
	result.version = result.computeVersion()
	return result, nil
}

func validateResource(resource Resource) error {
	if strings.TrimSpace(resource.Key.TypeURL) == "" {
		return fmt.Errorf("resource type URL is required")
	}
	if strings.TrimSpace(resource.Key.Name) == "" {
		return fmt.Errorf("resource name is required")
	}
	if resource.Value == nil {
		return fmt.Errorf("resource %s/%s has no value", resource.Key.TypeURL, resource.Key.Name)
	}
	if resource.Value.TypeUrl != resource.Key.TypeURL {
		return fmt.Errorf(
			"resource %s/%s value type URL %q does not match key",
			resource.Key.TypeURL, resource.Key.Name, resource.Value.TypeUrl,
		)
	}
	return validateResourceFacts(resource.Key, resource.Facts)
}

func validateResourceFacts(key ResourceKey, facts ResourceFacts) error {
	families := 0
	if facts.Workload != nil {
		families++
	}
	if facts.Service != nil {
		families++
	}
	if facts.Authorization != nil {
		families++
	}
	if families > 1 {
		return fmt.Errorf("resource %s/%s carries incompatible resource facts", key.TypeURL, key.Name)
	}
	if facts.Workload != nil {
		if key.TypeURL != AddressType && key.TypeURL != WorkloadType {
			return fmt.Errorf("resource %s/%s carries Workload facts", key.TypeURL, key.Name)
		}
		if facts.Workload.SandboxUID != strings.TrimSpace(facts.Workload.SandboxUID) {
			return fmt.Errorf("resource %s/%s Workload facts contain a non-canonical sandbox UID", key.TypeURL, key.Name)
		}
		if facts.Workload.NodeName != strings.TrimSpace(facts.Workload.NodeName) {
			return fmt.Errorf("resource %s/%s Workload facts contain a non-canonical node name", key.TypeURL, key.Name)
		}
		if err := validateWorkloadResourcePrincipal(facts.Workload.Principal); err != nil {
			return fmt.Errorf("resource %s/%s Workload principal: %w", key.TypeURL, key.Name, err)
		}
		for label, values := range map[string][]string{
			"Service":       facts.Workload.ServiceKeys,
			"Gateway":       facts.Workload.GatewayReferences,
			"Authorization": facts.Workload.AuthorizationRefs,
		} {
			for _, value := range values {
				if strings.TrimSpace(value) == "" {
					return fmt.Errorf("resource %s/%s Workload facts contain an empty %s key", key.TypeURL, key.Name, label)
				}
			}
		}
	}
	if facts.Service != nil {
		if key.TypeURL != AddressType {
			return fmt.Errorf("resource %s/%s carries Service facts", key.TypeURL, key.Name)
		}
		if strings.TrimSpace(facts.Service.ServiceKey) == "" {
			return fmt.Errorf("resource %s/%s Service facts require a service key", key.TypeURL, key.Name)
		}
	}
	if facts.Authorization != nil {
		if key.TypeURL != WorkloadAuthorizationType {
			return fmt.Errorf("resource %s/%s carries Authorization facts", key.TypeURL, key.Name)
		}
		switch facts.Authorization.Scope {
		case AuthorizationScopeGlobal, AuthorizationScopeWorkload:
			if facts.Authorization.Namespace != "" {
				return fmt.Errorf("resource %s/%s %v Authorization must not carry a namespace", key.TypeURL, key.Name, facts.Authorization.Scope)
			}
		case AuthorizationScopeNamespace:
			if strings.TrimSpace(facts.Authorization.Namespace) == "" {
				return fmt.Errorf("resource %s/%s namespace Authorization requires a namespace", key.TypeURL, key.Name)
			}
		default:
			return fmt.Errorf("resource %s/%s has unknown Authorization scope %d", key.TypeURL, key.Name, facts.Authorization.Scope)
		}
	}

	switch key.TypeURL {
	case AddressType:
		if facts.Workload == nil && facts.Service == nil {
			return fmt.Errorf("Address resource %s requires Workload or Service facts", key.Name)
		}
	case WorkloadType:
		if facts.Workload == nil {
			return fmt.Errorf("Workload resource %s requires Workload facts", key.Name)
		}
	case WorkloadAuthorizationType:
		if facts.Authorization == nil {
			return fmt.Errorf("Authorization resource %s requires Authorization facts", key.Name)
		}
	default:
		if families != 0 {
			return fmt.Errorf("resource %s/%s carries facts for another resource family", key.TypeURL, key.Name)
		}
	}

	if facts.GatewayOwner != "" {
		if strings.TrimSpace(facts.GatewayOwner) != facts.GatewayOwner {
			return fmt.Errorf("resource %s/%s carries a non-canonical Gateway owner", key.TypeURL, key.Name)
		}
		switch key.TypeURL {
		case AddressType, WorkloadType, ClusterType, EndpointType, ListenerType, RouteType,
			SecretType, ExtensionConfigurationType, ProxyConfigType:
		default:
			return fmt.Errorf("resource %s/%s cannot be owned by a Gateway", key.TypeURL, key.Name)
		}
	}
	return nil
}

func validateWorkloadResourcePrincipal(principal Principal) error {
	switch principal.Kind {
	case "":
		if principal != (Principal{}) {
			return fmt.Errorf("identity fields require a kind")
		}
	case PrincipalServiceAccount:
		return nil
	default:
		return fmt.Errorf("unknown identity kind %q", principal.Kind)
	}
	return nil
}

func cloneResourceFacts(facts ResourceFacts) ResourceFacts {
	result := ResourceFacts{GatewayOwner: facts.GatewayOwner}
	if facts.Workload != nil {
		workload := *facts.Workload
		workload.ServiceKeys = append([]string(nil), workload.ServiceKeys...)
		workload.GatewayReferences = append([]string(nil), workload.GatewayReferences...)
		workload.AuthorizationRefs = append([]string(nil), workload.AuthorizationRefs...)
		result.Workload = &workload
	}
	if facts.Service != nil {
		service := *facts.Service
		result.Service = &service
	}
	if facts.Authorization != nil {
		authorization := *facts.Authorization
		result.Authorization = &authorization
	}
	return result
}

func normalizeResourceFacts(facts *ResourceFacts) {
	if facts.Workload == nil {
		return
	}
	facts.Workload.ServiceKeys = sortedUnique(facts.Workload.ServiceKeys)
	facts.Workload.GatewayReferences = sortedUnique(facts.Workload.GatewayReferences)
	facts.Workload.AuthorizationRefs = sortedUnique(facts.Workload.AuthorizationRefs)
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	return compactSorted(values)
}

func hashResourceFacts(hasher hash.Hash, facts ResourceFacts) {
	write := func(tag, value string) {
		hasher.Write([]byte{0})
		hasher.Write([]byte(tag))
		hasher.Write([]byte{0})
		hasher.Write([]byte(value))
	}
	if facts.Workload != nil {
		write("family", "workload")
		write("sandbox", facts.Workload.SandboxUID)
		write("node", facts.Workload.NodeName)
		write("principal", facts.Workload.Principal.String())
		for _, value := range facts.Workload.ServiceKeys {
			write("service", value)
		}
		for _, value := range facts.Workload.GatewayReferences {
			write("gateway-reference", value)
		}
		for _, value := range facts.Workload.AuthorizationRefs {
			write("authorization-reference", value)
		}
	}
	if facts.Service != nil {
		write("family", "service")
		write("service", facts.Service.ServiceKey)
	}
	if facts.Authorization != nil {
		write("family", "authorization")
		write("authorization-scope", fmt.Sprintf("%d", facts.Authorization.Scope))
		write("authorization-namespace", facts.Authorization.Namespace)
	}
	if facts.GatewayOwner != "" {
		write("gateway-owner", facts.GatewayOwner)
	}
}

func (facts ResourceFacts) Equal(other ResourceFacts) bool {
	if facts.GatewayOwner != other.GatewayOwner ||
		(facts.Workload == nil) != (other.Workload == nil) ||
		(facts.Service == nil) != (other.Service == nil) ||
		(facts.Authorization == nil) != (other.Authorization == nil) {
		return false
	}
	if facts.Workload != nil &&
		(facts.Workload.SandboxUID != other.Workload.SandboxUID ||
			facts.Workload.NodeName != other.Workload.NodeName ||
			facts.Workload.Principal != other.Workload.Principal ||
			!slices.Equal(facts.Workload.ServiceKeys, other.Workload.ServiceKeys) ||
			!slices.Equal(facts.Workload.GatewayReferences, other.Workload.GatewayReferences) ||
			!slices.Equal(facts.Workload.AuthorizationRefs, other.Workload.AuthorizationRefs)) {
		return false
	}
	if facts.Service != nil && *facts.Service != *other.Service {
		return false
	}
	return facts.Authorization == nil || *facts.Authorization == *other.Authorization
}

func normalizeResource(resource Resource) (Resource, error) {
	if err := validateResource(resource); err != nil {
		return Resource{}, err
	}

	// The single defensive copy in the lifetime of a resource: from here on the
	// value belongs to the Resource and is shared with every reader.
	cloned := Resource{
		Key:     resource.Key,
		XDSName: resource.XDSName,
		Value:   proto.Clone(resource.Value).(*anypb.Any),
		Aliases: append([]string(nil), resource.Aliases...),
		Facts:   cloneResourceFacts(resource.Facts),
	}
	if cloned.XDSName == "" {
		cloned.XDSName = cloned.Key.Name
	}
	sort.Strings(cloned.Aliases)
	normalizeResourceFacts(&cloned.Facts)
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(cloned.Value)
	if err != nil {
		return Resource{}, fmt.Errorf("marshal resource %s/%s: %w", resource.Key.TypeURL, resource.Key.Name, err)
	}
	hasher := sha256.New()
	hasher.Write([]byte(cloned.Key.TypeURL))
	hasher.Write([]byte{0})
	hasher.Write([]byte(cloned.Key.Name))
	hasher.Write([]byte{0})
	hasher.Write([]byte(cloned.XDSName))
	hasher.Write([]byte{0})
	hasher.Write(encoded)
	for _, alias := range cloned.Aliases {
		hasher.Write([]byte{0})
		hasher.Write([]byte(alias))
	}
	hashResourceFacts(hasher, cloned.Facts)
	cloned.Hash = hex.EncodeToString(hasher.Sum(nil))
	return cloned, nil
}

func (s ResourceSet) Version() string {
	return s.version
}

func (s ResourceSet) Len() int {
	return s.length
}

// Get returns a resource by key. The result shares storage with the set and
// must not be mutated.
func (s ResourceSet) Get(key ResourceKey) (Resource, bool) {
	index := s.resources[key.TypeURL]
	if index == nil {
		return Resource{}, false
	}
	resource, found := index.shards[resourceShard(key.Name)][key.Name]
	if !found {
		return Resource{}, false
	}
	return resource, true
}

// Lookup returns resources addressed by a canonical key, wire name, or alias.
// It uses the immutable lookup index and never scans the type snapshot.
func (s ResourceSet) Lookup(typeURL, name string) []Resource {
	index := s.resources[typeURL]
	if index == nil || name == "" {
		return nil
	}
	names := append([]string(nil), lookupNames(&index.lookup, name)...)
	if resource, found := s.Get(ResourceKey{TypeURL: typeURL, Name: name}); found {
		names = append(names, resource.Key.Name)
	}
	return resourcesForNames(index, names)
}

func (s ResourceSet) ListWorkloads(typeURL string, query WorkloadQuery) []Resource {
	index := s.resources[typeURL]
	keys, valid := workloadQueryFactKeys(query)
	if index == nil || !valid {
		return nil
	}
	candidates := smallestPosting(&index.facts, keys)
	if len(candidates) == 0 {
		return nil
	}
	// Fact postings are already sorted and unique, so resolve them directly without rebuilding a set and sorting it.
	result := make([]Resource, 0, len(candidates))
	for _, name := range candidates {
		resource, found := index.shards[resourceShard(name)][name]
		if found && workloadMatchesQuery(resource.Facts.Workload, query) {
			result = append(result, resource)
		}
	}
	return result
}

func (s ResourceSet) HasWorkload(typeURL string, query WorkloadQuery) bool {
	index := s.resources[typeURL]
	keys, valid := workloadQueryFactKeys(query)
	if index == nil || !valid {
		return false
	}
	for _, name := range smallestPosting(&index.facts, keys) {
		resource, found := index.shards[resourceShard(name)][name]
		if found && workloadMatchesQuery(resource.Facts.Workload, query) {
			return true
		}
	}
	return false
}

func (s ResourceSet) ListServiceMembers(typeURL, serviceKey string) []Resource {
	return s.listByFact(typeURL, resourceFactService, serviceKey)
}

func (s ResourceSet) ListResourcesOwnedByGateway(typeURL, gatewayKey string) []Resource {
	return s.listByFact(typeURL, resourceFactGatewayOwner, gatewayKey)
}

func (s ResourceSet) ListGlobalAuthorizations() []Resource {
	return s.listByFact(WorkloadAuthorizationType, resourceFactAuthorizationGlobal, "global")
}

func (s ResourceSet) ListNamespaceAuthorizations(namespace string) []Resource {
	return s.listByFact(WorkloadAuthorizationType, resourceFactAuthorizationNamespace, namespace)
}

func (s ResourceSet) listByFact(typeURL string, kind resourceFactKind, key string) []Resource {
	index := s.resources[typeURL]
	if index == nil || key == "" {
		return nil
	}
	return resourcesForNames(index, lookupNames(&index.facts, resourceFactIndexKey(kind, key)))
}

// List returns every resource of a type, ordered by name. The results share
// storage with the set and must not be mutated.
func (s ResourceSet) List(typeURL string) []Resource {
	index := s.resources[typeURL]
	if index == nil {
		return nil
	}
	result := make([]Resource, 0, index.length)
	for _, shard := range index.shards {
		for _, resource := range shard {
			result = append(result, resource)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key.Name < result[j].Key.Name })
	return result
}

func (s ResourceSet) Types() []string {
	result := make([]string, 0, len(s.resources))
	for typeURL := range s.resources {
		result = append(result, typeURL)
	}
	sort.Strings(result)
	return result
}

// CountsByType returns snapshot cardinality without allocating every resource.
func (s ResourceSet) CountsByType() map[string]int {
	result := make(map[string]int, len(s.resources))
	for typeURL, index := range s.resources {
		result[typeURL] = index.length
	}
	return result
}

// Apply returns a new immutable snapshot by copying only the shards that contain
// an effective change. This keeps steady-state work bounded even when Address
// and Workload contain hundreds of thousands of resources.
func (s ResourceSet) Apply(changes []ResourceChange) (ResourceSet, bool, error) {
	if len(changes) == 0 {
		return s, false, nil
	}
	resources := make(map[string]*resourceTypeIndex, len(s.resources))
	maps.Copy(resources, s.resources)
	clonedTypes := make(map[string]*resourceTypeIndex)
	type shardKey struct {
		typeURL string
		shard   uint16
	}
	clonedShards := sets.New[shardKey]()
	clonedLookupShards := sets.New[lookupShardKey]()
	effective := make([]ResourceChange, 0, len(changes))
	length := s.length
	for _, change := range changes {
		if strings.TrimSpace(change.Key.TypeURL) == "" || strings.TrimSpace(change.Key.Name) == "" {
			return ResourceSet{}, false, fmt.Errorf("resource change key is required")
		}
		index := resources[change.Key.TypeURL]
		shardID := resourceShard(change.Key.Name)
		var currentShard map[string]Resource
		if index != nil {
			currentShard = index.shards[shardID]
		}
		current, found := currentShard[change.Key.Name]
		if change.New == nil {
			if !found {
				continue
			}
		} else {
			if change.New.Key != change.Key {
				return ResourceSet{}, false, fmt.Errorf("resource change key %v does not match new resource key %v", change.Key, change.New.Key)
			}
			normalized := *change.New
			if normalized.Hash == "" {
				var err error
				normalized, err = normalizeResource(normalized)
				if err != nil {
					return ResourceSet{}, false, err
				}
			} else if err := validateResource(normalized); err != nil {
				return ResourceSet{}, false, err
			}
			if found && current.Hash == normalized.Hash {
				continue
			}
			change.New = &normalized
		}

		if _, cloned := clonedTypes[change.Key.TypeURL]; !cloned {
			copied := &resourceTypeIndex{}
			if index != nil {
				*copied = *index
			}
			index = copied
			resources[change.Key.TypeURL] = index
			clonedTypes[change.Key.TypeURL] = index
		} else {
			index = clonedTypes[change.Key.TypeURL]
		}
		key := shardKey{typeURL: change.Key.TypeURL, shard: shardID}
		if !clonedShards.Contains(key) {
			original := index.shards[shardID]
			copied := make(map[string]Resource, len(original)+1)
			maps.Copy(copied, original)
			index.shards[shardID] = copied
			clonedShards.Insert(key)
		}
		old := current
		if found {
			change.Old = &old
		}
		updateResourceLookupDiff(index, change.Old, change.New, change.Key.TypeURL, clonedLookupShards)
		if change.New == nil {
			delete(index.shards[shardID], change.Key.Name)
			index.length--
			length--
		} else {
			index.shards[shardID][change.Key.Name] = *change.New
			if !found {
				index.length++
				length++
			}
		}
		effective = append(effective, change)
	}
	if len(effective) == 0 {
		return s, false, nil
	}
	for typeURL, index := range clonedTypes {
		if index.length == 0 {
			delete(resources, typeURL)
		}
	}
	return ResourceSet{resources: resources, version: incrementalVersion(s.version, effective), length: length}, true, nil
}

// Diff describes the key-level difference from s to next. It is intended for
// startup and recovery publication; the normal KRT path already supplies these
// changes and does not call Diff.
func (s ResourceSet) Diff(next ResourceSet) []ResourceChange {
	changes := make([]ResourceChange, 0)
	for typeURL, currentIndex := range s.resources {
		for _, currentShard := range currentIndex.shards {
			for name, current := range currentShard {
				updated, found := next.Get(ResourceKey{TypeURL: typeURL, Name: name})
				if found && updated.Hash == current.Hash {
					continue
				}
				old := current
				change := ResourceChange{Key: current.Key, Old: &old}
				if found {
					newResource := updated
					change.New = &newResource
				}
				changes = append(changes, change)
			}
		}
	}
	for typeURL, nextIndex := range next.resources {
		for _, nextShard := range nextIndex.shards {
			for name, resource := range nextShard {
				if _, found := s.Get(ResourceKey{TypeURL: typeURL, Name: name}); found {
					continue
				}
				newResource := resource
				changes = append(changes, ResourceChange{Key: resource.Key, New: &newResource})
			}
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Key.TypeURL != changes[j].Key.TypeURL {
			return changes[i].Key.TypeURL < changes[j].Key.TypeURL
		}
		return changes[i].Key.Name < changes[j].Key.Name
	})
	return changes
}

func incrementalVersion(previous string, changes []ResourceChange) string {
	ordered := append([]ResourceChange(nil), changes...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Key.TypeURL != ordered[j].Key.TypeURL {
			return ordered[i].Key.TypeURL < ordered[j].Key.TypeURL
		}
		return ordered[i].Key.Name < ordered[j].Key.Name
	})
	hasher := sha256.New()
	hasher.Write([]byte(previous))
	for _, change := range ordered {
		hasher.Write([]byte{0})
		hasher.Write([]byte(change.Key.TypeURL))
		hasher.Write([]byte{0})
		hasher.Write([]byte(change.Key.Name))
		hasher.Write([]byte{0})
		if change.New == nil {
			hasher.Write([]byte("deleted"))
		} else {
			hasher.Write([]byte(change.New.Hash))
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// computeVersion folds every resource hash into one snapshot version. It reads
// the hashes straight out of the index: going through List would allocate and
// order the full resource set a second time for no benefit.
func (s ResourceSet) computeVersion() string {
	hasher := sha256.New()
	for _, typeURL := range s.Types() {
		for _, resource := range s.List(typeURL) {
			hasher.Write([]byte(resource.Hash))
			hasher.Write([]byte{0})
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
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
	resourceFactSandbox resourceFactKind = iota + 1
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
		add(resourceFactSandbox, workload.SandboxUID)
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
	if !add(resourceFactSandbox, query.SandboxUID) ||
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
		(query.SandboxUID != "" && workload.SandboxUID != query.SandboxUID) ||
		(query.NodeName != "" && workload.NodeName != query.NodeName) ||
		(query.Principal != nil && workload.Principal != *query.Principal) ||
		(query.Namespace != "" && (workload.Principal.Kind != PrincipalServiceAccount ||
			workload.Principal.ServiceAccount.Namespace != query.Namespace)) ||
		(query.ServiceKey != "" && !slices.Contains(workload.ServiceKeys, query.ServiceKey)) ||
		(query.GatewayReference != "" && !slices.Contains(workload.GatewayReferences, query.GatewayReference)) ||
		(query.AuthorizationReference != "" && !slices.Contains(workload.AuthorizationRefs, query.AuthorizationReference)) {
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
