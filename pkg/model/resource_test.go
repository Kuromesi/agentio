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
	"fmt"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestResourceSetVersionIgnoresInsertionOrder(t *testing.T) {
	a, err := NewResourceSet([]Resource{
		testResource(t, "b", "two"),
		testResource(t, "a", "one"),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewResourceSet([]Resource{
		testResource(t, "a", "one"),
		testResource(t, "b", "two"),
	})
	if err != nil {
		t.Fatal(err)
	}

	if a.Version() != b.Version() {
		t.Fatalf("versions differ: %s != %s", a.Version(), b.Version())
	}
}

// The set takes ownership of what it is given: a caller that keeps mutating the
// resource it passed in cannot reach inside the snapshot.
func TestResourceSetOwnsItsInput(t *testing.T) {
	resource := testWorkloadResource(t, "a", "one", "sandbox-a", "", nil, nil)
	set, err := NewResourceSet([]Resource{resource})
	if err != nil {
		t.Fatal(err)
	}
	version := set.Version()

	resource.Facts.Workload.SandboxUID = "mutated"
	resource.Value.Value[0] ^= 0xff

	stored, found := set.Get(resource.Key)
	if !found {
		t.Fatal("resource not found")
	}
	if stored.Facts.Workload.SandboxUID != "sandbox-a" {
		t.Fatalf("input mutation changed facts: %#v", stored.Facts)
	}
	if set.Version() != version {
		t.Fatalf("input mutation changed version: %s != %s", set.Version(), version)
	}
}

// Reads share storage with the set; do not reintroduce a per-read copy.
func TestResourceSetReadsShareStorage(t *testing.T) {
	resource := testWorkloadResource(t, "a", "one", "sandbox-a", "", nil, nil)
	set, err := NewResourceSet([]Resource{resource})
	if err != nil {
		t.Fatal(err)
	}

	first, found := set.Get(resource.Key)
	if !found {
		t.Fatal("resource not found")
	}
	second, found := set.Get(resource.Key)
	if !found {
		t.Fatal("resource not found on second read")
	}
	if first.Value != second.Value {
		t.Fatal("Get returned a copied value; reads must share the set's storage")
	}

	listed := set.List(resource.Key.TypeURL)
	if len(listed) != 1 {
		t.Fatalf("List returned %d resources, want 1", len(listed))
	}
	if listed[0].Value != first.Value {
		t.Fatal("List returned a copied value; reads must share the set's storage")
	}
}

// Hash is computed once at construction, so a resource built by NewResource
// carries a hash that NewResourceSet accepts without re-encoding it.
func TestNewResourceHashesOnceAndMatchesSetNormalization(t *testing.T) {
	raw := testWorkloadResource(t, "a", "one", "sandbox-a", "", nil, nil)

	prehashed, err := NewResource(raw.Key, raw.XDSName, raw.Value, raw.Aliases, raw.Facts)
	if err != nil {
		t.Fatal(err)
	}
	if prehashed.Hash == "" {
		t.Fatal("NewResource did not compute a hash")
	}

	// A set built from the raw resource normalizes it itself; both paths must
	// agree or a pre-hashed snapshot would get a different version.
	fromRaw, err := NewResourceSet([]Resource{raw})
	if err != nil {
		t.Fatal(err)
	}
	fromPrehashed, err := NewResourceSet([]Resource{prehashed})
	if err != nil {
		t.Fatal(err)
	}
	if fromRaw.Version() != fromPrehashed.Version() {
		t.Fatalf("version differs between normalization paths: %s != %s", fromRaw.Version(), fromPrehashed.Version())
	}

	stored, _ := fromRaw.Get(raw.Key)
	if stored.Hash != prehashed.Hash {
		t.Fatalf("hash differs between normalization paths: %s != %s", stored.Hash, prehashed.Hash)
	}
}

// Equals is what krt uses to suppress no-op events, so it must track every field
// the hash covers.
func TestResourceEqualsTracksContent(t *testing.T) {
	base := testWorkloadResource(t, "a", "one", "sandbox-a", "", nil, nil)
	same := testWorkloadResource(t, "a", "one", "sandbox-a", "", nil, nil)
	differentValue := testWorkloadResource(t, "a", "two", "sandbox-a", "", nil, nil)
	differentFacts := testWorkloadResource(t, "a", "one", "sandbox-b", "", nil, nil)

	normalize := func(r Resource) Resource {
		out, err := NewResource(r.Key, r.XDSName, r.Value, r.Aliases, r.Facts)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	if !normalize(base).Equals(normalize(same)) {
		t.Fatal("identical resources are not Equal")
	}
	if normalize(base).Equals(normalize(differentValue)) {
		t.Fatal("resources with different values are Equal")
	}
	if normalize(base).Equals(normalize(differentFacts)) {
		t.Fatal("resources with different facts are Equal")
	}
}

// ResourceName must distinguish resources that share a name across types, since
// krt keys collection members by it.
func TestResourceNameSeparatesTypes(t *testing.T) {
	address := Resource{Key: ResourceKey{TypeURL: AddressType, Name: "same"}}
	workload := Resource{Key: ResourceKey{TypeURL: WorkloadType, Name: "same"}}
	if address.ResourceName() == workload.ResourceName() {
		t.Fatalf("ResourceName collides across types: %s", address.ResourceName())
	}
}

func TestResourceSetRejectsDuplicateKeys(t *testing.T) {
	_, err := NewResourceSet([]Resource{
		testResource(t, "a", "one"),
		testResource(t, "a", "two"),
	})
	if err == nil {
		t.Fatal("duplicate resource key accepted")
	}
}

func TestResourceSetPreservesScopedWireName(t *testing.T) {
	resource := testResource(t, "gateway-a/main_internal", "value")
	resource.XDSName = "main_internal"
	set, err := NewResourceSet([]Resource{resource})
	if err != nil {
		t.Fatalf("NewResourceSet: %v", err)
	}
	got, found := set.Get(resource.Key)
	if !found {
		t.Fatal("resource not found")
	}
	if got.XDSName != "main_internal" {
		t.Fatalf("wire name = %q", got.XDSName)
	}
}

// Applying one compiled KRT event must update only that key without rebuilding
// the set from a full List. The original snapshot remains a valid immutable
// view for readers that were already serving it.
func TestResourceSetApplyChangesIncrementally(t *testing.T) {
	original, err := NewResourceSet([]Resource{
		testResource(t, "a", "one"),
		testResource(t, "b", "two"),
	})
	if err != nil {
		t.Fatal(err)
	}
	beforeB, _ := original.Get(ResourceKey{TypeURL: "type.googleapis.com/google.protobuf.StringValue", Name: "b"})
	updatedB := testResource(t, "b", "updated")
	addedC := testResource(t, "c", "three")

	next, changed, err := original.Apply([]ResourceChange{
		{Key: updatedB.Key, New: &updatedB},
		{Key: addedC.Key, New: &addedC},
		{Key: ResourceKey{TypeURL: updatedB.Key.TypeURL, Name: "a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("incremental update reported no change")
	}
	if next.Len() != 2 {
		t.Fatalf("next length = %d, want 2", next.Len())
	}
	if _, found := next.Get(ResourceKey{TypeURL: updatedB.Key.TypeURL, Name: "a"}); found {
		t.Fatal("deleted resource a is still present")
	}
	afterB, found := next.Get(updatedB.Key)
	if !found || afterB.Hash == beforeB.Hash {
		t.Fatal("resource b was not updated")
	}
	if _, found := next.Get(addedC.Key); !found {
		t.Fatal("resource c was not added")
	}
	if original.Len() != 2 {
		t.Fatalf("applying changes mutated the original snapshot: len=%d", original.Len())
	}
}

func TestResourceSetApplyIgnoresNoOpChanges(t *testing.T) {
	resource, err := NewResource(
		testResource(t, "a", "one").Key,
		"",
		testResource(t, "a", "one").Value,
		nil,
		ResourceFacts{},
	)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewResourceSet([]Resource{resource})
	if err != nil {
		t.Fatal(err)
	}

	next, changed, err := set.Apply([]ResourceChange{{Key: resource.Key, New: &resource}})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("identical resource was treated as changed")
	}
	if next.Version() != set.Version() {
		t.Fatalf("no-op changed version: %s != %s", next.Version(), set.Version())
	}
}

func TestResourceSetApplyCanReplaceLastResourceOfType(t *testing.T) {
	oldResource := testResource(t, "old", "one")
	newResource := testResource(t, "new", "two")
	set, err := NewResourceSet([]Resource{oldResource})
	if err != nil {
		t.Fatal(err)
	}

	next, changed, err := set.Apply([]ResourceChange{
		{Key: oldResource.Key},
		{Key: newResource.Key, New: &newResource},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed || next.Len() != 1 {
		t.Fatalf("replacement result changed=%t len=%d", changed, next.Len())
	}
	if _, found := next.Get(newResource.Key); !found {
		t.Fatal("replacement resource is missing")
	}
}

func TestResourceSetLookupIndexesRemainImmutableAcrossApply(t *testing.T) {
	raw := testWorkloadResource(t, "canonical", "old", "sandbox-a", "", nil, nil)
	oldResource, err := NewResource(
		raw.Key, "wire-old", raw.Value, []string{"alias-old"}, raw.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := NewResourceSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	original, changed, err := empty.Apply([]ResourceChange{{Key: oldResource.Key, New: &oldResource}})
	if err != nil || !changed {
		t.Fatalf("Apply(add) changed=%t err=%v", changed, err)
	}
	assertLookupNames(t, empty.Lookup(oldResource.Key.TypeURL, "wire-old"))
	assertLookupNames(t, empty.ListWorkloads(oldResource.Key.TypeURL,
		WorkloadQuery{SandboxUID: "sandbox-a"}))
	assertLookupNames(t, original.Lookup(oldResource.Key.TypeURL, "wire-old"), "wire-old")
	assertLookupNames(t, original.Lookup(oldResource.Key.TypeURL, "alias-old"), "wire-old")
	assertLookupNames(t, original.ListWorkloads(oldResource.Key.TypeURL,
		WorkloadQuery{SandboxUID: "sandbox-a"}), "wire-old")

	updatedRaw := testWorkloadResource(t, "canonical", "new", "sandbox-b", "", nil, nil)
	newResource, err := NewResource(
		oldResource.Key, "wire-new", updatedRaw.Value, []string{"alias-new"}, updatedRaw.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	updated, changed, err := original.Apply([]ResourceChange{{Key: oldResource.Key, New: &newResource}})
	if err != nil || !changed {
		t.Fatalf("Apply(update) changed=%t err=%v", changed, err)
	}

	assertLookupNames(t, original.Lookup(oldResource.Key.TypeURL, "wire-new"))
	assertLookupNames(t, original.ListWorkloads(oldResource.Key.TypeURL,
		WorkloadQuery{SandboxUID: "sandbox-b"}))

	assertLookupNames(t, updated.Lookup(newResource.Key.TypeURL, "wire-old"))
	assertLookupNames(t, updated.Lookup(newResource.Key.TypeURL, "alias-old"))
	assertLookupNames(t, updated.ListWorkloads(newResource.Key.TypeURL,
		WorkloadQuery{SandboxUID: "sandbox-a"}))
	assertLookupNames(t, updated.Lookup(newResource.Key.TypeURL, "wire-new"), "wire-new")
	assertLookupNames(t, updated.Lookup(newResource.Key.TypeURL, "alias-new"), "wire-new")
	assertLookupNames(t, updated.ListWorkloads(newResource.Key.TypeURL,
		WorkloadQuery{SandboxUID: "sandbox-b"}), "wire-new")

	deleted, changed, err := updated.Apply([]ResourceChange{{Key: newResource.Key}})
	if err != nil || !changed {
		t.Fatalf("Apply(delete) changed=%t err=%v", changed, err)
	}
	assertLookupNames(t, deleted.Lookup(newResource.Key.TypeURL, "wire-new"))
	assertLookupNames(t, deleted.Lookup(newResource.Key.TypeURL, "alias-new"))
	assertLookupNames(t, deleted.ListWorkloads(newResource.Key.TypeURL,
		WorkloadQuery{SandboxUID: "sandbox-b"}))
	assertLookupNames(t, updated.Lookup(newResource.Key.TypeURL, "alias-new"), "wire-new")
}

func TestResourceSetHasWorkloadUsesExactIntersection(t *testing.T) {
	typeURL := AddressType
	resources := []Resource{
		testWorkloadResource(t, "node-a-gateway-a", "one", "sandbox-a", "node-a", nil, []string{"gateway-a"}),
		testWorkloadResource(t, "node-a-gateway-b", "two", "sandbox-b", "node-a", nil, []string{"gateway-b"}),
		testWorkloadResource(t, "node-b-gateway-a", "three", "sandbox-c", "node-b", nil, []string{"gateway-a"}),
	}
	set, err := NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}

	if !set.HasWorkload(typeURL, WorkloadQuery{NodeName: "node-a", GatewayReference: "gateway-a"}) {
		t.Fatal("node-a/gateway-a intersection was not found")
	}
	if !set.HasWorkload(typeURL, WorkloadQuery{
		SandboxUID: "sandbox-a", NodeName: "node-a", GatewayReference: "gateway-a",
	}) {
		t.Fatal("sandbox-a/node-a/gateway-a intersection was not found")
	}
	if set.HasWorkload(typeURL, WorkloadQuery{NodeName: "node-a", GatewayReference: "gateway-c"}) {
		t.Fatal("nonexistent node-a/gateway-c intersection was found")
	}
	if set.HasWorkload("unknown", WorkloadQuery{NodeName: "node-a"}) {
		t.Fatal("unknown type reported a Workload match")
	}
	if set.HasWorkload(typeURL, WorkloadQuery{}) {
		t.Fatal("empty Workload query reported a match")
	}
}

func TestResourceSetPayloadUpdateReusesUnchangedLookupMemberships(t *testing.T) {
	raw := testWorkloadResource(t, "canonical", "old", "sandbox-a", "", []string{"demo/service"}, nil)
	oldResource, err := NewResource(
		raw.Key, "wire-name", raw.Value, []string{"alias"}, raw.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	original, err := NewResourceSet([]Resource{oldResource})
	if err != nil {
		t.Fatal(err)
	}
	lookupBefore := lookupNames(&original.resources[oldResource.Key.TypeURL].lookup, "alias")
	factBefore := lookupNames(&original.resources[oldResource.Key.TypeURL].facts,
		resourceFactIndexKey(resourceFactService, "demo/service"))

	newRaw := testWorkloadResource(t, "canonical", "new", "sandbox-a", "", []string{"demo/service"}, nil)
	newResource, err := NewResource(
		oldResource.Key, oldResource.XDSName, newRaw.Value, oldResource.Aliases, oldResource.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	updated, changed, err := original.Apply([]ResourceChange{{Key: newResource.Key, New: &newResource}})
	if err != nil || !changed {
		t.Fatalf("Apply(payload update) changed=%t err=%v", changed, err)
	}
	lookupAfter := lookupNames(&updated.resources[newResource.Key.TypeURL].lookup, "alias")
	factAfter := lookupNames(&updated.resources[newResource.Key.TypeURL].facts,
		resourceFactIndexKey(resourceFactService, "demo/service"))
	if len(lookupBefore) != 1 || len(lookupAfter) != 1 || &lookupBefore[0] != &lookupAfter[0] {
		t.Fatal("payload-only update copied unchanged alias membership")
	}
	if len(factBefore) != 1 || len(factAfter) != 1 || &factBefore[0] != &factAfter[0] {
		t.Fatal("payload-only update copied unchanged fact membership")
	}
}

func assertLookupNames(t *testing.T, resources []Resource, want ...string) {
	t.Helper()
	got := make([]string, 0, len(resources))
	for _, resource := range resources {
		got = append(got, resource.XDSName)
	}
	if len(got) != len(want) {
		t.Fatalf("lookup names = %v, want %v", got, want)
	}
	for index := range got {
		if got[index] != want[index] {
			t.Fatalf("lookup names = %v, want %v", got, want)
		}
	}
}

func BenchmarkResourceSetSingleKeyUpdate(b *testing.B) {
	const resourcesCount = 100_000
	resources := make([]Resource, 0, resourcesCount)
	for i := range resourcesCount {
		name := fmt.Sprintf("cluster//Pod/default/pod-%06d", i)
		resources = append(resources, Resource{
			Key:     ResourceKey{TypeURL: AddressType, Name: name},
			XDSName: name,
			Value:   &anypb.Any{TypeUrl: AddressType, Value: []byte("address")},
			Hash:    name,
			Facts: ResourceFacts{Workload: &WorkloadResourceFacts{
				SandboxUID: name,
				Principal:  testPrincipal(),
			}},
		})
	}
	initial, err := NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	key := resources[len(resources)/2].Key
	variants := [2]Resource{resources[len(resources)/2], resources[len(resources)/2]}
	variants[0].Hash += "-a"
	variants[1].Hash += "-b"

	b.Run("incremental-sharded", func(b *testing.B) {
		set := initial
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resource := variants[i%2]
			var changed bool
			set, changed, err = set.Apply([]ResourceChange{{Key: key, New: &resource}})
			if err != nil || !changed {
				b.Fatalf("Apply() changed=%t err=%v", changed, err)
			}
		}
	})

	b.Run("full-rebuild", func(b *testing.B) {
		copyOfResources := append([]Resource(nil), resources...)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			copyOfResources[len(copyOfResources)/2] = variants[i%2]
			if _, err := NewResourceSet(copyOfResources); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestNewResourceRejectsInvalidFacts(t *testing.T) {
	base := testResource(t, "one", "value")
	tests := []struct {
		name  string
		key   ResourceKey
		value *anypb.Any
		facts ResourceFacts
	}{
		{
			name:  "generic resource with Workload facts",
			key:   base.Key,
			value: base.Value,
			facts: ResourceFacts{Workload: &WorkloadResourceFacts{SandboxUID: "sandbox-a", Principal: testPrincipal()}},
		},
		{
			name:  "Address without family",
			key:   ResourceKey{TypeURL: AddressType, Name: "uid-a"},
			value: &anypb.Any{TypeUrl: AddressType},
		},
		{
			name:  "namespace Authorization without namespace",
			key:   ResourceKey{TypeURL: WorkloadAuthorizationType, Name: "demo/policy"},
			value: &anypb.Any{TypeUrl: WorkloadAuthorizationType},
			facts: ResourceFacts{Authorization: &AuthorizationResourceFacts{Scope: AuthorizationScopeNamespace}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewResource(tt.key, "", tt.value, nil, tt.facts); err == nil {
				t.Fatal("NewResource accepted invalid facts")
			}
		})
	}
}

func TestNewResourceValidatesDiscoveryPrincipalShape(t *testing.T) {
	tests := []struct {
		name      string
		principal Principal
		wantErr   bool
	}{
		{name: "absent principal"},
		{name: "empty service-account identity", principal: Principal{Kind: PrincipalServiceAccount}},
		{name: "identity fields without kind", principal: Principal{TrustDomain: "cluster.local"}, wantErr: true},
		{name: "unknown identity kind", principal: Principal{Kind: "unsupported"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewResource(
				ResourceKey{TypeURL: AddressType, Name: "workload-a"},
				"",
				&anypb.Any{TypeUrl: AddressType},
				nil,
				ResourceFacts{Workload: &WorkloadResourceFacts{
					SandboxUID: "sandbox-a",
					Principal:  test.principal,
				}},
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("NewResource() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

// Production snapshots enter the set pre-hashed; that path validates without
// re-normalizing and must reject invalid facts just like NewResource.
func TestPreHashedResourceFactValidation(t *testing.T) {
	base := testResource(t, "one", "value")
	normalized, err := NewResource(base.Key, "", base.Value, nil, ResourceFacts{})
	if err != nil {
		t.Fatal(err)
	}
	invalid := normalized
	invalid.Facts.Workload = &WorkloadResourceFacts{SandboxUID: "sandbox-a", Principal: testPrincipal()}

	if _, err := NewResourceSet([]Resource{invalid}); err == nil {
		t.Fatal("NewResourceSet accepted invalid pre-hashed facts")
	}
	set, err := NewResourceSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := set.Apply([]ResourceChange{{Key: invalid.Key, New: &invalid}}); err == nil {
		t.Fatal("Apply accepted invalid pre-hashed facts")
	}
}

func TestIsWorkloadAddress(t *testing.T) {
	workload := testWorkloadResource(t, "uid-a", "value", "uid-a", "", nil, nil)
	placed := testWorkloadResource(t, "uid-b", "value", "uid-b", "node-a", nil, nil)
	service := Resource{Facts: ResourceFacts{Service: &ServiceResourceFacts{ServiceKey: "demo/svc"}}}
	if !workload.IsWorkloadAddress() || !placed.IsWorkloadAddress() {
		t.Fatal("Workload-fact resources must be workload addresses")
	}
	if service.IsWorkloadAddress() {
		t.Fatal("service variant must not be a workload address")
	}
}

func testResource(t *testing.T, name, value string) Resource {
	t.Helper()
	message := wrapperspb.String(value)
	encoded, err := anypb.New(message)
	if err != nil {
		t.Fatal(err)
	}
	return Resource{
		Key: ResourceKey{
			TypeURL: encoded.TypeUrl,
			Name:    name,
		},
		Value: encoded,
	}
}

func testWorkloadResource(
	t *testing.T,
	name, value, sandboxUID, nodeName string,
	serviceKeys, gatewayReferences []string,
) Resource {
	t.Helper()
	return Resource{
		Key:   ResourceKey{TypeURL: AddressType, Name: name},
		Value: &anypb.Any{TypeUrl: AddressType, Value: []byte(value)},
		Facts: ResourceFacts{Workload: &WorkloadResourceFacts{
			SandboxUID:        sandboxUID,
			NodeName:          nodeName,
			Principal:         testPrincipal(),
			ServiceKeys:       serviceKeys,
			GatewayReferences: gatewayReferences,
		}},
	}
}

func testPrincipal() Principal {
	return Principal{
		Kind:        PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: ServiceAccountRef{
			Namespace:      "demo",
			ServiceAccount: "default",
		},
	}
}
