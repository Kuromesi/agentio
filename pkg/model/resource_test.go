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
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
)

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
			facts: ResourceFacts{Workload: &WorkloadResourceFacts{WorkloadUID: "sandbox-a", Principal: testPrincipal()}},
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
					WorkloadUID: "sandbox-a",
					Principal:   test.principal,
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
	invalid.Facts.Workload = &WorkloadResourceFacts{WorkloadUID: "sandbox-a", Principal: testPrincipal()}

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
