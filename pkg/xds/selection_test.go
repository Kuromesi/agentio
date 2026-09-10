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
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

func TestOrderedUniquePreservesLastResourceForDuplicateKey(t *testing.T) {
	key := model.ResourceKey{TypeURL: model.AddressType, Name: "duplicate"}
	first := model.Resource{Key: key, XDSName: "wire-b", Hash: "first"}
	last := model.Resource{Key: key, XDSName: "wire-a", Hash: "last"}
	other := model.Resource{
		Key:     model.ResourceKey{TypeURL: model.AddressType, Name: "other"},
		XDSName: "wire-z",
		Hash:    "other",
	}

	got := orderedUnique([]model.Resource{first, other, last})
	if len(got) != 2 || got[0].Key != key || got[0].Hash != "last" || got[1].Key != other.Key {
		t.Fatalf("orderedUnique() = %#v, want last duplicate followed by other", got)
	}
}
