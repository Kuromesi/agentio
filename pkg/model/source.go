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

// SourceIdentity identifies the source object behind a configuration.
type SourceIdentity struct {
	UID string `json:"uid,omitempty"`
}

// SourceReader reads locally observed source identities using canonical resource
// keys. Presence does not imply successful compilation or publication. Absence
// does not establish a linearizable read from an external source. A present key
// with conflicting raw owners has an empty identity until the conflict is resolved.
type SourceReader interface {
	Lookup(ResourceKey) (SourceIdentity, bool)
}
