// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package kind

type Kind uint8

// Kinds defined outside the generated schema. Explicit values keep them clear
// of the generated iota block, which shifts on upstream rebases.
const (
	WorkloadConfig   Kind = 200
	SniTrafficPolicy Kind = 202
)

// extendedKindNames names the kinds above; the generated String and FromString
// delegate here for values outside the generated switch.
var extendedKindNames = map[Kind]string{
	WorkloadConfig:   "WorkloadConfig",
	SniTrafficPolicy: "SniTrafficPolicy",
}

func extendedKindName(k Kind) string {
	if name, found := extendedKindNames[k]; found {
		return name
	}
	return "Unknown"
}

func kindFromExtendedName(s string) Kind {
	for k, name := range extendedKindNames {
		if name == s {
			return k
		}
	}
	return Unknown
}
