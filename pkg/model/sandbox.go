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
	"reflect"
	"strings"

	"istio.io/istio/pkg/util/sets"
)

// PolicyKind identifies the independently stored policy family referenced by a
// Sandbox. The reference intentionally carries no policy payload.
type PolicyKind string

const (
	PolicyKindAuthorization PolicyKind = "authorization"
	PolicyKindEgressPolicy  PolicyKind = "egress-policy"
	PolicyKindSNIPolicy     PolicyKind = "sni-policy"
)

type PolicyRef struct {
	Kind PolicyKind
	Name string
}

func (r PolicyRef) ResourceName() string { return string(r.Kind) + "|" + r.Name }

func (r PolicyRef) Validate() error {
	switch r.Kind {
	case PolicyKindAuthorization, PolicyKindEgressPolicy, PolicyKindSNIPolicy:
	default:
		return fmt.Errorf("unsupported policy kind %q", r.Kind)
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("%s policy name is required", r.Kind)
	}
	return nil
}

// Sandbox is the minimal policy-enforcement unit: a stable UID, policy-selection
// namespace and labels, and explicit policy references. Namespace is the
// configuration scope used by namespaced policy APIs; it need not be native to
// the runtime hosting the Sandbox. Runtime, attester, and wire-projection state
// deliberately live outside this domain value.
type Sandbox struct {
	UID        string
	Namespace  string
	Labels     map[string]string
	PolicyRefs []PolicyRef
}

func (s Sandbox) Validate() error {
	if strings.TrimSpace(s.UID) == "" {
		return fmt.Errorf("sandbox UID is required")
	}
	seen := sets.NewWithLength[string](len(s.PolicyRefs))
	for index, reference := range s.PolicyRefs {
		if err := reference.Validate(); err != nil {
			return fmt.Errorf("policy reference %d: %w", index, err)
		}
		key := reference.ResourceName()
		if seen.Contains(key) {
			return fmt.Errorf("policy reference %s/%s is duplicated", reference.Kind, reference.Name)
		}
		seen.Insert(key)
	}
	return nil
}

func (s Sandbox) ResourceName() string {
	return s.UID
}

func (s Sandbox) Equals(other Sandbox) bool {
	return reflect.DeepEqual(s, other)
}
