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
	"maps"
	"slices"
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

// SandboxState is the observed runtime lifecycle, independent of policy validity.
type SandboxState int32

const (
	SandboxStateUnspecified SandboxState = iota
	SandboxStatePending
	SandboxStateRunning
	SandboxStatePaused
	SandboxStateStopped
)

// Attester identifies the one Workload currently hosting a Sandbox.
type Attester struct{ WorkloadUID string }

// Sandbox is an explicitly discovered runtime and its policy configuration.
type Sandbox struct {
	State      SandboxState
	Attester   *Attester
	UID        string
	Namespace  string
	Labels     map[string]string
	PolicyRefs []PolicyRef
}

func (s Sandbox) Validate() error {
	if strings.TrimSpace(s.UID) == "" {
		return fmt.Errorf("sandbox UID is required")
	}
	if s.State < SandboxStateUnspecified || s.State > SandboxStateStopped {
		return fmt.Errorf("unknown sandbox state %d", s.State)
	}
	if s.Attester != nil && strings.TrimSpace(s.Attester.WorkloadUID) == "" {
		return fmt.Errorf("attester workload UID is required")
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

// Equals compares all fields, preserving the distinction between nil and empty collections.
func (s Sandbox) Equals(other Sandbox) bool {
	return s.State == other.State &&
		s.UID == other.UID &&
		s.Namespace == other.Namespace &&
		attestersEqual(s.Attester, other.Attester) &&
		(s.PolicyRefs == nil) == (other.PolicyRefs == nil) &&
		slices.Equal(s.PolicyRefs, other.PolicyRefs) &&
		(s.Labels == nil) == (other.Labels == nil) &&
		maps.Equal(s.Labels, other.Labels)
}

func attestersEqual(left, right *Attester) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
