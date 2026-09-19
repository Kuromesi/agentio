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
	"strings"
)

// Attester identifies the one Workload currently hosting a Sandbox.
type Attester struct{ WorkloadUID string }

// Sandbox kinds identify the provider used to qualify an instance ID.
const (
	SandboxKindWorkload = "workload"
	SandboxKindKruise   = "kruise"
)

// SandboxUID qualifies a provider's instance ID with its Sandbox kind. Providers
// supply stable IDs unique within their kind; consumers compare the full string.
func SandboxUID(kind, instanceID string) string {
	return kind + ":" + instanceID
}

// Sandbox is an execution unit discovered from a sandbox runtime.
// Owned policies enter the TrafficPolicy and SecurityProfile input collections.
type Sandbox struct {
	Attester  *Attester
	UID       string
	Namespace string
}

func (s Sandbox) Validate() error {
	if strings.TrimSpace(s.UID) == "" {
		return fmt.Errorf("sandbox UID is required")
	}
	if s.Attester != nil && strings.TrimSpace(s.Attester.WorkloadUID) == "" {
		return fmt.Errorf("attester workload UID is required")
	}
	return nil
}

func (s Sandbox) ResourceName() string {
	return s.UID
}

// Equals compares identity and host binding.
func (s Sandbox) Equals(other Sandbox) bool {
	return s.UID == other.UID &&
		s.Namespace == other.Namespace &&
		attestersEqual(s.Attester, other.Attester)
}

func attestersEqual(left, right *Attester) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
