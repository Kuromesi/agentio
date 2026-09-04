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
	"reflect"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

type TrafficPolicy struct {
	Name         string
	Namespace    string
	SandboxUID   string
	Global       bool
	CreationTime time.Time
	Spec         agentsv1alpha1.TrafficPolicySpec
}

func (p TrafficPolicy) ResourceName() string {
	if p.Global {
		return "global/" + p.Name
	}
	return "namespaced/" + p.Namespace + "/" + p.Name
}

func (p TrafficPolicy) Equals(other TrafficPolicy) bool {
	return p.Name == other.Name && p.Namespace == other.Namespace && p.SandboxUID == other.SandboxUID && p.Global == other.Global &&
		p.CreationTime.Equal(other.CreationTime) && reflect.DeepEqual(p.Spec, other.Spec)
}

type SecurityProfile struct {
	Name         string
	Namespace    string
	SandboxUID   string
	Global       bool
	CreationTime time.Time
	Spec         agentsv1alpha1.SecurityProfileSpec
}

func (p SecurityProfile) ResourceName() string {
	if p.Global {
		return "global/" + p.Name
	}
	return "namespaced/" + p.Namespace + "/" + p.Name
}

func (p SecurityProfile) Equals(other SecurityProfile) bool {
	return p.Name == other.Name && p.Namespace == other.Namespace && p.SandboxUID == other.SandboxUID && p.Global == other.Global &&
		p.CreationTime.Equal(other.CreationTime) && reflect.DeepEqual(p.Spec, other.Spec)
}
