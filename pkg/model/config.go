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
	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

type AgentioConfiguration struct {
	ResourceVersion string
	Value           *configv1.AgentioConfig
}

func (c AgentioConfiguration) ResourceName() string { return "effective" }

// Equals compares content only; ResourceVersion is diagnostic.
func (c AgentioConfiguration) Equals(other AgentioConfiguration) bool {
	return proto.Equal(c.Value, other.Value)
}
