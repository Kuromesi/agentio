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

package kubernetes

import (
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func newAgentioConfigGateways(
	configurations krt.Collection[model.AgentioConfiguration],
	options ...krt.CollectionOption,
) krt.Collection[model.Gateway] {
	return krt.NewManyCollection(configurations,
		func(_ krt.HandlerContext, configuration model.AgentioConfiguration) []model.Gateway {
			return model.GatewaysFromAgentioConfig(configuration.Value)
		}, options...)
}
