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

package bootstrap

import (
	"testing"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/xds"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
)

func TestAgentioResourceGeneratorRegistration(t *testing.T) {
	env := model.NewEnvironment()
	server := &xds.DiscoveryServer{Env: env}
	InitGenerators(server, nil, "", "", nil, nil)

	if _, found := server.Generators[v3.SniTrafficPolicyType]; found {
		t.Fatal("inline SNI policy must not register a standalone generator")
	}
}
