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
	"istio.io/istio/pkg/test/util/assert"
)

func TestAgentioResourceGeneratorRegistration(t *testing.T) {
	env := model.NewEnvironment()
	server := &xds.DiscoveryServer{Env: env}
	InitGenerators(server, nil, "", "", nil, nil)

	descriptors := xds.AgentioResourceDescriptors()
	assert.Equal(t, len(descriptors), 3)
	assert.Equal(t, []string{
		descriptors[0].TypeURL,
		descriptors[1].TypeURL,
		descriptors[2].TypeURL,
	}, []string{
		v3.WorkloadConfigType,
		v3.SniTrafficPolicyType,
		v3.PolicyBindingType,
	})
	for _, descriptor := range descriptors {
		registered, found := server.Generators[descriptor.TypeURL]
		if !found {
			t.Fatalf("generator for %q was not registered", descriptor.TypeURL)
		}
		generator, ok := registered.(*xds.AgentioResourceGenerator)
		if !ok {
			t.Fatalf("generator for %q has type %T, want *xds.AgentioResourceGenerator", descriptor.TypeURL, registered)
		}
		if generator.Server != server {
			t.Fatalf("generator for %q has server %p, want %p", descriptor.TypeURL, generator.Server, server)
		}
		if generator.Descriptor.TypeURL != descriptor.TypeURL {
			t.Fatalf("generator descriptor type URL is %q, want %q", generator.Descriptor.TypeURL, descriptor.TypeURL)
		}
		if generator.Descriptor.ConfigKind != descriptor.ConfigKind {
			t.Fatalf("generator descriptor kind is %q, want %q", generator.Descriptor.ConfigKind, descriptor.ConfigKind)
		}
	}
}
