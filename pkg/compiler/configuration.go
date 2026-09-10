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

package compiler

import (
	"slices"

	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/policy"
)

// workloadMetadataConfiguration is the part of Agentio configuration that
// affects Workload metadata encoding. Keeping this projection separate stops
// DNS-only changes in compiled egress policy from invalidating Workloads
// through the full configuration as well as through their policy payloads.
type workloadMetadataConfiguration struct {
	IgnoredLabels []string
}

func (c workloadMetadataConfiguration) ResourceName() string {
	return "workload-metadata-configuration"
}

func (c workloadMetadataConfiguration) Equals(other workloadMetadataConfiguration) bool {
	return slices.Equal(c.IgnoredLabels, other.IgnoredLabels)
}

func newWorkloadMetadataConfiguration(
	configuration krt.Singleton[configuration],
	options collectionOptions,
) krt.Singleton[workloadMetadataConfiguration] {
	return krt.NewSingleton(func(ctx krt.HandlerContext) *workloadMetadataConfiguration {
		current := krt.FetchOne(ctx, configuration.AsCollection())
		if current == nil || current.Config == nil {
			return nil
		}
		return &workloadMetadataConfiguration{
			IgnoredLabels: slices.Clone(current.Config.GetSandboxIgnoredLabels()),
		}
	}, options("workload-metadata-configuration")...)
}

// configuration is the Agentio configuration after overlay merging together
// with its compiled egress policy payload.
type configuration struct {
	ResourceVersion string
	Config          *configv1.AgentioConfig
	Egress          *extensionsv1.EgressPolicies
}

func (c configuration) ResourceName() string { return "configuration" }

func (c configuration) Equals(other configuration) bool {
	// Egress is compared explicitly: DNS resolution can change it while the
	// ConfigMap ResourceVersion stays the same.
	return c.ResourceVersion == other.ResourceVersion &&
		proto.Equal(c.Config, other.Config) &&
		proto.Equal(c.Egress, other.Egress)
}

func newConfiguration(inputs Inputs, failures *failureRecorder, options collectionOptions) krt.Singleton[configuration] {
	return krt.NewSingleton(func(ctx krt.HandlerContext) *configuration {
		var raw *configv1.AgentioConfig
		resourceVersion := ""
		if current := krt.FetchOne(ctx, inputs.AgentioConfig); current != nil {
			raw = current.Value
			resourceVersion = current.ResourceVersion
		}
		egress, err := policy.CompileEgressPolicies(ctx, raw, inputs.Resolve)
		if err != nil {
			failures.record("AgentioConfig", "configuration", err)
			// Discard the result to retain the last known good configuration.
			ctx.DiscardResult()
			return nil
		}
		// Validate attachment targets and Gateway identities before committing.
		if _, err := policy.CompiledEgressPolicies(inputs.RootNamespace, egress); err != nil {
			failures.record("AgentioConfig", "configuration", err)
			ctx.DiscardResult()
			return nil
		}
		compiled := &configuration{
			ResourceVersion: resourceVersion,
			Config:          raw,
			Egress:          egress,
		}
		failures.clear("AgentioConfig", "configuration")
		return compiled
	}, options("configuration")...)
}
