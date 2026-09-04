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
	"fmt"
	"sort"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	"google.golang.org/protobuf/proto"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

type gatewayGlobalExtProc struct {
	Provider *configv1.ExtProcProvider
}

func (g gatewayGlobalExtProc) ResourceName() string { return "gateway-global-ext-proc" }

func (g gatewayGlobalExtProc) Equals(other gatewayGlobalExtProc) bool {
	return proto.Equal(g.Provider, other.Provider)
}

// newGatewayGlobalExtProc projects the global sandbox ext-proc provider from
// AgentioConfig. Per-Gateway overrides win over it in the final networking
// transform.
func newGatewayGlobalExtProc(
	configurations krt.Singleton[configuration],
	options collectionOptions,
) krt.Singleton[gatewayGlobalExtProc] {
	return krt.NewSingleton(func(ctx krt.HandlerContext) *gatewayGlobalExtProc {
		current := krt.FetchOne(ctx, configurations.AsCollection())
		var provider *configv1.ExtProcProvider
		if current != nil && current.Config.GetSandboxExtProc() != nil {
			provider = proto.Clone(current.Config.GetSandboxExtProc()).(*configv1.ExtProcProvider)
		}
		return &gatewayGlobalExtProc{Provider: provider}
	}, options("gateway-global-ext-proc")...)
}

// newGatewayDeclarations merges external and AgentioConfig-derived Gateway declarations.
func newGatewayDeclarations(
	configurations krt.Singleton[configuration],
	declarations krt.Collection[model.Gateway],
	options collectionOptions,
) krt.Collection[model.Gateway] {
	agentioDeclarations := krt.NewManyCollection(configurations.AsCollection(),
		func(_ krt.HandlerContext, current configuration) []model.Gateway {
			return model.GatewaysFromAgentioConfig(current.Config)
		}, options("validated-agentio-config-gateways")...)
	externalDeclarations := krt.NewCollection(declarations,
		func(_ krt.HandlerContext, declaration model.Gateway) *model.Gateway {
			if declaration.Source == model.GatewaySourceAgentioConfig {
				return nil
			}
			return &declaration
		}, options("external-gateway-declarations")...)
	return krt.JoinWithMergeCollection(
		[]krt.Collection[model.Gateway]{agentioDeclarations, externalDeclarations},
		model.MergeGatewaySources,
		options("gateway-declarations")...,
	)
}

func newGatewayResources(
	inputs Inputs,
	base baseIndexes,
	globalExtProc krt.Singleton[gatewayGlobalExtProc],
	gateways krt.Collection[model.Gateway],
	failures *failureRecorder,
	options collectionOptions,
) krt.Collection[model.Resource] {
	extProcs := globalExtProc.AsCollection()
	providerOverrides := inputs.TelemetryProviderOverrides.AsCollection()
	// A primary-input delete bypasses the transformation below. Clear any
	// recorded builder failure once that gateway identity no longer exists.
	gateways.Register(func(event krt.Event[model.Gateway]) {
		if event.New == nil {
			gateway := event.Latest()
			failures.clearIf("Gateway", gateway.ResourceName(), func() bool {
				return gateways.GetKey(gateway.ResourceName()) == nil
			})
		}
	})
	return krt.NewManyCollection(gateways,
		func(ctx krt.HandlerContext, item model.Gateway) []model.Resource {
			gatewayPatches := krt.Fetch(ctx, inputs.GatewayPatches,
				krt.FilterIndex(base.gatewayPatchesByGateway, item.ResourceName()))
			if err := validateGatewayPatches(ctx, inputs.GatewayPatches, base.gatewayPatchesByName, gatewayPatches); err != nil {
				recordGatewayFailureIfCurrent(gateways, failures, item, err)
				ctx.DiscardResult()
				return nil
			}
			telemetry := krt.Fetch(ctx, inputs.Telemetry,
				krt.FilterIndex(base.telemetryByGateway, item.ResourceName()))
			telemetry = append(telemetry, krt.Fetch(ctx, inputs.Telemetry,
				krt.FilterIndex(base.telemetryDefaultsByNamespace, item.Namespace))...)
			if inputs.RootNamespace != item.Namespace {
				telemetry = append(telemetry, krt.Fetch(ctx, inputs.Telemetry,
					krt.FilterIndex(base.telemetryDefaultsByNamespace, inputs.RootNamespace))...)
			}
			providerOverride := krt.FetchOne(ctx, providerOverrides)
			current := krt.FetchOne(ctx, extProcs)
			var provider *configv1.ExtProcProvider
			if current != nil {
				provider = current.Provider
			}
			resources, err := gatewayResourcesFor(
				item,
				provider,
				inputs.DiscoveryAddress,
				inputs.TrustDomain,
				gatewayPatches,
				inputs.ClusterID,
				inputs.RootNamespace,
				telemetry,
				providerOverride,
			)
			if err != nil {
				recordGatewayFailureIfCurrent(gateways, failures, item, err)
				ctx.DiscardResult()
				return nil
			}
			failures.clearIf("Gateway", item.ResourceName(), func() bool {
				current := gateways.GetKey(item.ResourceName())
				return current != nil && current.Equals(item)
			})
			return resources
		}, options("gateway-resources")...)
}

func recordGatewayFailureIfCurrent(
	gateways krt.Collection[model.Gateway],
	failures *failureRecorder,
	item model.Gateway,
	err error,
) {
	name := item.ResourceName()
	failures.recordIf("Gateway", name, err, func() bool {
		current := gateways.GetKey(name)
		return current != nil && current.Equals(item)
	})
}

func gatewayResourcesFor(
	item model.Gateway,
	globalExtProc *configv1.ExtProcProvider,
	discoveryAddress string,
	trustDomain string,
	gatewayPatches []model.GatewayPatch,
	clusterID string,
	rootNamespace string,
	telemetry []model.Telemetry,
	providerOverrides *model.TelemetryProviderOverrides,
) ([]model.Resource, error) {
	built, err := networking.Build(networking.Inputs{
		Gateway:                    item,
		GlobalExtProc:              globalExtProc,
		DiscoveryAddress:           discoveryAddress,
		TrustDomain:                trustDomain,
		GatewayPatches:             gatewayPatches,
		TelemetryRootNamespace:     rootNamespace,
		TelemetryClusterID:         clusterID,
		Telemetry:                  telemetry,
		TelemetryProviderOverrides: providerOverrides,
	})
	if err != nil {
		return nil, fmt.Errorf("compile gateway %s: %w", item.ResourceName(), err)
	}
	result := make([]model.Resource, 0, len(built))
	for _, resource := range built {
		normalized, err := model.NewResource(resource.Key, resource.XDSName, resource.Value, resource.Aliases, resource.Facts)
		if err != nil {
			return nil, fmt.Errorf("compile gateway %s: %w", item.ResourceName(), err)
		}
		result = append(result, normalized)
	}
	return result, nil
}

func validateGatewayPatches(
	ctx krt.HandlerContext,
	all krt.Collection[model.GatewayPatch],
	byLogicalName krt.Index[string, model.GatewayPatch],
	patches []model.GatewayPatch,
) error {
	names := sets.NewWithLength[string](len(patches))
	for _, patch := range patches {
		names.Insert(patch.LogicalName())
	}
	orderedNames := make([]string, 0, len(names))
	for name := range names {
		orderedNames = append(orderedNames, name)
	}
	sort.Strings(orderedNames)
	for _, name := range orderedNames {
		declarations := krt.Fetch(ctx, all, krt.FilterIndex(byLogicalName, name))
		if len(declarations) < 2 {
			continue
		}
		sources := make([]string, 0, len(declarations))
		for _, declaration := range declarations {
			sources = append(sources, declaration.Source)
		}
		sort.Strings(sources)
		return fmt.Errorf("EnvoyFilter %s is declared by multiple sources: %v", name, sources)
	}
	return nil
}
