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

package xds

import (
	"reflect"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/proto"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/util/protoconv"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/config/schema/kind"
	istiolog "istio.io/istio/pkg/log"
	"istio.io/istio/pkg/util/sets"
)

// sniPolicyLog carries SNI policy resource validation warnings.
var sniPolicyLog = istiolog.RegisterScope("snipolicy", "SNI traffic policy xDS debugging")

// AgentioResourceDescriptor describes one Agentio resource xDS type. The
// generator uses these fields to preserve the type-specific config filtering,
// resource naming and feature gating while sharing the
// common delta and envelope-encoding implementation.
type AgentioResourceDescriptor struct {
	TypeURL             string
	ConfigKind          kind.Kind
	ResourceNameFromKey func(model.ConfigKey) string
	Enabled             func() bool
}

// AgentioResourceDescriptors returns the resource types served by
// AgentioResourceGenerator. A fresh slice is returned on every call so bootstrap
// and tests cannot mutate shared descriptor ordering.
func AgentioResourceDescriptors() []AgentioResourceDescriptor {
	enabled := func() bool { return features.EnableSniTrafficPolicy }
	return []AgentioResourceDescriptor{
		{
			TypeURL:             v3.SniTrafficPolicyType,
			ConfigKind:          kind.SniTrafficPolicy,
			ResourceNameFromKey: func(k model.ConfigKey) string { return k.Name },
			Enabled:             enabled,
		},
	}
}

// AgentioResourceGenerator serves descriptor-defined Agentio resources.
// Sources opt in through model.AgentioResourceDiscovery, keeping the generic
// resource API separate from the wider ServiceDiscovery contract.
type AgentioResourceGenerator struct {
	Server     *DiscoveryServer
	Descriptor AgentioResourceDescriptor
}

func isNilProtoMessage(message proto.Message) bool {
	if message == nil {
		return true
	}
	value := reflect.ValueOf(message)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (e AgentioResourceGenerator) GenerateDeltas(
	proxy *model.Proxy,
	req *model.PushRequest,
	w *model.WatchedResource,
) (model.Resources, model.DeletedResources, model.XdsLogDetails, bool, error) {
	// Feature-flag gate lives here rather than at registration in
	// bootstrap.InitGenerators. Registration is static and shared with
	// PushOrder/KnownOrderedTypeUrls, which are package-level and flag-independent;
	// gating registration would make a subscription to these TypeURLs fall through
	// to the "unknown type" path, whose behavior differs between the SotW and delta
	// code paths. Gating here gives one well-defined answer for both: a client that
	// subscribes with the flag off gets an empty, non-error response and keeps its
	// stream.
	//
	// The empty slices must be non-nil: pushDeltaXds skips sending entirely when
	// both are nil (see pilot/pkg/xds/delta.go, `res == nil && deletedRes == nil`),
	// which would leave the client waiting for a first response that never comes.
	// The gateway policy store keys its readiness off having received one, so
	// returning nil here strands every proxy that subscribes with the flag off.
	if !e.Descriptor.Enabled() {
		return model.Resources{}, model.DeletedResources{}, model.DefaultXdsLogDetails, true, nil
	}

	var updated sets.Set[model.ConfigKey]
	expected := sets.New[string]()
	if req.IsRequest() {
		// Subscription requests need a complete current snapshot and stale
		// resource cleanup. An unrelated forced push is not a request: sending a
		// full snapshot for it duplicates every policy immediately after cold
		// start and amplifies large stores without changing their contents.
		expected.Merge(w.ResourceNames)
	} else {
		updated = model.ConfigsOfKind(req.ConfigsUpdated, e.Descriptor.ConfigKind)
		if len(updated) == 0 {
			// Incremental push for a resource we don't watch... skip.
			return nil, nil, model.DefaultXdsLogDetails, false, nil
		}
		for k := range updated {
			expected.Insert(e.Descriptor.ResourceNameFromKey(k))
		}
	}

	source, ok := e.Server.Env.ServiceDiscovery.(model.AgentioResourceDiscovery)
	var resources []model.AgentioResource
	if ok {
		resources = source.AgentioResourcesForProxy(proxy, e.Descriptor.TypeURL, updated)
	}
	encodedResources := make(model.Resources, 0, len(resources))
	for _, resource := range resources {
		if resource.Name == "" || isNilProtoMessage(resource.Resource) {
			sniPolicyLog.Warnf("dropping invalid Agentio resource type=%s name=%q",
				e.Descriptor.TypeURL, resource.Name)
			continue
		}
		encoded := protoconv.MessageToAny(resource.Resource)
		if encoded == nil {
			sniPolicyLog.Warnf("dropping Agentio resource type=%s name=%q: protobuf conversion failed",
				e.Descriptor.TypeURL, resource.Name)
			continue
		}
		if encoded.TypeUrl != e.Descriptor.TypeURL {
			sniPolicyLog.Warnf("dropping Agentio resource type=%s name=%q: payload type %s does not match",
				e.Descriptor.TypeURL, resource.Name, encoded.TypeUrl)
			continue
		}
		// Delete the names we can actually serve; whatever is left in `expected`
		// no longer exists and must be reported as removed.
		expected.Delete(resource.Name)
		encodedResources = append(encodedResources, &discovery.Resource{
			Name:     resource.Name,
			Resource: encoded,
		})
	}

	return encodedResources, sets.SortedList(expected), model.XdsLogDetails{}, true, nil
}

func (e AgentioResourceGenerator) Generate(
	proxy *model.Proxy,
	w *model.WatchedResource,
	req *model.PushRequest,
) (model.Resources, model.XdsLogDetails, error) {
	resources, _, details, _, err := e.GenerateDeltas(proxy, req, w)
	return resources, details, err
}

var (
	_ model.XdsResourceGenerator      = &AgentioResourceGenerator{}
	_ model.XdsDeltaResourceGenerator = &AgentioResourceGenerator{}
)
