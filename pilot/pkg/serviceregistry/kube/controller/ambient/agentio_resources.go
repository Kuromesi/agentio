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

package ambient

import (
	"reflect"

	"google.golang.org/protobuf/proto"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/log"
	xdsmodel "istio.io/istio/pkg/model"
	"istio.io/istio/pkg/util/sets"
)

type agentioResourceModel interface {
	ConfigKey() model.ConfigKey
}

type agentioResourceProvider func(
	a *index,
	proxy *model.Proxy,
	requested sets.Set[model.ConfigKey],
) []model.AgentioResource

func collectAgentioResources[T agentioResourceModel](
	collection func(*index) krt.Collection[T],
	name func(T) string,
	message func(T) proto.Message,
	visible func(*index, *model.Proxy, T) bool,
) agentioResourceProvider {
	return func(a *index, proxy *model.Proxy, requested sets.Set[model.ConfigKey]) []model.AgentioResource {
		resources := collection(a)
		if resources == nil {
			return nil
		}

		items := resources.List()
		result := make([]model.AgentioResource, 0, len(items))
		for _, item := range items {
			if visible != nil && !visible(a, proxy, item) {
				continue
			}
			key := item.ConfigKey()
			if len(requested) > 0 && !requested.Contains(key) {
				continue
			}
			resourceName := name(item)
			if resourceName == "" {
				log.Warnf("dropping invalid Agentio resource projection: modelType=%T configKey=%v name=%q: empty resource name",
					item, key, resourceName)
				continue
			}
			resource := message(item)
			if resource == nil {
				log.Warnf("dropping invalid Agentio resource projection: modelType=%T configKey=%v name=%q: nil protobuf",
					item, key, resourceName)
				continue
			}
			if isNilAgentioResourceMessage(resource) {
				log.Warnf("dropping invalid Agentio resource projection: modelType=%T configKey=%v name=%q: typed-nil protobuf payloadType=%T",
					item, key, resourceName, resource)
				continue
			}
			result = append(result, model.AgentioResource{
				Name:     resourceName,
				Resource: resource,
			})
		}
		return result
	}
}

func isNilAgentioResourceMessage(message proto.Message) bool {
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

var agentioResourceProviders = map[string]agentioResourceProvider{
	xdsmodel.PolicyBindingType: collectAgentioResources(
		func(a *index) krt.Collection[model.PolicyBinding] { return a.policyBindings },
		func(p model.PolicyBinding) string { return p.ResourceName() },
		func(p model.PolicyBinding) proto.Message { return p.Binding },
		nil,
	),
	xdsmodel.WorkloadConfigType: collectAgentioResources(
		func(a *index) krt.Collection[model.WorkloadConfig] { return a.workloadConfigs },
		func(c model.WorkloadConfig) string { return c.ResourceName() },
		func(c model.WorkloadConfig) proto.Message { return c.Config },
		func(a *index, proxy *model.Proxy, c model.WorkloadConfig) bool {
			if !agentio.IsSandboxDedicatedProxy(proxy) {
				return true
			}
			return c.Namespace == proxy.Metadata.Namespace || c.Namespace == a.SystemNamespace
		},
	),
}

func bindablePolicyResourceProvider(typeURL string) agentioResourceProvider {
	return collectAgentioResources(
		func(a *index) krt.Collection[agentio.BindablePolicy] { return a.bindablePolicies },
		func(p agentio.BindablePolicy) string { return p.XDSResourceName() },
		func(p agentio.BindablePolicy) proto.Message { return p.Resource },
		func(_ *index, _ *model.Proxy, p agentio.BindablePolicy) bool {
			return p.TypeURL == typeURL
		},
	)
}

func (a *index) AgentioResourcesForProxy(
	proxy *model.Proxy,
	typeURL string,
	requested sets.Set[model.ConfigKey],
) []model.AgentioResource {
	provider, found := agentioResourceProviders[typeURL]
	if found {
		return provider(a, proxy, requested)
	}
	resources := bindablePolicyResourceProvider(typeURL)(a, proxy, requested)
	if len(resources) == 0 {
		return nil
	}
	return resources
}
