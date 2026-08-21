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
	"google.golang.org/protobuf/proto"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/util/sets"
	"istio.io/istio/pkg/workloadapi"
)

func (a *index) WorkloadConfigs(requested sets.Set[model.ConfigKey]) []model.WorkloadConfig {
	if a.workloadConfigs == nil {
		return nil
	}
	exts := a.workloadConfigs.List()
	res := make([]model.WorkloadConfig, 0, len(exts))
	for _, ext := range exts {
		if len(requested) > 0 && !requested.Contains(ext.ConfigKey()) {
			continue
		}
		res = append(res, ext)
	}
	return res
}

func (a *index) WorkloadConfigsForProxy(proxy *model.Proxy, requested sets.Set[model.ConfigKey]) []model.WorkloadConfig {
	if !agentio.IsSandboxDedicatedProxy(proxy) {
		return a.WorkloadConfigs(requested)
	}

	if a.workloadConfigs == nil {
		return nil
	}
	exts := a.workloadConfigs.List()
	res := make([]model.WorkloadConfig, 0, len(exts))
	actorContext := a.actorContextForProxy(proxy)
	for _, ext := range exts {
		if ext.Namespace != proxy.Metadata.Namespace && ext.Namespace != a.SystemNamespace {
			continue
		}
		if len(requested) > 0 && !requested.Contains(ext.ConfigKey()) {
			continue
		}
		if ext.Config != nil && ext.Config.GetScope() == extensions.WorkloadConfigScope_WORKLOAD_CONFIG_SCOPE_GLOBAL {
			ext.Config = proto.Clone(ext.Config).(*extensions.WorkloadConfig)
			ext.Config.ActorContext = actorContext
		}
		res = append(res, ext)
	}
	return res
}

func (a *index) actorContextForProxy(proxy *model.Proxy) *extensions.ActorContext {
	workloadKey, ok := agentio.BuildProxyWorkloadKey(proxy)
	if !ok {
		return nil
	}
	workload := a.workloads.GetKey(workloadKey)
	if workload == nil {
		return nil
	}
	return a.actorContextForWorkload(workload)
}

func (a *index) actorContextForWorkload(workload *model.WorkloadInfo) *extensions.ActorContext {
	if workload == nil || workload.Workload == nil {
		return nil
	}
	if a.actorContextSource != nil {
		actor, authoritative := a.actorContextSource.ActorContextForWorker(
			workload.Workload.GetNamespace(),
			workload.Workload.GetName(),
			workload.NativeUID,
		)
		if authoritative {
			return actor
		}
	}
	return agentio.ActorContextFromLabels(workload.Labels)
}

func (a *index) attachActorContextsForProxy(proxy *model.Proxy, addresses []model.AddressInfo) []model.AddressInfo {
	if proxy == nil || !proxy.IsZTunnel() {
		return addresses
	}
	dedicated := agentio.IsSandboxDedicatedProxy(proxy)
	dedicatedWorkloadKey, dedicatedKeyOK := agentio.BuildProxyWorkloadKey(proxy)
	proxyNode := proxy.GetNodeName()

	result := make([]model.AddressInfo, 0, len(addresses))
	for _, address := range addresses {
		workload := a.workloads.GetKey(address.ResourceName())
		if workload == nil || workload.Workload == nil {
			result = append(result, address)
			continue
		}
		if dedicated {
			if !dedicatedKeyOK || workload.ResourceName() != dedicatedWorkloadKey {
				result = append(result, address)
				continue
			}
		} else if proxyNode == "" || workload.Workload.GetNode() != proxyNode {
			result = append(result, address)
			continue
		}
		actor := a.actorContextForWorkload(workload)
		if actor == nil {
			result = append(result, address)
			continue
		}

		cloned := proto.Clone(address.Address).(*workloadapi.Address)
		clonedWorkload := cloned.GetWorkload()
		clonedWorkload.Extensions = append(clonedWorkload.Extensions, agentio.NewActorContextExtension(actor))
		result = append(result, model.AddressInfo{Address: cloned})
	}
	return result
}
