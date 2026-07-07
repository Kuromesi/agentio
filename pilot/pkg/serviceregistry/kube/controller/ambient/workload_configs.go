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
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pkg/util/sets"
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
	for _, ext := range exts {
		if ext.Namespace != proxy.Metadata.Namespace && ext.Namespace != a.SystemNamespace {
			continue
		}
		if len(requested) > 0 && !requested.Contains(ext.ConfigKey()) {
			continue
		}
		res = append(res, ext)
	}
	return res
}
