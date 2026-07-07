package ambient

import (
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/sandbox"
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
	if !sandbox.IsSandboxDedicatedProxy(proxy) {
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
