package sandbox

import (
	"fmt"

	"istio.io/istio/pilot/pkg/config/file"
	"istio.io/istio/pilot/pkg/config/memory"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	v1 "k8s.io/api/core/v1"
)

const KubeSourceConfigMapFiledSelector = "manifests.agents.kruise.io/kube-source"

type configStore struct {
	model.ConfigStoreController
}

func newConfigStore(kc kube.Client, rootNamespace string, stop <-chan struct{}) *configStore {
	configmaps := krt.NewFilteredInformer[*v1.ConfigMap](kc, kclient.Filter{
		LabelSelector: KubeSourceConfigMapFiledSelector,
		ObjectFilter:  kc.ObjectFilter(),
		Namespace:     rootNamespace,
	})

	store := memory.Make(collections.PilotGatewayAPI())
	mc := memory.NewController(store)
	kubeSource := file.NewKubeSourceWithStore(mc)

	configmaps.Register(func(o krt.Event[*v1.ConfigMap]) {
		if o.Event == controllers.EventDelete {
			cm := ptr.Flatten(o.Old)
			kubeSource.RemoveContent(fmt.Sprintf("%s/%s", cm.Namespace, cm.Name))
			return
		}

		cm := ptr.Flatten(o.New)
		sources := cm.Data["sources"]
		if err := kubeSource.ApplyContent(fmt.Sprintf("%s/%s", cm.Namespace, cm.Name), sources); err != nil {
			log.Errorf("Failed to apply configs from configmap %s/%s: %v", cm.Namespace, cm.Name, err)
		}
	})

	go mc.Run(stop)
	return &configStore{
		ConfigStoreController: mc,
	}
}
