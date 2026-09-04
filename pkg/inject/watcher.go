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

// Watcher feeds the sidecar-injector ConfigMap keys "config" and "values" into
// a Webhook. Invalid updates keep the last known good configuration.

package inject

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

const (
	injectorConfigKey = "config"
	injectorValuesKey = "values"
)

type WatcherOptions struct {
	// Namespace is the control-plane namespace holding the ConfigMap.
	Namespace string
	// InjectorConfigMapName carries the injection templates and values.
	InjectorConfigMapName string
}

// Watcher drives a Webhook from the injector ConfigMap.
type Watcher struct {
	configMaps kclient.StartableInformer[*corev1.ConfigMap]
	webhook    *Webhook
	options    WatcherOptions
}

func NewWatcher(client kube.Client, webhook *Webhook, options WatcherOptions) (*Watcher, error) {
	if client == nil || webhook == nil {
		return nil, fmt.Errorf("kubernetes client and webhook are required")
	}
	if options.Namespace == "" || options.InjectorConfigMapName == "" {
		return nil, fmt.Errorf("watcher namespace and injector ConfigMap name are required")
	}
	return &Watcher{
		configMaps: kclient.NewFiltered[*corev1.ConfigMap](client, kclient.Filter{
			Namespace: options.Namespace,
		}),
		webhook: webhook,
		options: options,
	}, nil
}

// Run watches the ConfigMaps until stop closes. It returns once caches have
// synced, so callers can sequence webhook readiness after initial load.
func (w *Watcher) Run(stop <-chan struct{}) {
	queue := controllers.NewQueue("sidecar injector config",
		controllers.WithReconciler(func(o types.NamespacedName) error {
			return w.reconcile(w.configMaps, o)
		}),
		controllers.WithMaxAttempts(5))

	w.configMaps.AddEventHandler(controllers.FilteredObjectSpecHandler(queue.AddObject, func(o controllers.Object) bool {
		return o.GetName() == w.options.InjectorConfigMapName
	}))
	defer controllers.ShutdownAll(w.configMaps)

	w.configMaps.Start(stop)
	if !kube.WaitForCacheSync("sidecar injector config", stop, w.configMaps.HasSynced) {
		queue.ShutDownEarly()
		return
	}
	queue.Run(stop)
}

func (w *Watcher) reconcile(configMaps kclient.Reader[*corev1.ConfigMap], o types.NamespacedName) error {
	configMap := configMaps.Get(o.Name, o.Namespace)
	if configMap == nil {
		// Deleted: keep the last known good configuration.
		log.Warn("injector ConfigMap removed; keeping last-known-good configuration",
			"namespace", o.Namespace, "configmap", o.Name)
		return nil
	}
	if o.Name == w.options.InjectorConfigMapName {
		return w.applyInjectorConfigMap(configMap)
	}
	return nil
}

func (w *Watcher) applyInjectorConfigMap(configMap *corev1.ConfigMap) error {
	rawConfig, ok := configMap.Data[injectorConfigKey]
	if !ok {
		return fmt.Errorf("injector ConfigMap %s/%s is missing key %q", configMap.Namespace, configMap.Name, injectorConfigKey)
	}
	rawValues := configMap.Data[injectorValuesKey]
	config, err := UnmarshalConfig([]byte(rawConfig))
	if err != nil {
		return fmt.Errorf("parse injector config: %v", err)
	}
	if err := w.webhook.UpdateConfig(&config, rawValues); err != nil {
		return err
	}
	log.Info("loaded injection configuration", "namespace", configMap.Namespace,
		"configmap", configMap.Name, "templates", len(config.RawTemplates))
	return nil
}
