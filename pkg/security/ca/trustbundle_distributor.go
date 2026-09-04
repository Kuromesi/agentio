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

package ca

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

// With the default rate limiter, distributorMaxRetries yields delays of 5ms,
// 10ms, 20ms, 40ms, and 80ms before a namespace is dropped.
const distributorMaxRetries = 5

// trustBundleConfigMapKey is the data key proxies mount; it must stay
// root-cert.pem for wire compatibility with pilot-agent and ztunnel.
const trustBundleConfigMapKey = "root-cert.pem"

// distributorConfigMapLabel marks ConfigMaps owned by Agentio's trust-bundle distributor.
var distributorConfigMapLabel = map[string]string{"agentio.kruise.io/config": "true"}

// Namespaces skipped from distribution; kube-system is served.
var distributorIgnoredNamespaces = sets.New(
	"kube-public",
	"kube-node-lease",
	"local-path-storage",
)

type TrustBundleDistributorOptions struct {
	// Namespace hosts the leader-election Lease.
	Namespace     string
	ConfigMapName string
	LeaseName     string
}

// TrustBundleDistributor reconciles a ConfigMap carrying the workload trust
// bundle into every namespace, so proxies in any namespace can mount the root
// of trust by the name their charts expect.
type TrustBundleDistributor struct {
	client     kube.Client
	authority  *Authority
	options    TrustBundleDistributorOptions
	namespaces kclient.StartableInformer[*corev1.Namespace]
	configMaps kclient.StartableClient[*corev1.ConfigMap]
}

func NewTrustBundleDistributor(client kube.Client, authority *Authority, options TrustBundleDistributorOptions) (*TrustBundleDistributor, error) {
	if client == nil || authority == nil {
		return nil, fmt.Errorf("kubernetes client and authority are required")
	}
	if options.Namespace == "" {
		return nil, fmt.Errorf("trust bundle distributor namespace is required")
	}
	if options.ConfigMapName == "" {
		options.ConfigMapName = "istio-ca-root-cert"
	}
	if options.LeaseName == "" {
		options.LeaseName = "agentiod-trust-bundle-leader"
	}
	namespaces := kclient.NewFiltered[*corev1.Namespace](client, kclient.Filter{})
	configMaps := kclient.NewWritableStatuslessFromInformer(
		kclient.NewFiltered[*corev1.ConfigMap](client, kclient.Filter{
			FieldSelector: "metadata.name=" + options.ConfigMapName,
		}),
		func(namespace string) coreclientv1.ConfigMapInterface {
			return client.Kube().CoreV1().ConfigMaps(namespace)
		},
	)
	return &TrustBundleDistributor{
		client:     client,
		authority:  authority,
		options:    options,
		namespaces: namespaces,
		configMaps: configMaps,
	}, nil
}

// Run blocks until ctx is done, re-entering leader election after losses so a
// replica that regains the lease resumes distributing.
func (d *TrustBundleDistributor) Run(ctx context.Context) {
	d.namespaces.Start(ctx.Done())
	d.configMaps.Start(ctx.Done())
	runLeaseElection(ctx, d.client.Kube(), d.options.Namespace, d.options.LeaseName,
		"trust bundle distributor", d.runController)
}

// runController owns one lease acquisition. The shared informer caches remain
// process-scoped; only this cycle's handlers, queue, and rotation subscription
// are installed and removed with the leader context.
func (d *TrustBundleDistributor) runController(leaderCtx context.Context) {
	queue := controllers.NewQueue("trust bundle distributor",
		controllers.WithReconciler(func(o types.NamespacedName) error {
			return d.reconcile(d.configMaps, o)
		}),
		controllers.WithMaxAttempts(distributorMaxRetries))

	d.configMaps.AddEventHandler(
		controllers.FilteredObjectSpecHandler(queue.AddObject, func(o controllers.Object) bool {
			return !distributorIgnoredNamespaces.Contains(o.GetNamespace())
		}))
	d.namespaces.AddEventHandler(
		controllers.FilteredObjectSpecHandler(queue.AddObject, func(o controllers.Object) bool {
			return !distributorIgnoredNamespaces.Contains(o.GetName())
		}))
	defer controllers.ShutdownAll(d.configMaps, d.namespaces)

	if !kube.WaitForCacheSync("trust bundle distributor", leaderCtx.Done(),
		d.namespaces.HasSynced, d.configMaps.HasSynced) {
		queue.ShutDownEarly()
		return
	}

	// A committed rotation re-enqueues every namespace.
	rotationWatch := d.authority.TrustBundles().Register(func(krt.Event[TrustBundle]) {
		for _, namespace := range d.namespaces.List(metav1.NamespaceAll, labels.Everything()) {
			if namespace.Status.Phase == corev1.NamespaceTerminating {
				continue
			}
			if distributorIgnoredNamespaces.Contains(namespace.Name) {
				continue
			}
			queue.Add(types.NamespacedName{Name: namespace.Name})
		}
	})
	defer rotationWatch.UnregisterHandler()

	queue.Run(leaderCtx.Done())
}

// reconcile upserts the trust bundle ConfigMap for one namespace. The queued
// key is either a Namespace (name only) or a ConfigMap (namespace set).
func (d *TrustBundleDistributor) reconcile(configMaps kclient.Client[*corev1.ConfigMap], o types.NamespacedName) error {
	namespace := o.Namespace
	if namespace == "" {
		namespace = o.Name
	}
	return insertDataToConfigMap(configMaps, metav1.ObjectMeta{
		Name:      d.options.ConfigMapName,
		Namespace: namespace,
		Labels:    distributorConfigMapLabel,
	}, trustBundleConfigMapKey, d.authority.RootPEM())
}

// insertDataToConfigMap upserts one data key; deleted or terminating namespaces and forbidden writes are skipped without retry.
func insertDataToConfigMap(client kclient.Client[*corev1.ConfigMap], meta metav1.ObjectMeta, key string, data []byte) error {
	configMap := client.Get(meta.Name, meta.Namespace)
	if configMap == nil {
		configMap = &corev1.ConfigMap{
			ObjectMeta: meta,
			Data:       map[string]string{key: string(data)},
		}
		if _, err := client.Create(configMap); err != nil {
			if apierrors.IsAlreadyExists(err) || apierrors.HasStatusCause(err, corev1.NamespaceTerminatingCause) || apierrors.IsNotFound(err) {
				return nil
			}
			if apierrors.IsForbidden(err) {
				log.Warn("skip writing ConfigMap without permission", "namespace", meta.Namespace, "configmap", meta.Name)
				return nil
			}
			return fmt.Errorf("create ConfigMap %s/%s: %w", meta.Namespace, meta.Name, err)
		}
		return nil
	}
	if configMap.Data[key] == string(data) {
		return nil
	}
	updated := configMap.DeepCopy()
	if updated.Data == nil {
		updated.Data = map[string]string{}
	}
	updated.Data[key] = string(data)
	if _, err := client.Update(updated); err != nil {
		return fmt.Errorf("update ConfigMap %s/%s: %w", meta.Namespace, meta.Name, err)
	}
	return nil
}
