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
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeclient "k8s.io/client-go/kubernetes"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
)

func TestTrustBundleDistributor(t *testing.T) {
	client := kube.NewFakeClient()
	coreClient := client.Kube()
	authority := &Authority{trustBundles: krt.NewStatic(&TrustBundle{PEM: "caBundle"}, true)}
	distributor, err := NewTrustBundleDistributor(client, authority, TrustBundleDistributorOptions{
		Namespace: "agentio-system",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client.Run(ctx.Done())
	go distributor.runController(ctx)

	const configMapName = "istio-ca-root-cert"
	expectedData := map[string]string{trustBundleConfigMapKey: "caBundle"}
	createDistributorNamespace(t, coreClient, "foo")
	expectDistributedConfigMap(t, coreClient, "foo", configMapName, expectedData)

	created, getErr := coreClient.CoreV1().ConfigMaps("foo").Get(ctx, configMapName, metav1.GetOptions{})
	if getErr != nil {
		t.Fatal(getErr)
	}
	if got, want := created.Labels["agentio.kruise.io/config"], "true"; got != want {
		t.Fatalf("distributed ConfigMap label agentio.kruise.io/config = %q, want %q", got, want)
	}
	if value, found := created.Labels["istio.io/config"]; found {
		t.Fatalf("distributed ConfigMap retained legacy Istio label %q", value)
	}

	// A ConfigMap the distributor does not own must stay untouched.
	unrelated := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "not-root", Namespace: "foo"},
		Data:       map[string]string{"k": "v"},
	}
	if _, err := coreClient.CoreV1().ConfigMaps("foo").Create(ctx, unrelated, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	expectDistributedConfigMap(t, coreClient, "foo", "not-root", unrelated.Data)

	// A committed rotation refreshes every namespace.
	authority.trustBundles.Set(&TrustBundle{PEM: "caBundle-new"})
	newData := map[string]string{trustBundleConfigMapKey: "caBundle-new"}
	expectDistributedConfigMap(t, coreClient, "foo", configMapName, newData)

	// A deleted ConfigMap is recreated.
	if err := coreClient.CoreV1().ConfigMaps("foo").Delete(ctx, configMapName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	expectDistributedConfigMap(t, coreClient, "foo", configMapName, newData)

	// A tampered ConfigMap is repaired. The fake clientset does not bump
	// resourceVersion on update, and FilteredObjectSpecHandler drops updates
	// with an unchanged resourceVersion, so set one explicitly.
	tampered := created.DeepCopy()
	tampered.Data = map[string]string{trustBundleConfigMapKey: "attacker"}
	tampered.ResourceVersion = "tampered"
	if _, err := coreClient.CoreV1().ConfigMaps("foo").Update(ctx, tampered, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	expectDistributedConfigMap(t, coreClient, "foo", configMapName, newData)

	// kube-system is served so ztunnel can run there.
	createDistributorNamespace(t, coreClient, "kube-system")
	expectDistributedConfigMap(t, coreClient, "kube-system", configMapName, newData)

	// System namespaces in the ignored set never receive a ConfigMap.
	for _, namespace := range distributorIgnoredNamespaces.UnsortedList() {
		createDistributorNamespace(t, coreClient, namespace)
	}
	// The ignored namespaces were created before this marker namespace, so once
	// the marker is served, silence in the ignored namespaces is a decision
	// rather than queue lag.
	createDistributorNamespace(t, coreClient, "marker")
	expectDistributedConfigMap(t, coreClient, "marker", configMapName, newData)
	for _, namespace := range distributorIgnoredNamespaces.UnsortedList() {
		if _, err := coreClient.CoreV1().ConfigMaps(namespace).Get(ctx, configMapName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("ConfigMap lookup in ignored namespace %s = %v, want not found", namespace, err)
		}
	}
}

func createDistributorNamespace(t *testing.T, client kubeclient.Interface, name string) {
	t.Helper()
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if _, err := client.CoreV1().Namespaces().Create(context.Background(), namespace, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func expectDistributedConfigMap(t *testing.T, client kubeclient.Interface, namespace, name string, data map[string]string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		configMap, err := client.CoreV1().ConfigMaps(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil && reflect.DeepEqual(configMap.Data, data) {
			return
		}
		if err != nil {
			lastErr = err
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for ConfigMap %s/%s with data %v (last error: %v)", namespace, name, data, lastErr)
}
