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

package kclient

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gatewayclientv1 "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/typed/apis/v1"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1"
)

func TestWritableClusterScopedCreateDeleteRoundTrip(t *testing.T) {
	client := gatewayfake.NewSimpleClientset()
	informer := gatewayinformers.NewGatewayClassInformer(client, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	classes := NewWritable[*gatewayv1.GatewayClass, gatewayclientv1.GatewayClassInterface](informer, func(string) gatewayclientv1.GatewayClassInterface {
		return client.GatewayV1().GatewayClasses()
	})

	created, err := classes.Create(&gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "istio"}})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.Name != "istio" {
		t.Fatalf("Create() name = %q, want istio", created.Name)
	}
	if _, err := client.GatewayV1().GatewayClasses().Get(context.Background(), "istio", metav1.GetOptions{}); err != nil {
		t.Fatalf("created object not found in fake client: %v", err)
	}

	if err := classes.Delete("istio", ""); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := client.GatewayV1().GatewayClasses().Get(context.Background(), "istio", metav1.GetOptions{}); err == nil {
		t.Fatal("deleted GatewayClass still exists")
	}
}

func TestWritableNamespacedCreateDeleteRoundTrip(t *testing.T) {
	client := kubernetesfake.NewSimpleClientset()
	informer := coreinformers.NewPodInformer(client, metav1.NamespaceAll, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	pods := NewWritable[*corev1.Pod, coreclientv1.PodInterface](informer, func(namespace string) coreclientv1.PodInterface {
		return client.CoreV1().Pods(namespace)
	})

	created, err := pods.Create(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "settings", Namespace: "app"}})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.Name != "settings" || created.Namespace != "app" {
		t.Fatalf("Create() = %s/%s, want app/settings", created.Namespace, created.Name)
	}
	if _, err := client.CoreV1().Pods("app").Get(context.Background(), "settings", metav1.GetOptions{}); err != nil {
		t.Fatalf("created object not found in fake client: %v", err)
	}

	if err := pods.Delete("settings", "app"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := client.CoreV1().Pods("app").Get(context.Background(), "settings", metav1.GetOptions{}); err == nil {
		t.Fatal("deleted Pod still exists")
	}
}

func TestWritableStatuslessServiceAccount(t *testing.T) {
	client := kubernetesfake.NewSimpleClientset()
	informer := coreinformers.NewServiceAccountInformer(client, metav1.NamespaceAll, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	sas := NewWritableStatusless[*corev1.ServiceAccount, coreclientv1.ServiceAccountInterface](informer, func(ns string) coreclientv1.ServiceAccountInterface {
		return client.CoreV1().ServiceAccounts(ns)
	})

	// Create round-trip.
	created, err := sas.Create(&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "my-sa", Namespace: "test-ns"}})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.Name != "my-sa" || created.Namespace != "test-ns" {
		t.Fatalf("Create() = %s/%s, want test-ns/my-sa", created.Namespace, created.Name)
	}
	if _, err := client.CoreV1().ServiceAccounts("test-ns").Get(context.Background(), "my-sa", metav1.GetOptions{}); err != nil {
		t.Fatalf("created object not found in fake client: %v", err)
	}

	// Delete round-trip.
	if err := sas.Delete("my-sa", "test-ns"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := client.CoreV1().ServiceAccounts("test-ns").Get(context.Background(), "my-sa", metav1.GetOptions{}); err == nil {
		t.Fatal("deleted ServiceAccount still exists")
	}

	// UpdateStatus returns descriptive error.
	_, err = sas.UpdateStatus(&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "my-sa", Namespace: "test-ns"}})
	if err == nil {
		t.Fatal("UpdateStatus() expected error for ServiceAccount, got nil")
	}
	if !strings.Contains(err.Error(), "does not support status subresource") {
		t.Fatalf("UpdateStatus() error = %q, want 'does not support status subresource'", err.Error())
	}
}
