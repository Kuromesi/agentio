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
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"istio.io/istio/pkg/ptr"

	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
)

// NewFiltered creates a shared, typed informer from the process kube.Client.
// Informers with the same GVR, namespace, and selectors share one cache.
func NewFiltered[T controllers.ComparableObject](
	client kube.Client,
	filter Filter,
) StartableInformer[T] {
	return NewFilteredFor[T](client, registrationFor[T](client), filter)
}

// NewFilteredFor is the external-API variant of NewFiltered. The registration
// supplies typed List/Watch functions without adding that API to kube.Client.
func NewFilteredFor[T controllers.ComparableObject](
	client kube.Client,
	registration kube.InformerRegistration,
	filter Filter,
) StartableInformer[T] {
	return newFilteredFor[T](client, registration, filter)
}

func newFilteredFor[T controllers.ComparableObject](
	client kube.Client,
	registration kube.InformerRegistration,
	filter Filter,
) *activeInformer[T] {
	source := client.InformerFor(registration, kube.InformerOptions{
		LabelSelector:   filter.LabelSelector,
		FieldSelector:   filter.FieldSelector,
		Namespace:       filter.Namespace,
		ObjectTransform: filter.ObjectTransform,
	})
	return &activeInformer[T]{
		Informer: newInformerClient[T](source.Informer, filter),
		start:    source.Start,
	}
}

func registrationFor[T controllers.ComparableObject](client kube.Client) kube.InformerRegistration {
	var registration kube.InformerRegistration
	switch any(ptr.Empty[T]()).(type) {
	case *corev1.Pod:
		registration = namespacedRegistration(
			schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "pods",
			},
			&corev1.Pod{},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.Kube().CoreV1().Pods(namespace).List(ctx, options)
			},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.Kube().CoreV1().Pods(namespace).Watch(ctx, options)
			},
		)
	case *corev1.Service:
		registration = namespacedRegistration(
			schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "services",
			},
			&corev1.Service{},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.Kube().CoreV1().Services(namespace).List(ctx, options)
			},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.Kube().CoreV1().Services(namespace).Watch(ctx, options)
			},
		)
	case *corev1.ServiceAccount:
		registration = namespacedRegistration(
			schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "serviceaccounts",
			},
			&corev1.ServiceAccount{},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.Kube().CoreV1().ServiceAccounts(namespace).List(ctx, options)
			},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.Kube().CoreV1().ServiceAccounts(namespace).Watch(ctx, options)
			},
		)
	case *autoscalingv2.HorizontalPodAutoscaler:
		registration = namespacedRegistration(
			schema.GroupVersionResource{
				Group:    "autoscaling",
				Version:  "v2",
				Resource: "horizontalpodautoscalers",
			},
			&autoscalingv2.HorizontalPodAutoscaler{},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.Kube().AutoscalingV2().HorizontalPodAutoscalers(namespace).List(ctx, options)
			},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.Kube().AutoscalingV2().HorizontalPodAutoscalers(namespace).Watch(ctx, options)
			},
		)
	case *policyv1.PodDisruptionBudget:
		registration = namespacedRegistration(
			schema.GroupVersionResource{
				Group:    "policy",
				Version:  "v1",
				Resource: "poddisruptionbudgets",
			},
			&policyv1.PodDisruptionBudget{},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.Kube().PolicyV1().PodDisruptionBudgets(namespace).List(ctx, options)
			},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.Kube().PolicyV1().PodDisruptionBudgets(namespace).Watch(ctx, options)
			},
		)
	case *corev1.Namespace:
		registration = kube.InformerRegistration{
			Resource: schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "namespaces",
			},
			Object: &corev1.Namespace{},
			List: func(ctx context.Context, _ string, options metav1.ListOptions) (runtime.Object, error) {
				return client.Kube().CoreV1().Namespaces().List(ctx, options)
			},
			Watch: func(ctx context.Context, _ string, options metav1.ListOptions) (watch.Interface, error) {
				return client.Kube().CoreV1().Namespaces().Watch(ctx, options)
			},
		}
	case *corev1.Node:
		registration = kube.InformerRegistration{
			Resource: schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "nodes",
			},
			Object: &corev1.Node{},
			List: func(ctx context.Context, _ string, options metav1.ListOptions) (runtime.Object, error) {
				return client.Kube().CoreV1().Nodes().List(ctx, options)
			},
			Watch: func(ctx context.Context, _ string, options metav1.ListOptions) (watch.Interface, error) {
				return client.Kube().CoreV1().Nodes().Watch(ctx, options)
			},
		}
	case *appsv1.Deployment:
		registration = namespacedRegistration(
			schema.GroupVersionResource{
				Group:    "apps",
				Version:  "v1",
				Resource: "deployments",
			},
			&appsv1.Deployment{},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.Kube().AppsV1().Deployments(namespace).List(ctx, options)
			},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.Kube().AppsV1().Deployments(namespace).Watch(ctx, options)
			},
		)
	case *discoveryv1.EndpointSlice:
		registration = namespacedRegistration(
			schema.GroupVersionResource{
				Group:    discoveryv1.GroupName,
				Version:  "v1",
				Resource: "endpointslices",
			},
			&discoveryv1.EndpointSlice{},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.Kube().DiscoveryV1().EndpointSlices(namespace).List(ctx, options)
			},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.Kube().DiscoveryV1().EndpointSlices(namespace).Watch(ctx, options)
			},
		)
	case *corev1.Secret:
		registration = namespacedRegistration(
			schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "secrets",
			},
			&corev1.Secret{},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.Kube().CoreV1().Secrets(namespace).List(ctx, options)
			},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.Kube().CoreV1().Secrets(namespace).Watch(ctx, options)
			},
		)
	case *corev1.ConfigMap:
		registration = namespacedRegistration(
			schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "configmaps",
			},
			&corev1.ConfigMap{},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.Kube().CoreV1().ConfigMaps(namespace).List(ctx, options)
			},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.Kube().CoreV1().ConfigMaps(namespace).Watch(ctx, options)
			},
		)
	case *gatewayv1.Gateway:
		registration = namespacedRegistration(
			schema.GroupVersionResource{
				Group:    gatewayv1.GroupName,
				Version:  "v1",
				Resource: "gateways",
			},
			&gatewayv1.Gateway{},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.GatewayAPI().GatewayV1().Gateways(namespace).List(ctx, options)
			},
			func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.GatewayAPI().GatewayV1().Gateways(namespace).Watch(ctx, options)
			},
		)
	case *gatewayv1.GatewayClass:
		registration = kube.InformerRegistration{
			Resource: schema.GroupVersionResource{
				Group:    gatewayv1.GroupName,
				Version:  "v1",
				Resource: "gatewayclasses",
			},
			Object: &gatewayv1.GatewayClass{},
			List: func(ctx context.Context, _ string, options metav1.ListOptions) (runtime.Object, error) {
				return client.GatewayAPI().GatewayV1().GatewayClasses().List(ctx, options)
			},
			Watch: func(ctx context.Context, _ string, options metav1.ListOptions) (watch.Interface, error) {
				return client.GatewayAPI().GatewayV1().GatewayClasses().Watch(ctx, options)
			},
		}
	case *admissionregistrationv1.MutatingWebhookConfiguration:
		registration = kube.InformerRegistration{
			Resource: schema.GroupVersionResource{
				Group:    admissionregistrationv1.GroupName,
				Version:  "v1",
				Resource: "mutatingwebhookconfigurations",
			},
			Object: &admissionregistrationv1.MutatingWebhookConfiguration{},
			List: func(ctx context.Context, _ string, options metav1.ListOptions) (runtime.Object, error) {
				return client.Kube().AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, options)
			},
			Watch: func(ctx context.Context, _ string, options metav1.ListOptions) (watch.Interface, error) {
				return client.Kube().AdmissionregistrationV1().MutatingWebhookConfigurations().Watch(ctx, options)
			},
		}
	default:
		panic(fmt.Sprintf("no informer registration for %T", ptr.Empty[T]()))
	}
	return registration
}

func namespacedRegistration(
	resource schema.GroupVersionResource,
	object runtime.Object,
	list func(context.Context, string, metav1.ListOptions) (runtime.Object, error),
	watchResource func(context.Context, string, metav1.ListOptions) (watch.Interface, error),
) kube.InformerRegistration {
	return kube.InformerRegistration{
		Resource: resource,
		Object:   object,
		List:     list,
		Watch:    watchResource,
	}
}
