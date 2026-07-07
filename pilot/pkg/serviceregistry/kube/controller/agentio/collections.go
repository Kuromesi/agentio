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

package agentio

import (
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/kubetypes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func unstructuredToTyped[T any](us *unstructured.Unstructured) (T, error) {
	var empty T
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(us.Object, &empty)
	return empty, err
}

func newTrafficPoliciesCollection(client kube.Client, stop <-chan struct{}) krt.Collection[model.TrafficPolicy] {
	trafficPolicies := kclient.NewDelayedInformer[*unstructured.Unstructured](client, schema.GroupVersionResource{
		Group:    "network.alibabacloud.com",
		Version:  "v1alpha1",
		Resource: "trafficpolicies",
	}, kubetypes.DynamicInformer, kclient.Filter{
		ObjectFilter: client.ObjectFilter(),
	})
	trafficPolicies.Start(stop)

	return krt.NewCollection(krt.WrapClient(trafficPolicies), func(ctx krt.HandlerContext, i *unstructured.Unstructured) *model.TrafficPolicy {
		policy, err := unstructuredToTyped[model.TrafficPolicy](i)
		if err != nil {
			log.Warnf("Failed to convert traffic policy to typed, err: %v", err)
			return nil
		}
		return &policy
	})
}

func newGlobalTrafficPoliciesCollection(client kube.Client, stop <-chan struct{}) krt.Collection[model.GlobalTrafficPolicy] {
	globalTrafficPolicies := kclient.NewDelayedInformer[*unstructured.Unstructured](client, schema.GroupVersionResource{
		Group:    "network.alibabacloud.com",
		Version:  "v1alpha1",
		Resource: "globaltrafficpolicies",
	}, kubetypes.DynamicInformer, kclient.Filter{
		ObjectFilter: client.ObjectFilter(),
	})
	globalTrafficPolicies.Start(stop)

	return krt.NewCollection(krt.WrapClient(globalTrafficPolicies), func(ctx krt.HandlerContext, i *unstructured.Unstructured) *model.GlobalTrafficPolicy {
		policy, err := unstructuredToTyped[model.GlobalTrafficPolicy](i)
		if err != nil {
			log.Warnf("Failed to convert global traffic policy to typed, err: %v", err)
			return nil
		}
		return &policy
	})
}
