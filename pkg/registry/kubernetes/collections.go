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

package kubernetes

import (
	"context"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

var (
	trafficPolicyResource = schema.GroupVersionResource{
		Group:    "agents.kruise.io",
		Version:  "v1alpha1",
		Resource: "trafficpolicies",
	}
	globalTrafficPolicyResource = schema.GroupVersionResource{
		Group:    "agents.kruise.io",
		Version:  "v1alpha1",
		Resource: "globaltrafficpolicies",
	}
	securityProfileResource = schema.GroupVersionResource{
		Group:    "agents.kruise.io",
		Version:  "v1alpha1",
		Resource: "securityprofiles",
	}
	globalSecurityProfileResource = schema.GroupVersionResource{
		Group:    "agents.kruise.io",
		Version:  "v1alpha1",
		Resource: "globalsecurityprofiles",
	}
)

func newTrafficPoliciesCollection(
	client kube.Client,
	stop <-chan struct{},
	options ...krt.CollectionOption,
) krt.Collection[*agentsv1alpha1.TrafficPolicy] {
	informer := kclient.NewDelayedInformerFor[*agentsv1alpha1.TrafficPolicy](
		client,
		kube.InformerRegistration{
			Resource: trafficPolicyResource,
			Object:   &agentsv1alpha1.TrafficPolicy{},
			List: func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.AgentsAPI().AgentsV1alpha1().TrafficPolicies(namespace).List(ctx, options)
			},
			Watch: func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.AgentsAPI().AgentsV1alpha1().TrafficPolicies(namespace).Watch(ctx, options)
			},
		},
		kclient.Filter{
			ObjectTransform: stripTrafficPolicy,
		},
	)
	informer.Start(stop)
	return krt.WrapClient(informer, options...)
}

func newGlobalTrafficPoliciesCollection(
	client kube.Client,
	stop <-chan struct{},
	options ...krt.CollectionOption,
) krt.Collection[*agentsv1alpha1.GlobalTrafficPolicy] {
	informer := kclient.NewDelayedInformerFor[*agentsv1alpha1.GlobalTrafficPolicy](
		client,
		kube.InformerRegistration{
			Resource: globalTrafficPolicyResource,
			Object:   &agentsv1alpha1.GlobalTrafficPolicy{},
			List: func(ctx context.Context, _ string, options metav1.ListOptions) (runtime.Object, error) {
				return client.AgentsAPI().AgentsV1alpha1().GlobalTrafficPolicies().List(ctx, options)
			},
			Watch: func(ctx context.Context, _ string, options metav1.ListOptions) (watch.Interface, error) {
				return client.AgentsAPI().AgentsV1alpha1().GlobalTrafficPolicies().Watch(ctx, options)
			},
		},
		kclient.Filter{
			ObjectTransform: stripTrafficPolicy,
		},
	)
	informer.Start(stop)
	return krt.WrapClient(informer, options...)
}

func newSecurityProfilesCollection(
	client kube.Client,
	stop <-chan struct{},
	options ...krt.CollectionOption,
) krt.Collection[*agentsv1alpha1.SecurityProfile] {
	informer := kclient.NewDelayedInformerFor[*agentsv1alpha1.SecurityProfile](
		client,
		kube.InformerRegistration{
			Resource: securityProfileResource,
			Object:   &agentsv1alpha1.SecurityProfile{},
			List: func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.AgentsAPI().AgentsV1alpha1().SecurityProfiles(namespace).List(ctx, options)
			},
			Watch: func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.AgentsAPI().AgentsV1alpha1().SecurityProfiles(namespace).Watch(ctx, options)
			},
		},
		kclient.Filter{
			ObjectTransform: stripSecurityProfile,
		},
	)
	informer.Start(stop)
	return krt.WrapClient(informer, options...)
}

func newGlobalSecurityProfilesCollection(
	client kube.Client,
	stop <-chan struct{},
	options ...krt.CollectionOption,
) krt.Collection[*agentsv1alpha1.GlobalSecurityProfile] {
	informer := kclient.NewDelayedInformerFor[*agentsv1alpha1.GlobalSecurityProfile](
		client,
		kube.InformerRegistration{
			Resource: globalSecurityProfileResource,
			Object:   &agentsv1alpha1.GlobalSecurityProfile{},
			List: func(ctx context.Context, _ string, options metav1.ListOptions) (runtime.Object, error) {
				return client.AgentsAPI().AgentsV1alpha1().GlobalSecurityProfiles().List(ctx, options)
			},
			Watch: func(ctx context.Context, _ string, options metav1.ListOptions) (watch.Interface, error) {
				return client.AgentsAPI().AgentsV1alpha1().GlobalSecurityProfiles().Watch(ctx, options)
			},
		},
		kclient.Filter{
			ObjectTransform: stripSecurityProfile,
		},
	)
	informer.Start(stop)
	return krt.WrapClient(informer, options...)
}
