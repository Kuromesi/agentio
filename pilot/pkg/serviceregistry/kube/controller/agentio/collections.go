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
	"context"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	agentsclient "github.com/openkruise/agents-api/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"

	"istio.io/istio/pkg/config/schema/kubeclient"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/kubetypes"
)

var (
	securityProfileGVR = schema.GroupVersionResource{
		Group: "agents.kruise.io", Version: "v1alpha1", Resource: "securityprofiles",
	}
	securityProfileGVK = schema.GroupVersionKind{
		Group: "agents.kruise.io", Version: "v1alpha1", Kind: "SecurityProfile",
	}
	globalSecurityProfileGVR = schema.GroupVersionResource{
		Group: "agents.kruise.io", Version: "v1alpha1", Resource: "globalsecurityprofiles",
	}
	globalSecurityProfileGVK = schema.GroupVersionKind{
		Group: "agents.kruise.io", Version: "v1alpha1", Kind: "GlobalSecurityProfile",
	}
)

// registerSecurityProfileType registers the typed SecurityProfile List/Watch
// path used by the optional SNI-policy pipeline.
func registerSecurityProfileType(agentsCS agentsclient.Interface) {
	kubeclient.Register[*agentsv1alpha1.SecurityProfile](securityProfileGVR, securityProfileGVK,
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (runtime.Object, error) {
			return agentsCS.AgentsV1alpha1().SecurityProfiles(ns).List(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (watch.Interface, error) {
			return agentsCS.AgentsV1alpha1().SecurityProfiles(ns).Watch(context.Background(), opts)
		},
		nil,
	)
}

// registerGlobalSecurityProfileType registers the typed GlobalSecurityProfile
// List/Watch path used by the optional SNI-policy pipeline.
func registerGlobalSecurityProfileType(agentsCS agentsclient.Interface) {
	kubeclient.Register[*agentsv1alpha1.GlobalSecurityProfile](globalSecurityProfileGVR, globalSecurityProfileGVK,
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (runtime.Object, error) {
			return agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().List(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (watch.Interface, error) {
			return agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().Watch(context.Background(), opts)
		},
		nil,
	)
}

// registerTypes registers the always-on agents-api policy types with the
// kubeclient informer mechanism so NewDelayedInformer can use typed List/Watch
// instead of unstructured objects.
func registerTypes(agentsCS agentsclient.Interface) {
	tpGVR := schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "trafficpolicies"}
	tpGVK := schema.GroupVersionKind{Group: "agents.kruise.io", Version: "v1alpha1", Kind: "TrafficPolicy"}
	kubeclient.Register[*agentsv1alpha1.TrafficPolicy](tpGVR, tpGVK,
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (runtime.Object, error) {
			return agentsCS.AgentsV1alpha1().TrafficPolicies(ns).List(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (watch.Interface, error) {
			return agentsCS.AgentsV1alpha1().TrafficPolicies(ns).Watch(context.Background(), opts)
		},
		nil,
	)

	gtpGVR := schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "globaltrafficpolicies"}
	gtpGVK := schema.GroupVersionKind{Group: "agents.kruise.io", Version: "v1alpha1", Kind: "GlobalTrafficPolicy"}
	kubeclient.Register[*agentsv1alpha1.GlobalTrafficPolicy](gtpGVR, gtpGVK,
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (runtime.Object, error) {
			return agentsCS.AgentsV1alpha1().GlobalTrafficPolicies().List(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (watch.Interface, error) {
			return agentsCS.AgentsV1alpha1().GlobalTrafficPolicies().Watch(context.Background(), opts)
		},
		nil,
	)

	kubeclient.Register[*agentsv1alpha1.GlobalSecurityProfile](globalSecurityProfileGVR, globalSecurityProfileGVK,
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (runtime.Object, error) {
			return agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().List(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, ns string, opts metav1.ListOptions) (watch.Interface, error) {
			return agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().Watch(context.Background(), opts)
		},
		nil,
	)

	registerSecurityProfileType(agentsCS)
	registerGlobalSecurityProfileType(agentsCS)
}

func newTrafficPoliciesCollection(client kube.Client, stop <-chan struct{}, opts krt.OptionsBuilder) krt.Collection[*agentsv1alpha1.TrafficPolicy] {
	inf := kclient.NewDelayedInformer[*agentsv1alpha1.TrafficPolicy](client,
		schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "trafficpolicies"},
		kubetypes.StandardInformer, kclient.Filter{
			ObjectFilter:    client.ObjectFilter(),
			ObjectTransform: stripTrafficPolicyUnusedFields,
		})
	inf.Start(stop)
	return krt.WrapClient(inf, opts.WithName("TrafficPolicies")...)
}

func newGlobalTrafficPoliciesCollection(client kube.Client, stop <-chan struct{}, opts krt.OptionsBuilder) krt.Collection[*agentsv1alpha1.GlobalTrafficPolicy] {
	inf := kclient.NewDelayedInformer[*agentsv1alpha1.GlobalTrafficPolicy](client,
		schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: "globaltrafficpolicies"},
		kubetypes.StandardInformer, kclient.Filter{
			ObjectFilter:    client.ObjectFilter(),
			ObjectTransform: stripTrafficPolicyUnusedFields,
		})
	inf.Start(stop)
	return krt.WrapClient(inf, opts.WithName("GlobalTrafficPolicies")...)
}

func newSecurityProfilesCollection(
	client kube.Client,
	stop <-chan struct{},
	opts krt.OptionsBuilder,
) krt.Collection[*agentsv1alpha1.SecurityProfile] {
	inf := kclient.NewDelayedInformer[*agentsv1alpha1.SecurityProfile](client,
		securityProfileGVR, kubetypes.StandardInformer, kclient.Filter{
			ObjectFilter:    client.ObjectFilter(),
			ObjectTransform: stripSecurityProfileUnusedFields,
		})
	inf.Start(stop)
	return krt.WrapClient(inf, opts.WithName("SecurityProfilesForSniPolicy")...)
}

func newGlobalSecurityProfilesCollection(
	client kube.Client,
	stop <-chan struct{},
	opts krt.OptionsBuilder,
) krt.Collection[*agentsv1alpha1.GlobalSecurityProfile] {
	inf := kclient.NewDelayedInformer[*agentsv1alpha1.GlobalSecurityProfile](client,
		globalSecurityProfileGVR, kubetypes.StandardInformer, kclient.Filter{
			ObjectFilter:    client.ObjectFilter(),
			ObjectTransform: stripSecurityProfileUnusedFields,
		})
	inf.Start(stop)
	return krt.WrapClient(inf, opts.WithName("GlobalSecurityProfilesForSniPolicy")...)
}
