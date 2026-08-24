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

package trafficpolicy

import (
	"context"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	agentsclient "github.com/openkruise/agents-api/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pkg/config/schema/kubeclient"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/kubetypes"
)

var (
	trafficPolicyGVR = schema.GroupVersionResource{
		Group: "agents.kruise.io", Version: "v1alpha1", Resource: "trafficpolicies",
	}
	trafficPolicyGVK = schema.GroupVersionKind{
		Group: "agents.kruise.io", Version: "v1alpha1", Kind: "TrafficPolicy",
	}
	globalTrafficPolicyGVR = schema.GroupVersionResource{
		Group: "agents.kruise.io", Version: "v1alpha1", Resource: "globaltrafficpolicies",
	}
	globalTrafficPolicyGVK = schema.GroupVersionKind{
		Group: "agents.kruise.io", Version: "v1alpha1", Kind: "GlobalTrafficPolicy",
	}
)

// RegisterTypes registers typed List/Watch functions used by delayed
// informers. It must run before NewCollection.
func RegisterTypes(agentsCS agentsclient.Interface) {
	kubeclient.Register[*agentsv1alpha1.TrafficPolicy](trafficPolicyGVR, trafficPolicyGVK,
		func(c kubeclient.ClientGetter, namespace string, opts metav1.ListOptions) (runtime.Object, error) {
			return agentsCS.AgentsV1alpha1().TrafficPolicies(namespace).List(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
			return agentsCS.AgentsV1alpha1().TrafficPolicies(namespace).Watch(context.Background(), opts)
		},
		nil,
	)
	kubeclient.Register[*agentsv1alpha1.GlobalTrafficPolicy](globalTrafficPolicyGVR, globalTrafficPolicyGVK,
		func(c kubeclient.ClientGetter, namespace string, opts metav1.ListOptions) (runtime.Object, error) {
			return agentsCS.AgentsV1alpha1().GlobalTrafficPolicies().List(context.Background(), opts)
		},
		func(c kubeclient.ClientGetter, namespace string, opts metav1.ListOptions) (watch.Interface, error) {
			return agentsCS.AgentsV1alpha1().GlobalTrafficPolicies().Watch(context.Background(), opts)
		},
		nil,
	)
}

// NewCollection watches TrafficPolicy and GlobalTrafficPolicy and emits
// immutable compiled policies. Delayed informers allow EPE to start in a
// cluster where either CRD has not been installed yet.
func NewCollection(client kube.Client, debugger *krt.DebugHandler, stop <-chan struct{}) krt.Collection[Policy] {
	opts := krt.NewOptionsBuilder(stop, "epe", debugger)
	log := ctrllog.Log.WithName("traffic-policy")

	tpInf := kclient.NewDelayedInformer[*agentsv1alpha1.TrafficPolicy](client,
		trafficPolicyGVR, kubetypes.StandardInformer,
		kclient.Filter{ObjectFilter: client.ObjectFilter()})
	tpInf.Start(stop)
	trafficPolicies := krt.WrapClient(tpInf, opts.WithName("TrafficPolicies")...)

	gtpInf := kclient.NewDelayedInformer[*agentsv1alpha1.GlobalTrafficPolicy](client,
		globalTrafficPolicyGVR, kubetypes.StandardInformer,
		kclient.Filter{ObjectFilter: client.ObjectFilter()})
	gtpInf.Start(stop)
	globalTrafficPolicies := krt.WrapClient(gtpInf, opts.WithName("GlobalTrafficPolicies")...)

	compiled := krt.NewCollection(trafficPolicies, func(_ krt.HandlerContext, obj *agentsv1alpha1.TrafficPolicy) *Policy {
		policy, err := compilePolicy(obj, &obj.Spec, false)
		if err != nil {
			log.Error(err, "traffic policy failed to compile", "policy", obj.Namespace+"/"+obj.Name)
			return invalidPolicy(obj, &obj.Spec, false, err)
		}
		return policy
	}, opts.WithName("CompiledTrafficPolicies")...)

	compiledGlobal := krt.NewCollection(globalTrafficPolicies, func(_ krt.HandlerContext, obj *agentsv1alpha1.GlobalTrafficPolicy) *Policy {
		policy, err := compilePolicy(obj, &obj.Spec, true)
		if err != nil {
			log.Error(err, "global traffic policy failed to compile", "policy", obj.Name)
			return invalidPolicy(obj, &obj.Spec, true, err)
		}
		return policy
	}, opts.WithName("CompiledGlobalTrafficPolicies")...)

	return krt.JoinCollection([]krt.Collection[Policy]{compiled, compiledGlobal},
		append(opts.WithName("CompiledConnectTrafficPolicies"),
			krt.WithDebounce(features.KrtEventDistributeDebounce, features.KrtEventDistributeDebounceMax))...)
}
