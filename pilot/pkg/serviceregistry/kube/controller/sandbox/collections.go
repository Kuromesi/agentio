package sandbox

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
