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

package kube

import (
	"fmt"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	agentsfake "github.com/openkruise/agents-api/client/clientset/versioned/fake"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	metadatafake "k8s.io/client-go/metadata/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
)

// NewFakeClient creates a Client backed by client-go fake clientsets while
// retaining the real shared informer lifecycle. Tests that need optional-CRD
// discovery semantics can wrap the returned Client and override CrdWatcher.
func NewFakeClient(objects ...runtime.Object) Client {
	scheme := runtime.NewScheme()
	_ = kubescheme.AddToScheme(scheme)
	_ = agentsv1alpha1.AddToScheme(scheme)
	_ = gatewayv1.Install(scheme)
	var kubeObjects []runtime.Object
	var agentsObjects []runtime.Object
	var gatewayObjects []runtime.Object
	for _, object := range objects {
		switch object.(type) {
		case *gatewayv1.Gateway, *gatewayv1.GatewayList, *gatewayv1.GatewayClass, *gatewayv1.GatewayClassList:
			gatewayObjects = append(gatewayObjects, object)
		default:
			kinds, _, err := scheme.ObjectKinds(object)
			if err != nil {
				panic(fmt.Sprintf("classify fake Kubernetes object %T: %v", object, err))
			}
			if len(kinds) > 0 && kinds[0].Group == agentsv1alpha1.GroupVersion.Group {
				agentsObjects = append(agentsObjects, object)
			} else {
				kubeObjects = append(kubeObjects, object)
			}
		}
	}
	informers := newInformerFactory()
	// client-go's object tracker does not implement WatchList initial-event
	// bookmarks. Marking that capability accurately makes Reflector use the
	// compatible LIST/WATCH initialization path in tests.
	informers.unsupportedWatchListMode = true
	// The generic object tracker pluralizes Gateway as "gatewaies" when it
	// infers a resource from the kind. Seed the simple tracker with the exact
	// generated-client GVR instead.
	gatewayClient := gatewayfake.NewSimpleClientset()
	for _, object := range gatewayObjects {
		if err := seedGatewayObject(gatewayClient, object); err != nil {
			panic(fmt.Sprintf("seed fake Gateway API client: %v", err))
		}
	}
	return &client{
		kube:       kubefake.NewSimpleClientset(kubeObjects...),
		agentsAPI:  agentsfake.NewSimpleClientset(agentsObjects...),
		metadata:   metadatafake.NewSimpleMetadataClient(scheme),
		gatewayAPI: gatewayClient,
		dynamic:    fake.NewSimpleDynamicClient(scheme),
		informers:  informers,
	}
}

func seedGatewayObject(client *gatewayfake.Clientset, object runtime.Object) error {
	switch value := object.(type) {
	case *gatewayv1.Gateway:
		return client.Tracker().Create(
			gatewayv1.SchemeGroupVersion.WithResource("gateways"),
			value,
			value.Namespace,
		)
	case *gatewayv1.GatewayList:
		for i := range value.Items {
			if err := seedGatewayObject(client, &value.Items[i]); err != nil {
				return err
			}
		}
		return nil
	case *gatewayv1.GatewayClass:
		return client.Tracker().Create(
			gatewayv1.SchemeGroupVersion.WithResource("gatewayclasses"),
			value,
			"",
		)
	case *gatewayv1.GatewayClassList:
		for i := range value.Items {
			if err := seedGatewayObject(client, &value.Items[i]); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported object type %T", object)
	}
}
