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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"

	"github.com/openkruise/agentio/pkg/kube"
)

func TestInformerRegistrationPreservesScopeAndSelectors(t *testing.T) {
	client := kube.NewFakeClient()
	coreFake := client.Kube().(*kubernetesfake.Clientset)
	gatewayFake := client.GatewayAPI().(*gatewayfake.Clientset)
	for _, tc := range []struct {
		name         string
		registration kube.InformerRegistration
		namespace    string
		actions      func() []clienttesting.Action
		clear        func()
	}{
		{"pods", registrationFor[*corev1.Pod](client), "app", coreFake.Actions, coreFake.ClearActions},
		{"nodes", registrationFor[*corev1.Node](client), "", coreFake.Actions, coreFake.ClearActions},
		{"gateways", registrationFor[*gatewayv1.Gateway](client), "app", gatewayFake.Actions, gatewayFake.ClearActions},
		{"gatewayclasses", registrationFor[*gatewayv1.GatewayClass](client), "", gatewayFake.Actions, gatewayFake.ClearActions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.clear()
			options := metav1.ListOptions{LabelSelector: "app=worker", FieldSelector: "metadata.name=example"}
			if _, err := tc.registration.List(context.Background(), "app", options); err != nil {
				t.Fatal(err)
			}
			watcher, err := tc.registration.Watch(context.Background(), "app", options)
			if err != nil {
				t.Fatal(err)
			}
			watcher.Stop()
			actions := tc.actions()
			if len(actions) != 2 {
				t.Fatalf("got %d actions, want List and Watch", len(actions))
			}
			for _, action := range actions {
				if action.GetNamespace() != tc.namespace || action.GetResource() != tc.registration.Resource {
					t.Fatalf("incorrect scope or resource: %#v", action)
				}
			}
			list := actions[0].(clienttesting.ListAction).GetListRestrictions()
			watch := actions[1].(clienttesting.WatchAction).GetWatchRestrictions()
			if list.Labels.String() != options.LabelSelector || list.Fields.String() != options.FieldSelector || watch.Labels.String() != options.LabelSelector || watch.Fields.String() != options.FieldSelector {
				t.Fatal("List or Watch lost selectors")
			}
		})
	}
}
