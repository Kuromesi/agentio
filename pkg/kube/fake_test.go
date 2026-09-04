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
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestNewFakeClientProvidesOwnedClientSurfaces(t *testing.T) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "agentio-config",
		},
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "egress",
		},
	}
	client := NewFakeClient(configMap, gateway)

	if client.GatewayAPI() == nil {
		t.Fatal("GatewayAPI() is nil")
	}
	if client.AgentsAPI() == nil {
		t.Fatal("AgentsAPI() is nil")
	}
	if client.Dynamic() == nil {
		t.Fatal("Dynamic() is nil")
	}
	if _, err := client.Kube().CoreV1().ConfigMaps(configMap.Namespace).Get(
		context.Background(), configMap.Name, metav1.GetOptions{},
	); err != nil {
		t.Fatalf("Kube() does not expose the seeded object: %v", err)
	}
	if _, err := client.GatewayAPI().GatewayV1().Gateways(gateway.Namespace).Get(
		context.Background(), gateway.Name, metav1.GetOptions{},
	); err != nil {
		t.Fatalf("GatewayAPI() does not expose the seeded object: %v", err)
	}
}
