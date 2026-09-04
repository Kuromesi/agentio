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

package gatewaydeployer

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/openkruise/agentio/pkg/kube/kclient"
)

func TestClassForPrefersGatewayClassObject(t *testing.T) {
	informer := cache.NewSharedIndexInformer(&cache.ListWatch{}, &gatewayv1.GatewayClass{}, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	classes := kclient.New[*gatewayv1.GatewayClass](informer)
	if err := informer.GetStore().Add(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "custom"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController("agentio.kruise.io/egress-gateway-controller")},
	}); err != nil {
		t.Fatal(err)
	}

	got, ok := classFor(&gatewayv1.Gateway{Spec: gatewayv1.GatewaySpec{GatewayClassName: gatewayv1.ObjectName("custom")}}, classes)
	if !ok {
		t.Fatal("classFor returned ok=false")
	}
	if got.templateName != "egress-gateway" || got.defaultServiceType != corev1.ServiceTypeClusterIP || !got.disableNameSuffix {
		t.Fatalf("classFor = %+v, want egress-gateway class", got)
	}
}

func TestClassForFallsBackToBuiltinTable(t *testing.T) {
	informer := cache.NewSharedIndexInformer(&cache.ListWatch{}, &gatewayv1.GatewayClass{}, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	classes := kclient.New[*gatewayv1.GatewayClass](informer)

	got, ok := classFor(&gatewayv1.Gateway{Spec: gatewayv1.GatewaySpec{GatewayClassName: gatewayv1.ObjectName("agentio-egress")}}, classes)
	if !ok {
		t.Fatal("classFor builtin returned ok=false")
	}
	if got.controller != "agentio.kruise.io/egress-gateway-controller" {
		t.Fatalf("classFor builtin controller = %q, want agentio.kruise.io/egress-gateway-controller", got.controller)
	}
	if _, ok := classFor(&gatewayv1.Gateway{Spec: gatewayv1.GatewaySpec{GatewayClassName: gatewayv1.ObjectName("unknown")}}, classes); ok {
		t.Fatal("classFor unknown returned ok=true")
	}
	// "istio-waypoint" is not a builtin class and must not resolve.
	if _, ok := classFor(&gatewayv1.Gateway{Spec: gatewayv1.GatewaySpec{GatewayClassName: gatewayv1.ObjectName("istio-waypoint")}}, classes); ok {
		t.Fatal("classFor istio-waypoint returned ok=true, want false now that Istio compatibility classes are removed")
	}
}

func TestGetDefaultName(t *testing.T) {
	if got := getDefaultName("gateway", "agentio-egress", builtinClasses["agentio-egress"].disableNameSuffix); got != "gateway" {
		t.Fatalf("default agentio-egress name = %q, want gateway", got)
	}
	// The suffix is the Gateway's own class name even when resolved via controllerName.
	if got := getDefaultName("gateway", "my-ingress", false); got != "gateway-my-ingress" {
		t.Fatalf("default custom-class name = %q, want gateway-my-ingress", got)
	}
}

// Verifies a custom-named class resolved via controllerName inherits disableNameSuffix.
func TestGetDefaultNameCustomClassViaControllerName(t *testing.T) {
	informer := cache.NewSharedIndexInformer(&cache.ListWatch{}, &gatewayv1.GatewayClass{}, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	classes := kclient.New[*gatewayv1.GatewayClass](informer)
	if err := informer.GetStore().Add(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-egress"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController("agentio.kruise.io/egress-gateway-controller")},
	}); err != nil {
		t.Fatal(err)
	}

	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "alpha"}, Spec: gatewayv1.GatewaySpec{GatewayClassName: gatewayv1.ObjectName("my-egress")}}
	ci, ok := classFor(gw, classes)
	if !ok {
		t.Fatal("classFor returned ok=false")
	}
	// agentio-egress has disableNameSuffix=true: the resolved default name is
	// just the Gateway name, never the class name.
	if got := getDefaultName(gw.Name, string(gw.Spec.GatewayClassName), ci.disableNameSuffix); got != "alpha" {
		t.Fatalf("getDefaultName for custom class via controllerName = %q, want alpha (suffix disabled)", got)
	}

	// A second custom class resolving to the SAME classInfo must also produce
	// the Gateway's own name only, not the builtin key "agentio-egress".
	if err := informer.GetStore().Add(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-other-egress"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController("agentio.kruise.io/egress-gateway-controller")},
	}); err != nil {
		t.Fatal(err)
	}
	gw2 := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "beta"}, Spec: gatewayv1.GatewaySpec{GatewayClassName: gatewayv1.ObjectName("my-other-egress")}}
	ci2, ok := classFor(gw2, classes)
	if !ok {
		t.Fatal("classFor returned ok=false for second custom class")
	}
	got1 := getDefaultName(gw.Name, string(gw.Spec.GatewayClassName), ci.disableNameSuffix)
	got2 := getDefaultName(gw2.Name, string(gw2.Spec.GatewayClassName), ci2.disableNameSuffix)
	// Different gateway names must produce different deployment names even when
	// both classes resolve to the same classInfo.
	if got1 == got2 {
		t.Fatalf("two custom classes resolving to the same classInfo collided on name %q", got1)
	}
}
