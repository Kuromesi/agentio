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

package namespace

import (
	"context"
	"testing"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/cluster"
	"github.com/openkruise/agentio/test/e2e/kube"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestCreateUsesUniqueDNSNameLabelsAndTestCleanup(t *testing.T) {
	env, dynamicClient := namespaceEnvironment(t)
	var created Instance
	t.Run("scope", func(t *testing.T) {
		created = Create(t, env, Config{Prefix: "Traffic Policy_"})
		if problems := validation.IsDNS1123Label(created.Name()); len(problems) != 0 {
			t.Fatalf("name %q is not DNS-1123: %v", created.Name(), problems)
		}
		live, err := dynamicClient.Resource(namespaceGVR).Get(context.Background(), created.Name(), metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if live.GetLabels()[kube.RunLabel] != "run-1" || live.GetLabels()[kube.TestLabel] != "TestCreateUsesUniqueDNSNameLabelsAndTestCleanup-scope" {
			t.Fatalf("labels = %#v", live.GetLabels())
		}
	})
	_, err := dynamicClient.Resource(namespaceGVR).Get(context.Background(), created.Name(), metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("namespace remains after t.Cleanup: %v", err)
	}
}

func TestCreateGeneratesDifferentNames(t *testing.T) {
	env, _ := namespaceEnvironment(t)
	first := Create(t, env, Config{Prefix: "case"})
	second := Create(t, env, Config{Prefix: "case"})
	if first.Name() == second.Name() {
		t.Fatalf("generated duplicate name %q", first.Name())
	}
}

func TestApplyReturnsNamespaceAndCleanup(t *testing.T) {
	environment, dynamicClient := namespaceEnvironment(t)
	instance, cleanup, err := Apply(context.Background(), environment, Config{Prefix: "sandbox", StableName: true})
	if err != nil {
		t.Fatal(err)
	}
	if instance.Name() != "sandbox" || cleanup == nil {
		t.Fatalf("instance = %+v, cleanup present = %t", instance, cleanup != nil)
	}
	if _, err := dynamicClient.Resource(namespaceGVR).Get(context.Background(), "sandbox", metav1.GetOptions{}); err != nil {
		t.Fatalf("namespace was not applied: %v", err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := dynamicClient.Resource(namespaceGVR).Get(context.Background(), "sandbox", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("namespace remains after cleanup: %v", err)
	}
}

func namespaceEnvironment(t *testing.T) (*e2e.Environment, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	dynamicClient.PrependReactor("create", "namespaces", func(action ktesting.Action) (bool, runtime.Object, error) {
		object := action.(ktesting.CreateAction).GetObject().DeepCopyObject().(*unstructured.Unstructured)
		object.SetUID(types.UID("uid-" + object.GetName()))
		if err := unstructured.SetNestedField(object.Object, "Active", "status", "phase"); err != nil {
			return true, nil, err
		}
		if err := dynamicClient.Tracker().Create(namespaceGVR, object, ""); err != nil {
			return true, nil, err
		}
		return true, object, nil
	})
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Group: "", Version: "v1"}})
	mapper.Add(namespaceGVK, meta.RESTScopeRoot)
	client := kube.NewClient("run-1", &cluster.Cluster{Dynamic: dynamicClient, Mapper: mapper}, kube.NewLedger()).WithTestID(t.Name())
	return &e2e.Environment{RunID: "run-1", Kube: client}, dynamicClient
}

var (
	namespaceGVK = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}
	namespaceGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
)
