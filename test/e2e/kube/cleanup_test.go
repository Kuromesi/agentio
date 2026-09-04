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
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestDeleteOwnedRefusesRecreatedObject(t *testing.T) {
	live := configMap("sandbox", "settings")
	live.SetUID("new-uid")
	live.SetLabels(map[string]string{RunLabel: "run-1"})
	client, _ := newFakeClient(t, live)
	record := ResourceRecord{
		GVR: configMapGVR, Namespace: "sandbox", Name: "settings", UID: "old-uid", RunID: "run-1",
	}

	err := client.DeleteOwned(context.Background(), record)
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("DeleteOwned() error = %v", err)
	}
}

func TestDeleteOwnedRefusesWrongRunLabel(t *testing.T) {
	live := configMap("sandbox", "settings")
	live.SetUID("uid-1")
	live.SetLabels(map[string]string{RunLabel: "another-run"})
	client, _ := newFakeClient(t, live)
	record := ResourceRecord{
		GVR: configMapGVR, Namespace: "sandbox", Name: "settings", UID: "uid-1", RunID: "run-1",
	}

	err := client.DeleteOwned(context.Background(), record)
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("DeleteOwned() error = %v", err)
	}
}

func TestLedgerDeletesResourcesInReverseOrder(t *testing.T) {
	first := configMap("sandbox", "first")
	first.SetUID("uid-first")
	first.SetLabels(map[string]string{RunLabel: "run-1"})
	second := configMap("sandbox", "second")
	second.SetUID("uid-second")
	second.SetLabels(map[string]string{RunLabel: "run-1"})
	client, ledger := newFakeClient(t, first, second)
	ledger.Record(ResourceRecord{GVR: configMapGVR, Namespace: "sandbox", Name: "first", UID: "uid-first", RunID: "run-1"})
	ledger.Record(ResourceRecord{GVR: configMapGVR, Namespace: "sandbox", Name: "second", UID: "uid-second", RunID: "run-1"})

	var deleted []string
	fakeClient := client.dynamic.(*dynamicfake.FakeDynamicClient)
	fakeClient.PrependReactor("delete", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		deleted = append(deleted, action.(ktesting.DeleteAction).GetName())
		return false, nil, nil
	})
	if err := ledger.DeleteReverse(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if want := []string{"second", "first"}; !reflect.DeepEqual(deleted, want) {
		t.Fatalf("deleted = %v, want %v", deleted, want)
	}
}

func TestWaitObservesUpdatedObject(t *testing.T) {
	client, _ := newFakeClient(t, configMap("sandbox", "settings"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		time.Sleep(20 * time.Millisecond)
		live, _ := client.dynamic.Resource(configMapGVR).Namespace("sandbox").Get(ctx, "settings", metav1.GetOptions{})
		_ = unstructured.SetNestedField(live.Object, "ready", "status", "phase")
		_, _ = client.dynamic.Resource(configMapGVR).Namespace("sandbox").Update(ctx, live, metav1.UpdateOptions{})
	}()
	err := client.Wait(ctx, configMapGVR, "sandbox", "settings", func(object *unstructured.Unstructured) (bool, error) {
		phase, _, _ := unstructured.NestedString(object.Object, "status", "phase")
		return phase == "ready", nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRESTMappingErrorIncludesKind(t *testing.T) {
	client, _ := newFakeClient(t)
	object := configMap("sandbox", "settings")
	object.SetGroupVersionKind(schema.GroupVersionKind{Group: "unknown.io", Version: "v1", Kind: "Missing"})
	_, err := client.Apply(context.Background(), object, CreateOnly)
	if err == nil || !strings.Contains(err.Error(), "Missing") || !meta.IsNoMatchError(err) {
		t.Fatalf("error = %v", err)
	}
}

func newTestMapper() meta.RESTMapper {
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Group: "", Version: "v1"}})
	mapper.Add(configMapGVK, meta.RESTScopeNamespace)
	return mapper
}
