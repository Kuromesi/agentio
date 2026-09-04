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
	"fmt"
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestResourceScopeDeletesAppliedResourcesInReverse(t *testing.T) {
	client, deleted := scopeClient(t, "")
	scope := NewResourceScope(client)
	for _, name := range []string{"first", "second", "third"} {
		if _, err := scope.Apply(context.Background(), configMap("sandbox", name), CreateOnly); err != nil {
			t.Fatal(err)
		}
	}
	if err := scope.DeleteReverse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"third", "second", "first"}; !reflect.DeepEqual(*deleted, want) {
		t.Fatalf("delete order = %v, want %v", *deleted, want)
	}
	if err := scope.DeleteReverse(context.Background()); err != nil {
		t.Fatalf("second cleanup: %v", err)
	}
}

func TestResourceScopeKeepsEarlierRecordsWhenLaterApplyFails(t *testing.T) {
	client, deleted := scopeClient(t, "second")
	scope := NewResourceScope(client)
	if _, err := scope.Apply(context.Background(), configMap("sandbox", "first"), CreateOnly); err != nil {
		t.Fatal(err)
	}
	if _, err := scope.Apply(context.Background(), configMap("sandbox", "second"), CreateOnly); err == nil || !strings.Contains(err.Error(), "injected apply failure") {
		t.Fatalf("second Apply() error = %v", err)
	}
	if err := scope.DeleteReverse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"first"}; !reflect.DeepEqual(*deleted, want) {
		t.Fatalf("deleted = %v, want %v", *deleted, want)
	}
}

func TestResourceScopeDeleteUsesOwnedIdentity(t *testing.T) {
	client, deleted := scopeClient(t, "")
	scope := NewResourceScope(client)
	record, err := scope.Apply(context.Background(), configMap("sandbox", "settings"), CreateOnly)
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.Delete(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if want := []string{"settings"}; !reflect.DeepEqual(*deleted, want) {
		t.Fatalf("deleted = %v, want %v", *deleted, want)
	}

	recreated := configMap("sandbox", "foreign")
	recreated.SetUID("uid-new")
	recreated.SetLabels(map[string]string{RunLabel: "run-1"})
	client, _ = newFakeClient(t, recreated)
	scope = NewResourceScope(client)
	err = scope.Delete(context.Background(), ResourceRecord{
		GVR: configMapGVR, Namespace: "sandbox", Name: "foreign",
		UID: "uid-old", RunID: "run-1", Namespaced: true,
	})
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("Delete() error = %v, want ownership mismatch", err)
	}
}

func TestResourceScopeApplyInNamespaceRecordsDefaultNamespace(t *testing.T) {
	client, _ := scopeClient(t, "")
	scope := NewResourceScope(client)
	record, err := scope.ApplyInNamespace(context.Background(), "sandbox", configMap("", "settings"), CreateOnly)
	if err != nil {
		t.Fatal(err)
	}
	if record.Namespace != "sandbox" {
		t.Fatalf("record namespace = %q, want sandbox", record.Namespace)
	}
}

func TestResourceScopeRejectsNilClient(t *testing.T) {
	scope := NewResourceScope(nil)
	if _, err := scope.Apply(context.Background(), configMap("sandbox", "settings"), CreateOnly); err == nil || !strings.Contains(err.Error(), "Kubernetes client") {
		t.Fatalf("Apply() error = %v", err)
	}
	if _, err := scope.ApplyInNamespace(context.Background(), "sandbox", configMap("", "settings"), CreateOnly); err == nil || !strings.Contains(err.Error(), "Kubernetes client") {
		t.Fatalf("ApplyInNamespace() error = %v", err)
	}
	if err := scope.Delete(context.Background(), ResourceRecord{}); err == nil || !strings.Contains(err.Error(), "Kubernetes client") {
		t.Fatalf("Delete() error = %v", err)
	}
	if err := scope.DeleteReverse(context.Background()); err == nil || !strings.Contains(err.Error(), "Kubernetes client") {
		t.Fatalf("DeleteReverse() error = %v", err)
	}
}

func scopeClient(t *testing.T, failName string) (*Client, *[]string) {
	t.Helper()
	client, _ := newFakeClient(t)
	fakeClient := client.dynamic.(*dynamicfake.FakeDynamicClient)
	fakeClient.PrependReactor("create", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		object := action.(ktesting.CreateAction).GetObject().(*unstructured.Unstructured).DeepCopy()
		if object.GetName() == failName {
			return true, nil, errors.New("injected apply failure")
		}
		object.SetUID(types.UID(fmt.Sprintf("uid-%s", object.GetName())))
		if err := fakeClient.Tracker().Create(configMapGVR, object, object.GetNamespace()); err != nil {
			return true, nil, err
		}
		return true, object, nil
	})
	deleted := []string{}
	fakeClient.PrependReactor("delete", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		deleted = append(deleted, action.(ktesting.DeleteAction).GetName())
		return false, nil, nil
	})
	return client, &deleted
}
