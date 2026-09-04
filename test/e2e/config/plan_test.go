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

package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openkruise/agentio/test/e2e/cluster"
	"github.com/openkruise/agentio/test/e2e/kube"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestPlanEvalAppliesDocumentsWithRESTScopedNamespaces(t *testing.T) {
	scope, _, _ := planScope(t, "")
	plan := New(scope).Eval("sandbox", map[string]string{"Name": "settings"}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Name }}
---
apiVersion: v1
kind: Namespace
metadata:
  name: fixture
  namespace: must-be-cleared
`)

	records, err := plan.Apply(context.Background(), kube.CreateOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %+v", records)
	}
	if records[0].Name != "settings" || records[0].Namespace != "sandbox" || !records[0].Namespaced {
		t.Fatalf("ConfigMap record = %+v", records[0])
	}
	if records[1].Name != "fixture" || records[1].Namespace != "" || records[1].Namespaced {
		t.Fatalf("Namespace record = %+v", records[1])
	}
}

func TestPlanEvalRejectsMissingKeyBeforeMutation(t *testing.T) {
	scope, applied, _ := planScope(t, "")
	plan := New(scope).
		YAML("sandbox", configMapYAML("first")).
		Eval("sandbox", map[string]string{}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Missing }}
`)

	_, err := plan.Apply(context.Background(), kube.CreateOnly)
	if err == nil || !strings.Contains(err.Error(), "Missing") {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(*applied) != 0 {
		t.Fatalf("applied = %v, want no mutation", *applied)
	}
}

func TestPlanFileAndEvalFile(t *testing.T) {
	directory := t.TempDir()
	plainPath := filepath.Join(directory, "plain.yaml")
	templatePath := filepath.Join(directory, "template.yaml")
	if err := os.WriteFile(plainPath, []byte(configMapYAML("plain")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(templatePath, []byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Name }}
`), 0o600); err != nil {
		t.Fatal(err)
	}

	scope, _, _ := planScope(t, "")
	records, err := New(scope).
		File("sandbox", plainPath).
		EvalFile("sandbox", map[string]string{"Name": "evaluated"}, templatePath).
		Apply(context.Background(), kube.CreateOnly)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{records[0].Name, records[1].Name}; !reflect.DeepEqual(got, []string{"plain", "evaluated"}) {
		t.Fatalf("record names = %v", got)
	}
}

func TestPlanCopyIsIndependentAndDeleteIsReverseOrdered(t *testing.T) {
	scope, _, deleted := planScope(t, "")
	base := New(scope).YAML("sandbox", configMapYAML("first"))
	copy := base.Copy().YAML("sandbox", configMapYAML("second"))

	if _, err := base.Apply(context.Background(), kube.CreateOnly); err != nil {
		t.Fatal(err)
	}
	if err := base.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := copy.Apply(context.Background(), kube.CreateOnly); err != nil {
		t.Fatal(err)
	}
	if err := copy.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"first", "second", "first"}; !reflect.DeepEqual(*deleted, want) {
		t.Fatalf("delete order = %v, want %v", *deleted, want)
	}
	if err := copy.Delete(context.Background()); err != nil {
		t.Fatalf("second Delete() = %v", err)
	}
}

func TestPlanKeepsSuccessfulRecordsAfterPartialApply(t *testing.T) {
	scope, _, deleted := planScope(t, "second")
	plan := New(scope).YAML("sandbox", configMapYAML("first"), configMapYAML("second"))

	records, err := plan.Apply(context.Background(), kube.CreateOnly)
	if err == nil || !strings.Contains(err.Error(), "injected apply failure") {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(records) != 1 || records[0].Name != "first" {
		t.Fatalf("records = %+v", records)
	}
	if err := plan.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"first"}; !reflect.DeepEqual(*deleted, want) {
		t.Fatalf("deleted = %v, want %v", *deleted, want)
	}
}

func TestPlanRejectsNilScopeAndUnreadableFile(t *testing.T) {
	_, err := New(nil).YAML("sandbox", configMapYAML("settings")).Apply(context.Background(), kube.CreateOnly)
	if err == nil || !strings.Contains(err.Error(), "resource scope") {
		t.Fatalf("nil scope error = %v", err)
	}

	_, err = New(nil).File("sandbox", filepath.Join(t.TempDir(), "missing.yaml")).Apply(context.Background(), kube.CreateOnly)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error = %v", err)
	}
}

func planScope(t *testing.T, failName string) (*kube.ResourceScope, *[]string, *[]string) {
	t.Helper()
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Group: "", Version: "v1"}})
	mapper.Add(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"}, meta.RESTScopeNamespace)
	mapper.Add(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}, meta.RESTScopeRoot)
	client := kube.NewClient("run-1", &cluster.Cluster{Dynamic: dynamicClient, Mapper: mapper}, kube.NewLedger())
	applied := []string{}
	dynamicClient.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		object := action.(ktesting.CreateAction).GetObject().DeepCopyObject().(*unstructured.Unstructured)
		if object.GetName() == failName {
			return true, nil, errors.New("injected apply failure")
		}
		object.SetUID(types.UID("uid-" + object.GetName()))
		if err := dynamicClient.Tracker().Create(action.GetResource(), object, action.GetNamespace()); err != nil {
			return true, nil, err
		}
		applied = append(applied, object.GetName())
		return true, object, nil
	})
	deleted := []string{}
	dynamicClient.PrependReactor("delete", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		deleted = append(deleted, action.(ktesting.DeleteAction).GetName())
		return false, nil, nil
	})
	return kube.NewResourceScope(client), &applied, &deleted
}

func configMapYAML(name string) string {
	return `
apiVersion: v1
kind: ConfigMap
metadata:
  name: ` + name + `
data:
  key: value
`
}
