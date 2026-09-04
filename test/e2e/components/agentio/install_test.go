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

package agentio

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/artifacts"
	"github.com/openkruise/agentio/test/e2e/cluster"
	"github.com/openkruise/agentio/test/e2e/command"
	"github.com/openkruise/agentio/test/e2e/kube"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestInstallUsesProductionChartAndOwnsPrerequisites(t *testing.T) {
	chartPath := testChart(t)
	runner := &recordingRunner{
		results: []command.Result{
			{Stderr: "Error: release: not found", ExitCode: 1},
			{Stdout: "apiVersion: v1\nkind: ConfigMap\n"},
			{},
			{},
		},
		errors: []error{errors.New("exit status 1")},
	}
	environment, applied := installEnvironment(t, runner)
	config := validConfig(t)
	config.ReleaseName = "agentio"
	config.ChartPath = chartPath

	instance, cleanup, err := Install(context.Background(), environment, config)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup == nil || instance.Namespace() != "agentio-system" || instance.ReleaseName() != "agentio" || instance.Fingerprint() == "" {
		t.Fatalf("instance = %+v, cleanup nil = %v", instance, cleanup == nil)
	}
	if got, want := *applied, []string{
		"Namespace/agentio-system",
		"CustomResourceDefinition/widgets.example.test",
		"CustomResourceDefinition/sandboxes.agents.kruise.io",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("prerequisites = %v, want %v", got, want)
	}

	valuesPath := environment.Artifacts.Path("setup", "agentio", "values.yaml")
	values, err := os.ReadFile(valuesPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{config.AgentiodImage, config.ZtunnelImage, config.ProxyInitImage, config.GatewayImage, config.EPEImage} {
		parts := strings.SplitN(image, "@", 2)
		if !strings.Contains(string(values), parts[0]) || !strings.Contains(string(values), parts[1]) {
			t.Fatalf("values do not pin image %q:\n%s", image, values)
		}
	}
	wantCommands := [][]string{
		{"helm", "status", "agentio", "--namespace", "agentio-system", "--output", "json"},
		{"helm", "template", "agentio", chartPath, "--namespace", "agentio-system", "--values", valuesPath},
		{"helm", "upgrade", "--install", "agentio", chartPath, "--namespace", "agentio-system", "--wait", "--timeout", "5m0s", "--description", "agentio-e2e:" + instance.Fingerprint(), "--skip-crds", "--values", valuesPath},
	}
	if !reflect.DeepEqual(runner.calls, wantCommands) {
		t.Fatalf("Helm commands = %#v, want %#v", runner.calls, wantCommands)
	}
	component := environment.State.Snapshot().Components["agentio"]
	if component.Fingerprint != instance.Fingerprint() || component.Images["epe"] != config.EPEImage {
		t.Fatalf("recorded component = %+v", component)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := runner.calls[len(runner.calls)-1]; !reflect.DeepEqual(got, []string{"helm", "uninstall", "agentio", "--namespace", "agentio-system", "--wait"}) {
		t.Fatalf("cleanup command = %v", got)
	}
}

func TestInstallReusesExactReleaseWithoutApplyingPrerequisites(t *testing.T) {
	config := validConfig(t)
	config.ChartPath = testChart(t)
	config.ReleaseName = "shared-agentio"
	config.Reuse = true
	values, err := chartValues(config)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := installationFingerprint(config.ChartPath, values)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{results: []command.Result{{
		Stdout: `{"info":{"description":"agentio-e2e:` + fingerprint + `"}}`,
	}}}
	environment, applied := installEnvironment(t, runner)

	instance, cleanup, err := Install(context.Background(), environment, config)
	if err != nil {
		t.Fatal(err)
	}
	if len(*applied) != 0 {
		t.Fatalf("reuse applied prerequisites: %v", *applied)
	}
	if instance.Fingerprint() != fingerprint {
		t.Fatalf("fingerprint = %q, want %q", instance.Fingerprint(), fingerprint)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"helm", "status", "shared-agentio", "--namespace", "agentio-system", "--output", "json"}}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("reuse mutated cluster: calls = %#v", runner.calls)
	}
}

func testChart(t *testing.T) string {
	t.Helper()
	chartPath := filepath.Join(t.TempDir(), "agentio")
	if err := os.MkdirAll(filepath.Join(chartPath, "crds"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(chartPath, "Chart.yaml"), []byte("apiVersion: v2\nname: agentio\nversion: 0.1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	crd := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.test\n"
	if err := os.WriteFile(filepath.Join(chartPath, "crds", "widgets.yaml"), []byte(crd), 0o600); err != nil {
		t.Fatal(err)
	}
	return chartPath
}

type recordingRunner struct {
	calls   [][]string
	results []command.Result
	errors  []error
}

func (r *recordingRunner) Run(_ context.Context, request command.Request) (command.Result, error) {
	r.calls = append(r.calls, append([]string{request.Name}, request.Args...))
	index := len(r.calls) - 1
	var result command.Result
	if index < len(r.results) {
		result = r.results[index]
	}
	var err error
	if index < len(r.errors) {
		err = r.errors[index]
	}
	return result, err
}

func installEnvironment(t *testing.T, runner command.Interface) (*e2e.Environment, *[]string) {
	t.Helper()
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	applied := &[]string{}
	dynamicClient.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		object := action.(ktesting.CreateAction).GetObject().DeepCopyObject().(*unstructured.Unstructured)
		object.SetUID(types.UID("uid-" + object.GetKind() + "-" + object.GetName()))
		if object.GetKind() == "CustomResourceDefinition" {
			if err := unstructured.SetNestedSlice(object.Object, []any{
				map[string]any{"type": "Established", "status": "True"},
			}, "status", "conditions"); err != nil {
				return true, nil, err
			}
		}
		*applied = append(*applied, object.GetKind()+"/"+object.GetName())
		if err := dynamicClient.Tracker().Create(action.GetResource(), object, object.GetNamespace()); err != nil {
			return true, nil, err
		}
		return true, object, nil
	})
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{
		{Group: "", Version: "v1"},
		{Group: "apiextensions.k8s.io", Version: "v1"},
	})
	mapper.Add(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}, meta.RESTScopeRoot)
	mapper.Add(schema.GroupVersionKind{Group: "apiextensions.k8s.io", Version: "v1", Kind: "CustomResourceDefinition"}, meta.RESTScopeRoot)
	clusterHandle := &cluster.Cluster{Dynamic: dynamicClient, Mapper: mapper}
	store, err := artifacts.New(t.TempDir(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	state := &e2e.EnvironmentState{Components: make(map[string]e2e.ComponentFingerprint)}
	return &e2e.Environment{
		RunID: "run-1", Cluster: clusterHandle,
		Kube:      kube.NewClient("run-1", clusterHandle, kube.NewLedger()),
		Artifacts: store, Commands: runner, State: state,
	}, applied
}
