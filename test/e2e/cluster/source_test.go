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

package cluster

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/openkruise/agentio/test/e2e/command"
)

func TestKindSourceCreatesAndDeletesOwnedCluster(t *testing.T) {
	runner := &recordingRunner{results: []command.Result{
		{Stdout: ""},
		{},
		{Stdout: validKubeconfig("kind-new")},
		{},
	}}
	built := false
	source := KindSource{Runner: runner, BuildClients: func(kubeconfig, contextName string) (*Cluster, error) {
		built = true
		data, err := os.ReadFile(kubeconfig)
		if err != nil {
			return nil, err
		}
		if !strings.Contains(string(data), "kind-new") || contextName != "kind-new" {
			return nil, errors.New("wrong kubeconfig or context")
		}
		return &Cluster{}, nil
	}}

	opened, err := source.Open(context.Background(), Config{Mode: ModeKind, Name: "new"})
	if err != nil {
		t.Fatal(err)
	}
	if !built || !opened.Owned || opened.Name != "new" {
		t.Fatalf("cluster = %+v, built = %v", opened, built)
	}
	kubeconfig := opened.Kubeconfig
	if err := source.Close(context.Background(), opened, CloseOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(kubeconfig); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary kubeconfig still exists: %v", err)
	}
	want := [][]string{
		{"kind", "get", "clusters"},
		{"kind", "create", "cluster", "--name", "new"},
		{"kind", "get", "kubeconfig", "--name", "new"},
		{"kind", "delete", "cluster", "--name", "new"},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
}

func TestKindSourcePreservesOwnedClusterWhenRequested(t *testing.T) {
	runner := &recordingRunner{results: []command.Result{{}, {}, {Stdout: validKubeconfig("kind-new")}}}
	source := KindSource{Runner: runner, BuildClients: emptyBuilder}
	opened, err := source.Open(context.Background(), Config{Mode: ModeKind, Name: "new"})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(context.Background(), opened, CloseOptions{Preserve: true}); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if len(call) > 1 && call[1] == "delete" {
			t.Fatalf("preserved cluster was deleted: %#v", runner.calls)
		}
	}
}

func TestKindSourceReusesNamedClusterAsBorrowed(t *testing.T) {
	runner := &recordingRunner{results: []command.Result{
		{Stdout: "other\ndev\n"},
		{Stdout: validKubeconfig("kind-dev")},
	}}
	source := KindSource{Runner: runner, BuildClients: emptyBuilder}
	opened, err := source.Open(context.Background(), Config{Mode: ModeKind, Name: "dev", Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	if opened.Owned {
		t.Fatal("reused Kind cluster is marked owned")
	}
	if err := source.Close(context.Background(), opened, CloseOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls = %#v; borrowed cluster should not be deleted", runner.calls)
	}
}

func TestKindSourceRejectsCollisionWithoutDeletingIt(t *testing.T) {
	runner := &recordingRunner{results: []command.Result{{Stdout: "dev\n"}}}
	source := KindSource{Runner: runner, BuildClients: emptyBuilder}
	_, err := source.Open(context.Background(), Config{Mode: ModeKind, Name: "dev"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %#v", runner.calls)
	}
}

func TestKindSourceRequiresExistingClusterForReuse(t *testing.T) {
	runner := &recordingRunner{results: []command.Result{{Stdout: "other\n"}}}
	source := KindSource{Runner: runner, BuildClients: emptyBuilder}
	_, err := source.Open(context.Background(), Config{Mode: ModeKind, Name: "dev", Reuse: true})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("error = %v", err)
	}
}

func TestKindSourceClientBuildFailureRollsBackOwnedCluster(t *testing.T) {
	runner := &recordingRunner{results: []command.Result{
		{}, {}, {Stdout: validKubeconfig("kind-new")}, {},
	}}
	var kubeconfig string
	source := KindSource{Runner: runner, BuildClients: func(path, _ string) (*Cluster, error) {
		kubeconfig = path
		return nil, errors.New("client build failed")
	}}
	_, err := source.Open(context.Background(), Config{Mode: ModeKind, Name: "new"})
	if err == nil || !strings.Contains(err.Error(), "client build failed") {
		t.Fatalf("error = %v", err)
	}
	if len(runner.calls) != 4 || !reflect.DeepEqual(runner.calls[3], []string{"kind", "delete", "cluster", "--name", "new"}) {
		t.Fatalf("rollback calls = %#v", runner.calls)
	}
	if _, err := os.Stat(kubeconfig); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary kubeconfig still exists: %v", err)
	}
}

func TestExistingSourceIsAlwaysBorrowed(t *testing.T) {
	built := false
	source := ExistingSource{BuildClients: func(kubeconfig, contextName string) (*Cluster, error) {
		built = true
		if kubeconfig != "/tmp/config" || contextName != "dev" {
			t.Fatalf("build args = %q, %q", kubeconfig, contextName)
		}
		return &Cluster{}, nil
	}}
	opened, err := source.Open(context.Background(), Config{
		Mode: ModeExisting, Kubeconfig: "/tmp/config", Context: "dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !built || opened.Owned || opened.Context != "dev" {
		t.Fatalf("cluster = %+v, built = %v", opened, built)
	}
	if err := source.Close(context.Background(), opened, CloseOptions{}); err != nil {
		t.Fatal(err)
	}
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

func emptyBuilder(_, _ string) (*Cluster, error) { return &Cluster{}, nil }

func validKubeconfig(contextName string) string {
	return `apiVersion: v1
kind: Config
clusters: []
contexts: []
current-context: ` + contextName + "\n"
}
