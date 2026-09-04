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

package helm

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/artifacts"
	"github.com/openkruise/agentio/test/e2e/cluster"
	"github.com/openkruise/agentio/test/e2e/command"
)

func TestInstallRejectsUnrelatedReleaseFingerprint(t *testing.T) {
	runner := &recordingRunner{results: []command.Result{{Stdout: `{"info":{"description":"managed elsewhere"}}`}}}
	env := helmEnvironment(t, runner)

	_, _, err := Install(context.Background(), env, Config{
		Name: "control-plane", Namespace: "agentio-system", Chart: "./chart", Fingerprint: "expected", Reuse: true,
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("Install() error = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %#v", runner.calls)
	}
}

func TestInstallReusesExactReleaseWithoutMutation(t *testing.T) {
	runner := &recordingRunner{results: []command.Result{{Stdout: `{"info":{"description":"agentio-e2e:fp-1"}}`}}}
	env := helmEnvironment(t, runner)

	release, cleanup, err := Install(context.Background(), env, Config{
		Name: "control-plane", Namespace: "agentio-system", Chart: "./chart", Fingerprint: "fp-1", Reuse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if release.Created || cleanup == nil {
		t.Fatalf("release = %+v, cleanup nil = %v", release, cleanup == nil)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("reuse mutated Helm release: %#v", runner.calls)
	}
}

func TestInstallRejectsMissingReleaseWhenReuseRequested(t *testing.T) {
	runner := &recordingRunner{
		results: []command.Result{{Stderr: "Error: release: not found", ExitCode: 1}},
		errors:  []error{errors.New("exit status 1")},
	}
	env := helmEnvironment(t, runner)

	_, _, err := Install(context.Background(), env, Config{
		Name: "control-plane", Namespace: "agentio-system", Chart: "./chart", Fingerprint: "fp-1", Reuse: true,
	})
	if err == nil || !strings.Contains(err.Error(), "reuse requested") {
		t.Fatalf("Install() error = %v, want missing reusable release", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("reuse request mutated Helm state: %#v", runner.calls)
	}
}

func TestInstallRendersInstallsAndUninstallsOwnedRelease(t *testing.T) {
	runner := &recordingRunner{
		results: []command.Result{
			{Stderr: "Error: release: not found", ExitCode: 1},
			{Stdout: "apiVersion: v1\nkind: ConfigMap\n"},
			{},
			{},
		},
		errors: []error{errors.New("exit status 1")},
	}
	env := helmEnvironment(t, runner)
	env.Cluster = &cluster.Cluster{Kubeconfig: "/tmp/e2e-kubeconfig", Context: "kind-target"}
	release, cleanup, err := Install(context.Background(), env, Config{
		Name: "control-plane", Namespace: "agentio-system", Chart: "./chart", Fingerprint: "fp-1",
		ValuesFiles: []string{"values.yaml"}, Timeout: 2 * time.Minute, SkipCRDs: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !release.Created {
		t.Fatalf("release = %+v", release)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantCommands := [][]string{
		{"helm", "status", "control-plane", "--namespace", "agentio-system", "--output", "json", "--kubeconfig", "/tmp/e2e-kubeconfig", "--kube-context", "kind-target"},
		{"helm", "template", "control-plane", "./chart", "--namespace", "agentio-system", "--kubeconfig", "/tmp/e2e-kubeconfig", "--kube-context", "kind-target", "--values", "values.yaml"},
		{"helm", "upgrade", "--install", "control-plane", "./chart", "--namespace", "agentio-system", "--wait", "--timeout", "2m0s", "--description", "agentio-e2e:fp-1", "--skip-crds", "--kubeconfig", "/tmp/e2e-kubeconfig", "--kube-context", "kind-target", "--values", "values.yaml"},
		{"helm", "uninstall", "control-plane", "--namespace", "agentio-system", "--wait", "--kubeconfig", "/tmp/e2e-kubeconfig", "--kube-context", "kind-target"},
	}
	if !reflect.DeepEqual(runner.calls, wantCommands) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, wantCommands)
	}
	rendered, err := os.ReadFile(env.Artifacts.Path("setup", "helm", "control-plane", "rendered.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rendered), "kind: ConfigMap") {
		t.Fatalf("rendered artifact = %q", rendered)
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

func helmEnvironment(t *testing.T, runner command.Interface) *e2e.Environment {
	t.Helper()
	store, err := artifacts.New(t.TempDir(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	return &e2e.Environment{RunID: "run-1", Artifacts: store, Commands: runner}
}
