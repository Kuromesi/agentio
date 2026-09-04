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

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/artifacts"
	"github.com/openkruise/agentio/test/e2e/cluster"
	"github.com/openkruise/agentio/test/e2e/command"
	"github.com/openkruise/agentio/test/e2e/kube"
	"gopkg.in/yaml.v3"
)

type SuiteSpec struct {
	Name          string
	RequiredTools []string
}

type CleanupFunc func(context.Context) error

type SetupFunc func(context.Context, *Environment) (CleanupFunc, error)

type Collector interface {
	Name() string
	Collect(context.Context, *Environment, artifacts.Writer) error
}

type namedSetup struct {
	name string
	fn   SetupFunc
}

type Suite struct {
	spec   SuiteSpec
	config Config

	setups     []namedSetup
	collectors []Collector
	source     cluster.Source

	lookupTool       func(string) (string, error)
	cleanupResources func(context.Context, *Environment) error

	mu          sync.RWMutex
	environment *Environment
	running     atomic.Bool
	fullDumps   atomic.Int64
}

func NewSuite(spec SuiteSpec, config Config) *Suite {
	return &Suite{
		spec:       spec,
		config:     config,
		lookupTool: exec.LookPath,
		cleanupResources: func(ctx context.Context, env *Environment) error {
			return env.Kube.Ledger().DeleteReverse(ctx, env.Kube)
		},
	}
}

func (s *Suite) Setup(name string, setup SetupFunc) {
	if s.running.Load() {
		panic("e2e Suite.Setup called after Suite.Run started")
	}
	if name == "" || setup == nil {
		panic("e2e Suite.Setup requires a name and function")
	}
	s.setups = append(s.setups, namedSetup{name: name, fn: setup})
}

func (s *Suite) RegisterCollector(collector Collector) {
	if s.running.Load() {
		panic("e2e Suite.RegisterCollector called after Suite.Run started")
	}
	if collector == nil || collector.Name() == "" {
		panic("e2e collector requires a name")
	}
	s.collectors = append(s.collectors, collector)
}

func (s *Suite) Environment(t testing.TB) *Environment {
	t.Helper()
	s.mu.RLock()
	environment := s.environment
	s.mu.RUnlock()
	if environment == nil {
		t.Fatalf("e2e environment is available only while Suite tests are running")
		return nil
	}
	copy := &Environment{
		RunID:     environment.RunID,
		Cluster:   environment.Cluster,
		Kube:      environment.Kube.WithTestID(t.Name()),
		Artifacts: environment.Artifacts,
		Commands:  environment.Commands,
		State:     environment.State,
		retain:    environment.retain,
	}
	copy.setRetaining(environment.Retaining())
	return copy
}

func (s *Suite) Run(m *testing.M) int {
	return s.run(context.Background(), m.Run)
}

func (s *Suite) run(ctx context.Context, runTests func() int) int {
	if !s.running.CompareAndSwap(false, true) {
		fmt.Fprintln(os.Stderr, "e2e suite may run only once")
		return 1
	}
	if err := s.config.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid e2e configuration: %v\n", err)
		return 1
	}
	if err := s.verifyTools(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	runID, err := newRunID()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	store, err := artifacts.New(s.config.Artifacts.Dir, runID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeResolvedConfig(store, s.config.Redacted()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	commands := &command.Runner{
		Artifacts: store,
		Redactor:  command.NewRedactor([]string{s.config.Cluster.Kubeconfig}),
	}
	if s.source == nil {
		factory := cluster.Factory{Runner: commands}
		s.source, err = factory.Source(toClusterConfig(s.config.Cluster))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	opened, err := s.source.Open(ctx, toClusterConfig(s.config.Cluster))
	if err != nil {
		fmt.Fprintf(os.Stderr, "open e2e cluster: %v\n", err)
		return 1
	}
	ledger := kube.NewLedger()
	state := newEnvironmentState(runID, s.config)
	state.setCluster(opened.Name, opened.Context, opened.Owned)
	environment := &Environment{
		RunID: runID, Cluster: opened, Kube: kube.NewClient(runID, opened, ledger),
		Artifacts: store, Commands: commands, State: state, retain: s.config.Lifecycle.Retain,
	}

	completed := make([]CleanupFunc, 0, len(s.setups))
	code := 0
	var primaryErr error
	for _, setup := range s.setups {
		cleanup, setupErr := setup.fn(ctx, environment)
		if setupErr != nil {
			primaryErr = fmt.Errorf("setup %q: %w", setup.name, setupErr)
			code = 1
			break
		}
		if cleanup != nil {
			completed = append(completed, cleanup)
		}
	}
	if primaryErr == nil {
		s.mu.Lock()
		s.environment = environment
		s.mu.Unlock()
		code = runTests()
		s.mu.Lock()
		s.environment = nil
		s.mu.Unlock()
		if code != 0 {
			primaryErr = fmt.Errorf("tests exited with code %d", code)
		}
	}
	if primaryErr != nil {
		if diagnosticErr := s.collectFailure(ctx, environment, "suite", primaryErr); diagnosticErr != nil {
			fmt.Fprintf(os.Stderr, "collect e2e diagnostics: %v\n", diagnosticErr)
		}
	}

	environment.setRetaining(shouldPreserve(s.config.Lifecycle.Retain, code != 0))
	var cleanupErrs []error
	for i := len(completed) - 1; i >= 0; i-- {
		if err := completed[i](ctx); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
	}
	if cleanupErr := errors.Join(cleanupErrs...); cleanupErr != nil {
		fmt.Fprintf(os.Stderr, "e2e setup cleanup: %v\n", cleanupErr)
		code = 1
		if s.config.Lifecycle.Retain == RetainOnFailure {
			environment.setRetaining(true)
		}
		if diagnosticErr := s.collectFailure(ctx, environment, "cleanup", cleanupErr); diagnosticErr != nil {
			fmt.Fprintf(os.Stderr, "collect cleanup diagnostics: %v\n", diagnosticErr)
		}
	}
	if !environment.Retaining() {
		if err := s.cleanupResources(ctx, environment); err != nil {
			fmt.Fprintf(os.Stderr, "clean e2e resources: %v\n", err)
			code = 1
			if s.config.Lifecycle.Retain == RetainOnFailure {
				environment.setRetaining(true)
			}
		}
	}
	if err := s.source.Close(ctx, opened, cluster.CloseOptions{Preserve: environment.Retaining()}); err != nil {
		fmt.Fprintf(os.Stderr, "close e2e cluster: %v\n", err)
		code = 1
	}
	status := "passed"
	if code != 0 {
		status = "failed"
	}
	state.finish(ledger.Snapshot(), status, code)
	if err := store.WriteJSON("environment.json", state.Snapshot()); err != nil {
		fmt.Fprintf(os.Stderr, "write environment state: %v\n", err)
		code = 1
	}
	if environment.Retaining() {
		printReconnect(environment)
	}
	return code
}

func (s *Suite) verifyTools() error {
	tools := append([]string(nil), s.spec.RequiredTools...)
	if s.config.Cluster.Mode == ClusterModeKind {
		tools = append(tools, "kind", "docker")
	}
	seen := make(map[string]bool)
	for _, tool := range tools {
		if seen[tool] {
			continue
		}
		seen[tool] = true
		if _, err := s.lookupTool(tool); err != nil {
			return fmt.Errorf("required e2e tool %q is unavailable: %w", tool, err)
		}
	}
	return nil
}

func shouldPreserve(policy RetainPolicy, failed bool) bool {
	return policy == RetainAlways || policy == RetainOnFailure && failed
}

func toClusterConfig(config ClusterConfig) cluster.Config {
	return cluster.Config{
		Mode:       cluster.Mode(config.Mode),
		Name:       config.Name,
		Kubeconfig: config.Kubeconfig,
		Context:    config.Context,
		Reuse:      config.Reuse,
		Kind: cluster.KindConfig{
			NodeImage: config.Kind.NodeImage,
			Config:    config.Kind.Config,
		},
	}
}

func newRunID() (string, error) {
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate e2e run ID: %w", err)
	}
	return fmt.Sprintf("%s-%s", time.Now().UTC().Format("20060102-150405"), hex.EncodeToString(random)), nil
}

func writeResolvedConfig(store *artifacts.Store, config Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal resolved e2e config: %w", err)
	}
	writer, err := store.Writer("config.yaml")
	if err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		return err
	}
	return writer.Close()
}

func printReconnect(environment *Environment) {
	for _, instruction := range reconnectInstructions(environment) {
		fmt.Fprintln(os.Stderr, instruction)
	}
}

func reconnectInstructions(environment *Environment) []string {
	if environment == nil || environment.Cluster == nil {
		return nil
	}
	opened := environment.Cluster
	instructions := make([]string, 0, 3)
	if opened.Mode == cluster.ModeKind {
		instructions = append(instructions,
			fmt.Sprintf("retained Kind cluster: kind export kubeconfig --name %q", opened.Name),
			fmt.Sprintf("inspect retained environment: kubectl --context %q get pods -A", opened.Context),
		)
	} else {
		instructions = append(instructions,
			fmt.Sprintf("retained e2e environment: KUBECONFIG=%q kubectl --context %q get pods -A", opened.Kubeconfig, opened.Context),
		)
	}
	if opened.Owned {
		instructions = append(instructions, fmt.Sprintf("delete retained Kind cluster: kind delete cluster --name %q", opened.Name))
	}
	return instructions
}
