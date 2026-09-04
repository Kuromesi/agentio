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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openkruise/agentio/test/e2e/command"
)

type KindSource struct {
	Runner       CommandRunner
	BuildClients ClientBuilder
}

func (s KindSource) Open(ctx context.Context, config Config) (*Cluster, error) {
	if strings.TrimSpace(config.Name) == "" {
		return nil, errors.New("Kind cluster name is required")
	}
	if s.Runner == nil || s.BuildClients == nil {
		return nil, errors.New("Kind source runner and client builder are required")
	}
	listed, err := s.Runner.Run(ctx, command.Request{Name: "kind", Args: []string{"get", "clusters"}})
	if err != nil {
		return nil, fmt.Errorf("list Kind clusters: %w", err)
	}
	exists := containsLine(listed.Stdout, config.Name)
	if config.Reuse && !exists {
		return nil, fmt.Errorf("Kind cluster %q does not exist for reuse", config.Name)
	}
	if !config.Reuse && exists {
		return nil, fmt.Errorf("Kind cluster %q already exists and reuse is disabled", config.Name)
	}

	owned := !config.Reuse
	if owned {
		args := []string{"create", "cluster", "--name", config.Name}
		if config.Kind.NodeImage != "" {
			args = append(args, "--image", config.Kind.NodeImage)
		}
		if config.Kind.Config != "" {
			args = append(args, "--config", config.Kind.Config)
		}
		if _, err := s.Runner.Run(ctx, command.Request{Name: "kind", Args: args}); err != nil {
			return nil, fmt.Errorf("create Kind cluster %q: %w", config.Name, err)
		}
	}
	rollbackOwned := owned
	defer func() {
		if rollbackOwned {
			_, _ = s.Runner.Run(context.Background(), command.Request{
				Name: "kind", Args: []string{"delete", "cluster", "--name", config.Name},
			})
		}
	}()

	output, err := s.Runner.Run(ctx, command.Request{
		Name: "kind", Args: []string{"get", "kubeconfig", "--name", config.Name},
	})
	if err != nil {
		return nil, fmt.Errorf("get kubeconfig for Kind cluster %q: %w", config.Name, err)
	}
	kubeconfig, err := writeKubeconfig(config.Kubeconfig, output.Stdout)
	if err != nil {
		return nil, err
	}
	removeKubeconfig := true
	defer func() {
		if removeKubeconfig {
			_ = os.Remove(kubeconfig)
		}
	}()

	contextName := "kind-" + config.Name
	opened, err := s.BuildClients(kubeconfig, contextName)
	if err != nil {
		return nil, fmt.Errorf("build clients for Kind cluster %q: %w", config.Name, err)
	}
	opened.Name = config.Name
	opened.Kubeconfig = kubeconfig
	opened.Context = contextName
	opened.Mode = ModeKind
	opened.Owned = owned
	opened.removeKubeconfig = true
	rollbackOwned = false
	removeKubeconfig = false
	return opened, nil
}

func (s KindSource) Close(ctx context.Context, opened *Cluster, options CloseOptions) error {
	if opened == nil {
		return nil
	}
	var errs []error
	if opened.Owned && !options.Preserve {
		if _, err := s.Runner.Run(ctx, command.Request{
			Name: "kind", Args: []string{"delete", "cluster", "--name", opened.Name},
		}); err != nil {
			errs = append(errs, fmt.Errorf("delete Kind cluster %q: %w", opened.Name, err))
		}
	}
	if opened.removeKubeconfig && opened.Kubeconfig != "" {
		if err := os.Remove(opened.Kubeconfig); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove temporary kubeconfig %q: %w", opened.Kubeconfig, err))
		}
	}
	return errors.Join(errs...)
}

func containsLine(output, want string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func writeKubeconfig(path, contents string) (string, error) {
	var file *os.File
	var err error
	if path == "" {
		file, err = os.CreateTemp("", "agentio-e2e-kubeconfig-*.yaml")
	} else {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return "", fmt.Errorf("create kubeconfig directory %q: %w", filepath.Dir(path), err)
		}
		file, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	}
	if err != nil {
		return "", fmt.Errorf("create temporary kubeconfig: %w", err)
	}
	name := file.Name()
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(name)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", fmt.Errorf("secure temporary kubeconfig %q: %w", name, err)
	}
	if _, err := file.WriteString(contents); err != nil {
		return "", fmt.Errorf("write temporary kubeconfig %q: %w", name, err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close temporary kubeconfig %q: %w", name, err)
	}
	committed = true
	return name, nil
}
