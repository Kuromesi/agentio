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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/command"
)

type Config struct {
	Name        string
	Namespace   string
	Chart       string
	ValuesFiles []string
	Fingerprint string
	Reuse       bool
	SkipCRDs    bool
	Timeout     time.Duration
}

type Release struct {
	Name        string
	Namespace   string
	Fingerprint string
	Created     bool
}

func Install(ctx context.Context, environment *e2e.Environment, config Config) (Release, e2e.CleanupFunc, error) {
	if environment == nil || environment.Commands == nil || environment.Artifacts == nil {
		return Release{}, nil, errors.New("Helm install requires commands and artifacts")
	}
	if config.Name == "" || config.Namespace == "" || config.Chart == "" || config.Fingerprint == "" {
		return Release{}, nil, errors.New("Helm name, namespace, chart, and fingerprint are required")
	}
	artifact := fmt.Sprintf("setup/helm/%s", config.Name)
	statusArgs := []string{"status", config.Name, "--namespace", config.Namespace, "--output", "json"}
	statusArgs = append(statusArgs, clusterArgs(environment)...)
	status, statusErr := environment.Commands.Run(ctx, command.Request{Name: "helm", Args: statusArgs, Artifact: artifact})
	if statusErr == nil {
		description, err := releaseDescription(status.Stdout)
		if err != nil {
			return Release{}, nil, fmt.Errorf("parse Helm release %s/%s status: %w", config.Namespace, config.Name, err)
		}
		want := "agentio-e2e:" + config.Fingerprint
		if !config.Reuse {
			return Release{}, nil, fmt.Errorf("Helm release %s/%s already exists and reuse is disabled", config.Namespace, config.Name)
		}
		if description != want {
			return Release{}, nil, fmt.Errorf("Helm release %s/%s fingerprint mismatch: description %q, want %q", config.Namespace, config.Name, description, want)
		}
		release := Release{Name: config.Name, Namespace: config.Namespace, Fingerprint: config.Fingerprint}
		return release, func(context.Context) error { return nil }, nil
	}
	if !releaseNotFound(status, statusErr) {
		return Release{}, nil, fmt.Errorf("inspect Helm release %s/%s: %w", config.Namespace, config.Name, statusErr)
	}
	if config.Reuse {
		return Release{}, nil, fmt.Errorf("Helm release %s/%s reuse requested but the release does not exist", config.Namespace, config.Name)
	}

	templateArgs := []string{"template", config.Name, config.Chart, "--namespace", config.Namespace}
	templateArgs = append(templateArgs, clusterArgs(environment)...)
	for _, values := range config.ValuesFiles {
		templateArgs = append(templateArgs, "--values", values)
	}
	rendered, err := environment.Commands.Run(ctx, command.Request{Name: "helm", Args: templateArgs, Artifact: artifact})
	if err != nil {
		return Release{}, nil, fmt.Errorf("render Helm release %s/%s: %w", config.Namespace, config.Name, err)
	}
	writer, err := environment.Artifacts.Writer("setup", "helm", config.Name, "rendered.yaml")
	if err != nil {
		return Release{}, nil, err
	}
	_, writeErr := writer.Write([]byte(rendered.Stdout))
	if err := errors.Join(writeErr, writer.Close()); err != nil {
		return Release{}, nil, fmt.Errorf("write rendered Helm release %s/%s: %w", config.Namespace, config.Name, err)
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	installArgs := []string{
		"upgrade", "--install", config.Name, config.Chart,
		"--namespace", config.Namespace,
		"--wait", "--timeout", timeout.String(),
		"--description", "agentio-e2e:" + config.Fingerprint,
	}
	if config.SkipCRDs {
		installArgs = append(installArgs, "--skip-crds")
	}
	installArgs = append(installArgs, clusterArgs(environment)...)
	for _, values := range config.ValuesFiles {
		installArgs = append(installArgs, "--values", values)
	}
	if _, err := environment.Commands.Run(ctx, command.Request{Name: "helm", Args: installArgs, Artifact: artifact}); err != nil {
		return Release{}, nil, fmt.Errorf("install Helm release %s/%s: %w", config.Namespace, config.Name, err)
	}
	if environment.State != nil {
		environment.State.RecordComponent("helm/"+config.Namespace+"/"+config.Name, config.Fingerprint, nil)
	}
	release := Release{Name: config.Name, Namespace: config.Namespace, Fingerprint: config.Fingerprint, Created: true}
	cleanup := func(cleanupCtx context.Context) error {
		if environment.Retaining() {
			return nil
		}
		uninstallArgs := []string{"uninstall", config.Name, "--namespace", config.Namespace, "--wait"}
		uninstallArgs = append(uninstallArgs, clusterArgs(environment)...)
		_, err := environment.Commands.Run(cleanupCtx, command.Request{Name: "helm", Args: uninstallArgs, Artifact: artifact})
		if err != nil {
			return fmt.Errorf("uninstall Helm release %s/%s: %w", config.Namespace, config.Name, err)
		}
		return nil
	}
	return release, cleanup, nil
}

func clusterArgs(environment *e2e.Environment) []string {
	if environment == nil || environment.Cluster == nil {
		return nil
	}
	var args []string
	if environment.Cluster.Kubeconfig != "" {
		args = append(args, "--kubeconfig", environment.Cluster.Kubeconfig)
	}
	if environment.Cluster.Context != "" {
		args = append(args, "--kube-context", environment.Cluster.Context)
	}
	return args
}

func releaseDescription(output string) (string, error) {
	var status struct {
		Info struct {
			Description string `json:"description"`
		} `json:"info"`
	}
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		return "", err
	}
	return status.Info.Description, nil
}

func releaseNotFound(result command.Result, err error) bool {
	combined := strings.ToLower(result.Stdout + "\n" + result.Stderr + "\n" + err.Error())
	return strings.Contains(combined, "release: not found") || strings.Contains(combined, "release not found")
}
