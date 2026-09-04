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
	"fmt"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	helmcomponent "github.com/openkruise/agentio/test/e2e/components/helm"
)

const installTimeout = 5 * time.Minute

type Instance struct {
	namespace   string
	releaseName string
	fingerprint string
}

func (i Instance) Namespace() string   { return i.namespace }
func (i Instance) ReleaseName() string { return i.releaseName }
func (i Instance) Fingerprint() string { return i.fingerprint }

func Setup(target *Instance, config Config) e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		instance, cleanup, err := Install(ctx, environment, config)
		if err == nil && target != nil {
			*target = instance
		}
		return cleanup, err
	}
}

func Install(ctx context.Context, environment *e2e.Environment, config Config) (Instance, e2e.CleanupFunc, error) {
	if environment == nil || environment.Kube == nil || environment.Commands == nil || environment.Artifacts == nil {
		return Instance{}, nil, errors.New("Agentio install requires Kubernetes, command, and artifact services")
	}
	resolved, err := installConfig(config)
	if err != nil {
		return Instance{}, nil, err
	}
	values, err := chartValues(resolved)
	if err != nil {
		return Instance{}, nil, err
	}
	fingerprint, err := installationFingerprint(resolved.ChartPath, values)
	if err != nil {
		return Instance{}, nil, err
	}
	valuesFile, err := writeValues(environment, values)
	if err != nil {
		return Instance{}, nil, err
	}
	if !resolved.Reuse {
		if err := applyPrerequisites(ctx, environment, resolved); err != nil {
			return Instance{}, nil, err
		}
	}

	_, cleanup, err := helmcomponent.Install(ctx, environment, helmcomponent.Config{
		Name: resolved.ReleaseName, Namespace: resolved.Namespace,
		Chart: resolved.ChartPath, ValuesFiles: []string{valuesFile},
		Fingerprint: fingerprint, Reuse: resolved.Reuse, SkipCRDs: true,
		Timeout: installTimeout,
	})
	if err != nil {
		return Instance{}, nil, fmt.Errorf("install Agentio Helm chart: %w", err)
	}
	instance := Instance{namespace: resolved.Namespace, releaseName: resolved.ReleaseName, fingerprint: fingerprint}
	recordComponent(environment, resolved, fingerprint)
	return instance, cleanup, nil
}

func installConfig(config Config) (Config, error) {
	if config.ReleaseName == "" {
		config.ReleaseName = "agentio"
	}
	if config.ChartPath == "" {
		chartPath, err := findProductionChart()
		if err != nil {
			return Config{}, err
		}
		config.ChartPath = chartPath
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func writeValues(environment *e2e.Environment, values []byte) (string, error) {
	writer, err := environment.Artifacts.Writer("setup", "agentio", "values.yaml")
	if err != nil {
		return "", err
	}
	_, writeErr := writer.Write(values)
	if err := errors.Join(writeErr, writer.Close()); err != nil {
		return "", fmt.Errorf("write Agentio Helm values: %w", err)
	}
	return environment.Artifacts.Path("setup", "agentio", "values.yaml"), nil
}

func recordComponent(environment *e2e.Environment, config Config, fingerprint string) {
	if environment.State == nil {
		return
	}
	environment.State.RecordComponent("agentio", fingerprint, map[string]string{
		"agentiod": config.AgentiodImage, "cni": config.CNIImage, "ztunnel": config.ZtunnelImage,
		"proxy-init": config.ProxyInitImage, "gateway": config.GatewayImage,
		"epe": config.EPEImage,
	})
}
