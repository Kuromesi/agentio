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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	testenv "istio.io/istio/pkg/test/env"
	kubecluster "istio.io/istio/pkg/test/framework/components/cluster/kube"
	"istio.io/istio/pkg/test/framework/resource"
	"istio.io/istio/pkg/test/helm"
	testKube "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/scopes"
	"istio.io/istio/pkg/test/util/retry"
)

const (
	DefaultNamespace        = "agentio-system"
	DefaultReleaseName      = "agentio"
	DefaultChartDir         = "manifests/charts/agentio"
	controlPlanePodSelector = "app=agentiod"
)

type Config struct {
	Namespace   string
	ReleaseName string
	ChartPath   string
	WaitTimeout time.Duration
	// ValuesFiles are Helm values overlays applied in order after the generated
	// test values and before Values.
	ValuesFiles []string
	// Values are --set style overrides applied to the chart.
	Values map[string]string
}

func (c Config) helmArgs() ([]string, error) {
	args := []string{"--create-namespace"}
	for _, valuesFile := range c.ValuesFiles {
		if err := validateValuesFile(valuesFile); err != nil {
			return nil, err
		}
		args = append(args, "--values", valuesFile)
	}

	keys := make([]string, 0, len(c.Values))
	for key := range c.Values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := c.Values[key]
		if !isSafeHelmSetKey(key) || !isSafeHelmSetValue(value) {
			return nil, fmt.Errorf("unsafe Helm --set value %q=%q", key, value)
		}
		args = append(args, "--set", fmt.Sprintf("%s=%s", key, value))
	}
	return args, nil
}

func isSafeHelmSetKey(value string) bool {
	return value != "" && strings.IndexFunc(value, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("._-[]", r))
	}) < 0
}

func isSafeHelmSetValue(value string) bool {
	return value != "" && strings.IndexFunc(value, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("._/-:", r))
	}) < 0
}

func validateValuesFile(path string) error {
	if path == "" || strings.IndexFunc(path, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("/._-", r))
	}) >= 0 {
		return fmt.Errorf("unsafe Helm values file path %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("invalid Helm values file %q: %v", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("Helm values file %q is not a regular file", path)
	}
	return nil
}

func DefaultConfig() Config {
	cfg := Config{
		Namespace:   DefaultNamespace,
		ReleaseName: DefaultReleaseName,
		ChartPath:   filepath.Join(testenv.IstioSrc, DefaultChartDir),
		WaitTimeout: 5 * time.Minute,
	}
	if valuesFileFromCommandLine != "" {
		cfg.ValuesFiles = []string{valuesFileFromCommandLine}
	}
	return cfg
}

type Instance interface {
	resource.Resource
	Namespace() string
	ReleaseName() string
}

type SetupConfigFn func(ctx resource.Context, cfg *Config)

func Setup(i *Instance, cfn SetupConfigFn) resource.SetupFn {
	return func(ctx resource.Context) error {
		cfg := DefaultConfig()
		if cfn != nil {
			cfn(ctx, &cfg)
		}
		ins, err := install(ctx, cfg)
		if err != nil {
			return err
		}
		if i != nil {
			*i = ins
		}
		return nil
	}
}

type instance struct {
	id       resource.ID
	cfg      Config
	helmInst *helm.Helm
	ctx      resource.Context
}

func (i *instance) ID() resource.ID     { return i.id }
func (i *instance) Namespace() string   { return i.cfg.Namespace }
func (i *instance) ReleaseName() string { return i.cfg.ReleaseName }

func install(ctx resource.Context, cfg Config) (Instance, error) {
	start := time.Now()
	scopes.Framework.Infof("=== BEGIN: Install Agentio chart (namespace=%s) ===", cfg.Namespace)

	cs := ctx.Clusters().Default().(*kubecluster.Cluster)
	h := helm.New(cs.Filename())

	valuesFile, err := writeValues(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to write Agentio values: %v", err)
	}

	args, err := cfg.helmArgs()
	if err != nil {
		return nil, fmt.Errorf("invalid Agentio Helm arguments: %v", err)
	}

	if err := h.InstallChart(
		cfg.ReleaseName,
		cfg.ChartPath,
		cfg.Namespace,
		valuesFile,
		cfg.WaitTimeout,
		args...,
	); err != nil {
		scopes.Framework.Errorf("=== FAILED: Install Agentio chart ===")
		return nil, fmt.Errorf("failed to install Agentio chart: %v", err)
	}

	fetchFn := testKube.NewPodFetch(cs, cfg.Namespace, controlPlanePodSelector)
	if _, err := testKube.WaitUntilPodsAreReady(fetchFn, retry.Timeout(cfg.WaitTimeout), retry.Delay(5*time.Second)); err != nil {
		return nil, fmt.Errorf("Agentio control plane not ready: %v", err)
	}

	scopes.Framework.Infof("=== SUCCEEDED: Install Agentio chart in %v ===", time.Since(start))

	ins := &instance{
		cfg:      cfg,
		helmInst: h,
		ctx:      ctx,
	}
	ins.id = ctx.TrackResource(ins)
	return ins, nil
}

func (i *instance) Close() error {
	scopes.Framework.Infof("Cleaning up Agentio chart release %s", i.cfg.ReleaseName)
	return i.helmInst.DeleteChart(i.cfg.ReleaseName, i.cfg.Namespace)
}

func writeValues(ctx resource.Context, cfg Config) (string, error) {
	// Only the images built from THIS repo and pushed to the KinD-local registry
	// are overridden here (hub+tag from the test settings). The cni image is also
	// renamed because the build target produces "install-cni" while the chart
	// default name is different.
	//
	// External values overlays are applied later, so they take precedence over
	// these local image defaults. Scenario-specific --set values are applied last.
	hub := ctx.Settings().Image.Hub
	tag := ctx.Settings().Image.Tag

	values := fmt.Sprintf(`enabled: true
namespace: %s
global:
  trustDomain: cluster.local
  clusterId: Kubernetes
agentiod:
  image:
    hub: %s
    name: pilot
    tag: %s
proxy:
  image:
    hub: %s
    name: proxyv2
    tag: %s
egressGateway:
  image:
    hub: %s
    name: proxyv2
    tag: %s
ztunnel:
  image:
    hub: %s
    name: ztunnel
    tag: %s
ambient:
  cni:
    image:
      hub: %s
      name: install-cni
      tag: %s
`, cfg.Namespace, hub, tag, hub, tag, hub, tag, hub, tag, hub, tag)

	dir, err := ctx.CreateTmpDirectory("agentio-values")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %v", err)
	}
	f := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(f, []byte(values), 0o644); err != nil {
		return "", err
	}
	return f, nil
}
