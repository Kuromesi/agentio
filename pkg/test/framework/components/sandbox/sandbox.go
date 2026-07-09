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

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	kubecluster "istio.io/istio/pkg/test/framework/components/cluster/kube"
	testenv "istio.io/istio/pkg/test/env"
	"istio.io/istio/pkg/test/framework/resource"
	"istio.io/istio/pkg/test/helm"
	testKube "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/scopes"
	"istio.io/istio/pkg/test/util/retry"
)

const (
	DefaultNamespace   = "agentio-system"
	DefaultReleaseName = "agentio"
	DefaultChartDir    = "manifests/charts/agentio"
)

type Config struct {
	Namespace   string
	ReleaseName string
	ChartPath   string
	WaitTimeout time.Duration
	// Values are --set style overrides applied to the chart.
	Values map[string]string
}

func DefaultConfig() Config {
	return Config{
		Namespace:       DefaultNamespace,
		ReleaseName:     DefaultReleaseName,
		ChartPath:       filepath.Join(testenv.IstioSrc, DefaultChartDir),
		WaitTimeout:     5 * time.Minute,
	}
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
	id        resource.ID
	cfg       Config
	helmInst  *helm.Helm
	ctx       resource.Context
}

func (i *instance) ID() resource.ID   { return i.id }
func (i *instance) Namespace() string  { return i.cfg.Namespace }
func (i *instance) ReleaseName() string { return i.cfg.ReleaseName }

func install(ctx resource.Context, cfg Config) (Instance, error) {
	start := time.Now()
	scopes.Framework.Infof("=== BEGIN: Install sandbox chart (namespace=%s) ===", cfg.Namespace)

	cs := ctx.Clusters().Default().(*kubecluster.Cluster)
	h := helm.New(cs.Filename())

	valuesFile, err := writeValues(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to write sandbox values: %v", err)
	}

	args := []string{"--create-namespace"}
	for k, v := range cfg.Values {
		args = append(args, "--set", fmt.Sprintf("%s=%s", k, v))
	}

	if err := h.InstallChart(
		cfg.ReleaseName,
		cfg.ChartPath,
		cfg.Namespace,
		valuesFile,
		cfg.WaitTimeout,
		args...,
	); err != nil {
		scopes.Framework.Errorf("=== FAILED: Install sandbox chart ===")
		return nil, fmt.Errorf("failed to install sandbox chart: %v", err)
	}

	fetchFn := testKube.NewPodFetch(cs, cfg.Namespace, "app=gateway-controller")
	if _, err := testKube.WaitUntilPodsAreReady(fetchFn, retry.Timeout(cfg.WaitTimeout), retry.Delay(5*time.Second)); err != nil {
		return nil, fmt.Errorf("sandbox control plane not ready: %v", err)
	}

	scopes.Framework.Infof("=== SUCCEEDED: Install sandbox chart in %v ===", time.Since(start))

	ins := &instance{
		cfg:      cfg,
		helmInst: h,
		ctx:      ctx,
	}
	ins.id = ctx.TrackResource(ins)
	return ins, nil
}

func (i *instance) Close() error {
	scopes.Framework.Infof("Cleaning up sandbox chart release %s", i.cfg.ReleaseName)
	return i.helmInst.DeleteChart(i.cfg.ReleaseName, i.cfg.Namespace)
}

func writeValues(ctx resource.Context, cfg Config) (string, error) {
	// Only the images built from THIS repo and pushed to the KinD-local registry
	// are overridden here (hub+tag from the test settings). The cni image is also
	// renamed because the build target produces "install-cni" while the chart
	// default name is different.
	//
	// External components (ztunnel, traffic-extension) are intentionally NOT
	// overridden: they keep the chart's own default image references from
	// values.yaml (global.hub is left untouched so the empty-hub ztunnel image
	// resolves to it). Bumping those components is therefore a values.yaml change
	// and never a CI/workflow change.
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
ambient:
  cni:
    image:
      hub: %s
      name: install-cni
      tag: %s
`, cfg.Namespace, hub, tag, hub, tag, hub, tag)

	dir, err := ctx.CreateTmpDirectory("sandbox-values")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %v", err)
	}
	f := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(f, []byte(values), 0o644); err != nil {
		return "", err
	}
	return f, nil
}
