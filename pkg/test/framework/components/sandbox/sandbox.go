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
	DefaultNamespace   = "sandbox-traffic-system"
	DefaultReleaseName = "sandbox"
	DefaultChartDir    = "manifests/charts/sandbox"
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
	hub := ctx.Settings().Image.Hub
	tag := ctx.Settings().Image.Tag

	values := fmt.Sprintf(`enhancedTrafficManagement:
  enabled: true
  namespace: %s
  global:
    hub: %s
    trustDomain: cluster.local
    clusterId: Kubernetes
    ztunnelImage:
      hub: %s
      name: sandbox-tunnel
      tag: %s
  gatewayController:
    image:
      hub: %s
      name: pilot
      tag: %s
`, cfg.Namespace, hub, hub, tag, hub, tag)

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
