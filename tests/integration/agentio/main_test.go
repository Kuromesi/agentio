//go:build integ

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
	"testing"
	"time"

	"istio.io/api/label"
	sandboxpkg "istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/common/ports"
	"istio.io/istio/pkg/test/framework/components/echo/deployment"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/components/namespace"
	sandboxcomp "istio.io/istio/pkg/test/framework/components/sandbox"
	"istio.io/istio/pkg/test/framework/resource"
	testKube "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/util/retry"
)

const agentioConfigMapName = "agentio-config-primary"

var (
	i   istio.Instance
	sb  sandboxcomp.Instance
	ns  namespace.Instance
	all echo.Instances
)

var (
	deployAsSandbox  = env.Register("DEPLOY_AS_SANDBOX", false, "Whether to deploy echo instances as sandbox workloads").Get()
	ambientMode      = env.Register("AMBIENT_MODE", false, "Whether to use ambient mode (node-level ztunnel) instead of sidecar ztunnel").Get()
	firewallBackend  = env.Register("FIREWALL_BACKEND", "auto", "Ztunnel firewall backend: auto or iptables").Get()
	enableFirewall   = env.Register("ENABLE_FIREWALL", false, "Whether to enable firewall rules; when false, UDP/ICMP traffic policy tests are skipped").Get()
	proxyImageHub    = env.Register("AGENTIO_PROXY_IMAGE_HUB", "", "External proxy image registry and namespace").Get()
	proxyImageName   = env.Register("AGENTIO_PROXY_IMAGE_NAME", "", "External proxy image name").Get()
	proxyImageTag    = env.Register("AGENTIO_PROXY_IMAGE_TAG", "", "External proxy image tag").Get()
	ztunnelImageHub  = env.Register("AGENTIO_ZTUNNEL_IMAGE_HUB", "", "External ztunnel image registry and namespace").Get()
	ztunnelImageName = env.Register("AGENTIO_ZTUNNEL_IMAGE_NAME", "", "External ztunnel image name").Get()
	ztunnelImageTag  = env.Register("AGENTIO_ZTUNNEL_IMAGE_TAG", "", "External ztunnel image tag").Get()
)

func TestMain(m *testing.M) {
	nsPrefix := "sandbox"
	if ambientMode {
		nsPrefix += "-ambient"
	}
	nsCfg := namespace.Config{Prefix: nsPrefix, Inject: !ambientMode}
	if ambientMode {
		nsCfg.Inject = false
		nsCfg.Labels = map[string]string{
			label.IoIstioDataplaneMode.Name: "ambient",
		}
	}
	suite := framework.
		NewSuite(m)
	if ambientMode || deployAsSandbox {
		suite = suite.Setup(func(ctx resource.Context) error {
			ctx.Settings().Ambient = true
			return nil
		})
	}
	suite.
		Setup(istio.Setup(&i, func(_ resource.Context, cfg *istio.Config) {
			cfg.DeployIstio = false
			cfg.SystemNamespace = sandboxcomp.DefaultNamespace
		})).
		Setup(sandboxcomp.Setup(&sb, func(_ resource.Context, cfg *sandboxcomp.Config) {
			cfg.Values = map[string]string{
				"ambient.ztunnel.env.FIREWALL_BACKEND": firewallBackend,
				"global.enableFirewallRules":           fmt.Sprintf("%t", enableFirewall),
				"agentiod.resources.requests.cpu":      "1",
				"agentiod.resources.requests.memory":   "1Gi",
				"agentiod.resources.limits.cpu":        "1",
				"agentiod.resources.limits.memory":     "1Gi",
			}
			if proxyImageHub != "" || proxyImageName != "" || proxyImageTag != "" {
				cfg.ProxyImage = &sandboxcomp.ImageConfig{Hub: proxyImageHub, Name: proxyImageName, Tag: proxyImageTag}
			}
			if ztunnelImageHub != "" || ztunnelImageName != "" || ztunnelImageTag != "" {
				cfg.ZtunnelImage = &sandboxcomp.ImageConfig{Hub: ztunnelImageHub, Name: ztunnelImageName, Tag: ztunnelImageTag}
			}
		})).
		Setup(namespace.Setup(&ns, nsCfg)).
		Setup(deployEchoes).
		Setup(deployExtProc).
		Run()
}

func sandboxPorts() echo.Ports {
	return append(ports.All(), echo.Port{
		Name: "udp", Protocol: protocol.UDP, ServicePort: 9200, WorkloadPort: 19200,
	})
}

func deployEchoes(ctx resource.Context) error {
	var err error
	annotations := map[string]string{}
	labels := map[string]string{}
	if !ambientMode {
		labels[sandboxpkg.LabelSandboxProxyType] = "ztunnel"
		if !deployAsSandbox {
			annotations["inject.istio.io/templates"] = "ztunnel"
		}
	}

	all, err = deployment.New(ctx).
		WithConfig(echo.Config{
			Service:        "client",
			Namespace:      ns,
			Ports:          sandboxPorts(),
			ServiceAccount: true,
			Subsets: []echo.SubsetConfig{{
				Annotations: annotations,
				Labels:      labels,
			}},
			DeployAsSandbox: deployAsSandbox,
			Capabilities:    []string{"NET_ADMIN", "NET_RAW"},
		}).
		WithConfig(echo.Config{
			Service:        "server",
			Namespace:      ns,
			Ports:          sandboxPorts(),
			ServiceAccount: true,
			Subsets: []echo.SubsetConfig{{
				Annotations: annotations,
				Labels:      labels,
			}},
			DeployAsSandbox: deployAsSandbox,
		}).
		WithConfig(echo.Config{
			Service:        "another-server",
			Namespace:      ns,
			Ports:          sandboxPorts(),
			ServiceAccount: true,
			Subsets: []echo.SubsetConfig{{
				Annotations: annotations,
				Labels:      labels,
			}},
			DeployAsSandbox: deployAsSandbox,
		}).
		WithConfig(echo.Config{
			Service:   "workload-target",
			Namespace: ns,
			Ports:     sandboxPorts(),
			Subsets: []echo.SubsetConfig{{
				Annotations: annotations,
				Labels:      labels,
				Replicas:    2,
			}},
			DeployAsSandbox: deployAsSandbox,
		}).
		Build()
	return err
}

func applyTrafficPolicyCRDs(ctx resource.Context) error {
	return ctx.ConfigIstio().File("", "testdata/trafficpolicy-crds.yaml").Apply()
}

func deployExtProc(ctx resource.Context) error {
	image := ctx.Settings().Image
	if err := ctx.ConfigIstio().EvalFile(i.Settings().SystemNamespace, map[string]string{
		"ImageHub": image.Hub,
		"ImageTag": image.Tag,
	}, "testdata/ext-proc.yaml").Apply(); err != nil {
		return err
	}

	fetchFn := testKube.NewPodFetch(ctx.Clusters().Default(), i.Settings().SystemNamespace, "app=ext-proc")
	_, err := testKube.WaitUntilPodsAreReady(fetchFn, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
	if err != nil {
		return fmt.Errorf("ext-proc deployment not ready: %v", err)
	}
	return nil
}
