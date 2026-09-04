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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestChartValuesPinSuiteImagesAndBehavior(t *testing.T) {
	config := validConfig(t)
	config.AgentiodImage = immutableImageRef("agentiod", "b")
	config.CNIImage = immutableImageRef("install-cni", "1")
	config.ZtunnelImage = immutableImageRef("ztunnel", "c")
	config.ProxyInitImage = immutableImageRef("proxy-init", "d")
	config.GatewayImage = immutableImageRef("gateway", "e")
	config.EPEImage = immutableImageRef("epe", "f")
	config.EnableFirewallRules = true
	config.FirewallBackend = "iptables"

	data, err := chartValues(config)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatal(err)
	}

	if got := values["profile"]; got != "sidecar" {
		t.Fatalf("profile = %#v, want sidecar", got)
	}
	agentiod := values["agentiod"].(map[string]any)
	assertPinnedImage(t, agentiod["image"], "registry.example/agentiod", "sha256:"+strings.Repeat("b", 64))
	if got := agentiod["trustedNodeServiceAccount"]; got != "agentio-system/ztunnel" {
		t.Fatalf("trusted node account = %#v", got)
	}
	injector := agentiod["injector"].(map[string]any)
	ztunnel := injector["ztunnel"].(map[string]any)
	if ztunnel["image"] != config.ZtunnelImage || ztunnel["enableFirewallRules"] != true || ztunnel["firewallBackend"] != "iptables" {
		t.Fatalf("ztunnel injection values = %#v", ztunnel)
	}
	if got := injector["proxyInit"].(map[string]any)["image"]; got != config.ProxyInitImage {
		t.Fatalf("proxy-init image = %#v, want %q", got, config.ProxyInitImage)
	}
	cni := values["cni"].(map[string]any)
	assertPinnedImage(t, cni["image"], "registry.example/install-cni", "sha256:"+strings.Repeat("1", 64))
	topLevelZtunnel := values["ztunnel"].(map[string]any)
	assertPinnedImage(t, topLevelZtunnel["image"], "registry.example/ztunnel", "sha256:"+strings.Repeat("c", 64))

	gateway := values["egressGateway"].(map[string]any)
	if gateway["mode"] != "static" || gateway["nameOverride"] != "egress-gateway" {
		t.Fatalf("gateway mode/name = %#v", gateway)
	}
	assertPinnedImage(t, gateway["image"], "registry.example/gateway", "sha256:"+strings.Repeat("e", 64))
	if gateway["autoscaling"].(map[string]any)["enabled"] != false || gateway["podDisruptionBudget"].(map[string]any)["enabled"] != false {
		t.Fatalf("gateway singleton values = %#v", gateway)
	}

	epe := values["epe"].(map[string]any)
	if epe["mode"] != "managed" {
		t.Fatalf("epe mode = %#v, want managed", epe["mode"])
	}
	assertPinnedImage(t, epe["image"], "registry.example/epe", "sha256:"+strings.Repeat("f", 64))
}

func TestProductionChartRendersSuiteValues(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	config := validConfig(t)
	chartPath, err := findProductionChart()
	if err != nil {
		t.Fatal(err)
	}
	values, err := chartValues(config)
	if err != nil {
		t.Fatal(err)
	}
	valuesPath := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(valuesPath, values, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("helm", "template", "agentio", chartPath,
		"--namespace", config.Namespace, "--include-crds", "--values", valuesPath)
	manifest, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("render production Agentio chart: %v\n%s", err, manifest)
	}
	for _, expected := range []string{
		`name: egress-gateway`,
		`name: agentio-epe`,
		`image: "` + config.AgentiodImage + `"`,
		`image: "` + config.GatewayImage + `"`,
		`image: "` + config.EPEImage + `"`,
		`image: "` + config.ZtunnelImage + `"`,
		`image: "` + config.ProxyInitImage + `"`,
	} {
		if !strings.Contains(string(manifest), expected) {
			t.Errorf("rendered manifest does not contain %q", expected)
		}
	}
	if strings.Contains(string(manifest), "kind: DaemonSet") {
		t.Fatal("sidecar suite values unexpectedly rendered ambient DaemonSets")
	}
}

func TestProductionChartRendersAmbientSuiteImages(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	config := validConfig(t)
	config.Profile = "ambient"
	config.CNIImage = immutableImageRef("install-cni", "c")
	config.ZtunnelImage = immutableImageRef("ztunnel", "d")
	chartPath, err := findProductionChart()
	if err != nil {
		t.Fatal(err)
	}
	values, err := chartValues(config)
	if err != nil {
		t.Fatal(err)
	}
	valuesPath := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(valuesPath, values, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := exec.Command("helm", "template", "agentio", chartPath,
		"--namespace", config.Namespace, "--include-crds", "--values", valuesPath).CombinedOutput()
	if err != nil {
		t.Fatalf("render production Agentio chart: %v\n%s", err, manifest)
	}
	for _, expected := range []string{
		`kind: DaemonSet`,
		`image: "` + config.CNIImage + `"`,
		`image: "` + config.ZtunnelImage + `"`,
	} {
		if !strings.Contains(string(manifest), expected) {
			t.Errorf("rendered ambient manifest does not contain %q", expected)
		}
	}
}

func assertPinnedImage(t *testing.T, raw any, repository, digest string) {
	t.Helper()
	image := raw.(map[string]any)
	if image["repository"] != repository || image["digest"] != digest {
		t.Fatalf("image = %#v, want repository %q digest %q", image, repository, digest)
	}
}

func immutableImageRef(name, digestCharacter string) string {
	return "registry.example/" + name + "@sha256:" + strings.Repeat(digestCharacter, 64)
}

func validConfig(t *testing.T) Config {
	t.Helper()
	image := immutableImageRef("image", "a")
	return Config{
		Profile: "sidecar", Namespace: "agentio-system", AgentiodImage: image, CNIImage: image, ZtunnelImage: image,
		ProxyInitImage: image, GatewayImage: image, EPEImage: image,
		ExtProcImage: image, ForwardProxyImage: image, FirewallBackend: "auto",
	}
}
