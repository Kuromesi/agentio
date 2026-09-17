// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyReleasedBundlePreservesChartImageRegistry(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	source := filepath.Join(t.TempDir(), "agentio")
	copyTestTree(t, repositoryAgentioChart(t), source)
	digest := "sha256:" + strings.Repeat("a", 64)
	images := []string{}
	for _, name := range []string{"agentiod", "agentio-epe", "ztunnel", "install-cni", "proxy-init", "proxyv2"} {
		images = append(images, "docker.io/openkruise/"+name+"@"+digest)
	}
	if output, err := exec.Command("../prepare-release-chart.sh", append([]string{source, "1.2.3"}, images...)...).CombinedOutput(); err != nil {
		t.Fatalf("prepare released bundle: %v\n%s", err, output)
	}
	bundle := filepath.Join(source, "integrations", "openkruise")
	beforeBundle := readTestTree(t, bundle)
	manager, controller := t.TempDir(), newSandboxControllerChart(t)
	writeTestFile(t, manager, "Chart.yaml", "apiVersion: v2\nname: sandbox-manager\nversion: 1.0.0\n")
	writeTestFile(t, manager, "values.yaml", "image: {registry: docker.io}\nparent: unchanged\n")
	writeTestFile(t, controller, "values.yaml", "image: {registry: docker.io}\nnamespace: {name: sandbox-system}\n")
	args := []string{"--bundle", bundle, "--manager-chart", manager, "--controller-chart", controller}
	if err := runApply(args); err != nil {
		t.Fatal(err)
	}
	beforeManager, beforeController := readTestTree(t, manager), readTestTree(t, controller)
	if err := runApply(args); err != nil {
		t.Fatal(err)
	}
	if readTestTree(t, manager) != beforeManager || readTestTree(t, controller) != beforeController {
		t.Fatal("reapplying a released bundle changes the adapted charts")
	}
	if readTestTree(t, bundle) != beforeBundle {
		t.Fatal("apply mutated the released bundle")
	}
	if !strings.HasPrefix(readTestFile(t, manager, "values.yaml"), "image: {registry: docker.io}\nparent: unchanged\n") {
		t.Fatal("apply changed parent values outside the generated block")
	}
	for _, test := range []struct {
		name, chartRegistry, globalRegistry, imageRegistry, repository, tag, digest string
		managerPrefix, controllerPrefix                                             string
	}{
		{name: "released defaults", managerPrefix: "docker.io/openkruise/", controllerPrefix: "docker.io/openkruise/"},
		{name: "chart registry", chartRegistry: "mirror.example:5000", managerPrefix: "mirror.example:5000/openkruise/", controllerPrefix: "mirror.example:5000/openkruise/"},
		{name: "agentio registry", chartRegistry: "chart.example", globalRegistry: "agentio.example", managerPrefix: "agentio.example/openkruise/", controllerPrefix: "chart.example/openkruise/"},
		{name: "per-image registry", chartRegistry: "chart.example", globalRegistry: "agentio.example", imageRegistry: "image.example", managerPrefix: "image.example/openkruise/", controllerPrefix: "image.example/openkruise/"},
		{name: "qualified repository", chartRegistry: "chart.example", globalRegistry: "agentio.example", imageRegistry: "image.example", repository: "explicit.example:5000/team/image"},
		{name: "digest override", digest: digest, tag: "2.3.4", managerPrefix: "docker.io/openkruise/", controllerPrefix: "docker.io/openkruise/"},
		{name: "tag override", chartRegistry: "mirror.example", tag: "2.3.4", managerPrefix: "mirror.example/openkruise/", controllerPrefix: "mirror.example/openkruise/"},
	} {
		t.Run(test.name, func(t *testing.T) {
			imageValues := map[string]any{"registry": test.imageRegistry}
			if test.repository != "" {
				imageValues["repository"] = test.repository
			}
			suffix := ":1.2.3"
			if test.tag != "" {
				imageValues["tag"] = test.tag
				suffix = ":" + test.tag
			}
			if test.digest != "" {
				imageValues["digest"] = test.digest
				suffix = "@" + test.digest
			}
			managerValues := map[string]any{
				"image": map[string]any{"registry": test.chartRegistry},
				"agentio": map[string]any{
					"enabled":       true,
					"global":        map[string]any{"registry": test.globalRegistry},
					"agentiod":      map[string]any{"image": imageValues},
					"epe":           map[string]any{"mode": "managed", "image": imageValues},
					"egressGateway": map[string]any{"mode": "static", "image": imageValues},
				},
			}
			controllerValues := map[string]any{
				"image":   map[string]any{"registry": test.chartRegistry},
				"agentio": map[string]any{"trafficProxy": map[string]any{"image": imageValues, "initImage": imageValues}},
			}
			for _, chart := range []struct {
				path, prefix string
				values       map[string]any
				names        []string
			}{
				{manager, test.managerPrefix, managerValues, []string{"agentiod", "agentio-epe", "proxyv2"}},
				{controller, test.controllerPrefix, controllerValues, []string{"ztunnel", "proxy-init"}},
			} {
				all := ""
				for _, content := range renderChart(t, chart.path, chart.values) {
					all += content
				}
				for _, name := range chart.names {
					want := chart.prefix + name + suffix
					if test.repository != "" {
						want = test.repository + suffix
					}
					if !strings.Contains(all, `"`+want+`"`) {
						t.Errorf("rendered chart does not contain image %s", want)
					}
				}
			}
		})
	}
}

func TestApplyRequiresFixedReleaseTag(t *testing.T) {
	for _, tag := range []string{"", "latest", "main", "0.2", "01.2.3", "1.2.3-01", "1.2.3+build"} {
		t.Run(tag, func(t *testing.T) {
			bundle, target := t.TempDir(), t.TempDir()
			writeTestFile(t, bundle, "sandbox-manager/values.yaml", "agentio:\n  global:\n    tag: \""+tag+"\"\n")
			before := readTestTree(t, target)
			if err := runApply([]string{"--bundle", bundle, "--manager-chart", target}); err == nil || !strings.Contains(err.Error(), "fixed release version") {
				t.Fatalf("expected release tag validation error, got %v", err)
			}
			if readTestTree(t, target) != before {
				t.Fatal("invalid release tag changed target")
			}
		})
	}
	for _, tag := range []string{"0.2.0", "1.2.3-rc.1"} {
		bundle := t.TempDir()
		writeTestFile(t, bundle, "sandbox-manager/values.yaml", "agentio:\n  global:\n    tag: \""+tag+"\"\n")
		if actual, err := integrationImageTag(bundle); err != nil || actual != tag {
			t.Fatalf("tag %q: got %q, %v", tag, actual, err)
		}
	}
}
