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

package ci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestReleasePromotesExactProductE2ECandidates(t *testing.T) {
	workflow := loadWorkflow(t, "agentio-release.yml")
	jobs := workflowJobs(t, workflow)

	for _, forbidden := range []string{"build-ztunnel", "publish-ztunnel"} {
		if _, found := jobs[forbidden]; found {
			t.Errorf("release workflow must not own external component job %q", forbidden)
		}
	}

	build := workflowJob(t, jobs, "build-candidates")
	if got := stringValue(t, build, "uses"); got != "./.github/workflows/agentio-image.yml" {
		t.Errorf("build-candidates uses %q, want reusable owned-image workflow", got)
	}

	productE2E := workflowJob(t, jobs, "product-e2e")
	if got := stringValue(t, productE2E, "uses"); got != "./.github/workflows/agentio-e2e.yml" {
		t.Errorf("product-e2e uses %q, want reusable product E2E workflow", got)
	}
	inputs := mapValue(t, productE2E, "with")
	for _, input := range []string{
		"agentiod_image", "epe_image", "cni_image", "ztunnel_image",
		"proxy_init_image", "gateway_image", "ext_proc_image", "chart_artifact",
	} {
		if _, found := inputs[input]; !found {
			t.Errorf("product-e2e does not pass required BOM input %q", input)
		}
	}

	if needs := jobNeeds(t, jobs, "tag-agentio"); !slices.Contains(needs, "product-e2e") {
		t.Errorf("tag-agentio needs %v, want product-e2e gate", needs)
	}
	if needs := jobNeeds(t, jobs, "promote-version-images"); !slices.Contains(needs, "tag-agentio") || !slices.Contains(needs, "build-candidates") {
		t.Errorf("promote-version-images needs %v, want tag-agentio and build-candidates", needs)
	}
}

func TestProductE2ERunsSidecarAndAmbientOnSeparateClusters(t *testing.T) {
	workflow := loadWorkflow(t, "agentio-e2e.yml")
	jobs := workflowJobs(t, workflow)
	job := workflowJob(t, jobs, "product-e2e")
	strategy := mapValue(t, job, "strategy")
	matrix := mapValue(t, strategy, "matrix")
	include, ok := matrix["include"].([]any)
	if !ok {
		t.Fatalf("product-e2e matrix.include has type %T, want list", matrix["include"])
	}

	profiles := map[string]string{}
	for _, raw := range include {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("matrix entry has type %T, want map", raw)
		}
		profile, _ := entry["profile"].(string)
		cluster, _ := entry["cluster"].(string)
		profiles[profile] = cluster
	}
	for _, profile := range []string{"sidecar", "ambient"} {
		if profiles[profile] == "" {
			t.Errorf("product-e2e matrix is missing %q profile", profile)
		}
	}
	if profiles["sidecar"] == profiles["ambient"] {
		t.Errorf("sidecar and ambient must use separate KinD clusters, both use %q", profiles["sidecar"])
	}

	environment := mapValue(t, job, "env")
	for _, variable := range []string{
		"AGENTIO_E2E_AGENTIOD_IMAGE", "AGENTIO_E2E_EPE_IMAGE", "AGENTIO_E2E_CNI_IMAGE",
		"AGENTIO_E2E_ZTUNNEL_IMAGE", "AGENTIO_E2E_PROXY_INIT_IMAGE", "AGENTIO_E2E_GATEWAY_IMAGE",
	} {
		if _, found := environment[variable]; !found {
			t.Errorf("product-e2e does not expose %q", variable)
		}
	}
}

func TestOwnedImageWorkflowExportsImmutableReferences(t *testing.T) {
	workflow := loadWorkflow(t, "agentio-image.yml")
	jobs := workflowJobs(t, workflow)
	job := workflowJob(t, jobs, "build-images")
	outputs := mapValue(t, job, "outputs")
	for _, output := range []string{"agentiod_image", "epe_image"} {
		if _, found := outputs[output]; !found {
			t.Errorf("build-images is missing immutable output %q", output)
		}
	}
}

func TestExternalDependencyUpdatesAreReleaseDriven(t *testing.T) {
	workflow := loadWorkflow(t, "sync-agentio-deps.yml")
	triggers := workflowTriggers(t, workflow)
	if _, found := triggers["repository_dispatch"]; !found {
		t.Error("dependency sync must accept component release dispatches")
	}
	if _, found := triggers["schedule"]; found {
		t.Error("dependency sync must not follow source repositories on a schedule")
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "agentio.deps"))
	if err != nil {
		t.Fatal(err)
	}
	var pins []struct {
		Name       string `json:"name"`
		Repository string `json:"repository"`
		Digest     string `json:"digest"`
	}
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatalf("parse agentio.deps: %v", err)
	}
	want := map[string]bool{
		"ZTUNNEL_IMAGE": false, "CNI_IMAGE": false,
		"PROXY_INIT_IMAGE": false, "GATEWAY_IMAGE": false,
	}
	if len(pins) != len(want) {
		t.Fatalf("agentio.deps has %d entries, want exactly the four externally owned image pins", len(pins))
	}
	for _, pin := range pins {
		if _, found := want[pin.Name]; !found {
			t.Errorf("agentio.deps contains non-image or repository-owned pin %q", pin.Name)
			continue
		}
		if want[pin.Name] {
			t.Errorf("agentio.deps contains duplicate pin %q", pin.Name)
		}
		want[pin.Name] = true
		if pin.Repository == "" || pin.Digest == "" {
			t.Errorf("agentio.deps pin %q is incomplete", pin.Name)
		}
	}
}

func loadWorkflow(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatalf("read workflow %s: %v", name, err)
	}
	var workflow map[string]any
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse workflow %s: %v", name, err)
	}
	return workflow
}

func workflowJobs(t *testing.T, workflow map[string]any) map[string]any {
	t.Helper()
	return mapValue(t, workflow, "jobs")
}

func workflowTriggers(t *testing.T, workflow map[string]any) map[string]any {
	t.Helper()
	// GitHub's `on` key is a YAML 1.1 boolean spelling. sigs.k8s.io/yaml
	// normalizes it to "true" when decoding into an untyped map.
	if _, found := workflow["on"]; found {
		return mapValue(t, workflow, "on")
	}
	return mapValue(t, workflow, "true")
}

func workflowJob(t *testing.T, jobs map[string]any, name string) map[string]any {
	t.Helper()
	return mapValue(t, jobs, name)
}

func mapValue(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, found := parent[key]
	if !found {
		t.Fatalf("missing key %q", key)
	}
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("key %q has type %T, want map", key, value)
	}
	return result
}

func stringValue(t *testing.T, parent map[string]any, key string) string {
	t.Helper()
	value, found := parent[key]
	if !found {
		t.Fatalf("missing key %q", key)
	}
	result, ok := value.(string)
	if !ok {
		t.Fatalf("key %q has type %T, want string", key, value)
	}
	return result
}

func jobNeeds(t *testing.T, jobs map[string]any, name string) []string {
	t.Helper()
	job := workflowJob(t, jobs, name)
	value, found := job["needs"]
	if !found {
		return nil
	}
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			entry, ok := item.(string)
			if !ok {
				t.Fatalf("job %q needs entry has type %T, want string", name, item)
			}
			result = append(result, entry)
		}
		return result
	default:
		t.Fatalf("job %q needs has type %T, want string or list", name, value)
		return nil
	}
}
