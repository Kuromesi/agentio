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
	"bytes"
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// The Sandbox API is owned by the agent runtime rather than the Agentio chart,
// but the product E2E environment needs it as an explicit prerequisite.
//
//go:embed testdata/sandboxes.yaml
var prerequisiteFS embed.FS

func applyPrerequisites(ctx context.Context, environment *e2e.Environment, config Config) error {
	objects, err := prerequisiteObjects(config)
	if err != nil {
		return err
	}
	for _, object := range objects {
		if _, err := environment.Kube.Apply(ctx, object, kube.CreateOnly); err != nil {
			return fmt.Errorf("install Agentio prerequisite %s %s/%s: %w", object.GetKind(), object.GetNamespace(), object.GetName(), err)
		}
	}
	return nil
}

func prerequisiteObjects(config Config) ([]*unstructured.Unstructured, error) {
	namespace := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata":   map[string]any{"name": config.Namespace},
	}}
	objects := []*unstructured.Unstructured{namespace}

	crdFiles, err := filepath.Glob(filepath.Join(config.ChartPath, "crds", "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("list Agentio chart CRDs: %w", err)
	}
	sort.Strings(crdFiles)
	for _, path := range crdFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read Agentio chart CRD %q: %w", path, err)
		}
		decoded, err := kube.DecodeYAML(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decode Agentio chart CRD %q: %w", path, err)
		}
		objects = append(objects, decoded...)
	}
	sandboxCRD, err := prerequisiteFS.ReadFile("testdata/sandboxes.yaml")
	if err != nil {
		return nil, fmt.Errorf("read Sandbox prerequisite CRD: %w", err)
	}
	decoded, err := kube.DecodeYAML(bytes.NewReader(sandboxCRD))
	if err != nil {
		return nil, fmt.Errorf("decode Sandbox prerequisite CRD: %w", err)
	}
	objects = append(objects, decoded...)
	return objects, nil
}
