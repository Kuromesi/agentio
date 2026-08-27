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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	yamlv3 "gopkg.in/yaml.v3"
)

var (
	versionPattern          = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	sourceRepositoryPattern = regexp.MustCompile(`^[0-9A-Za-z_.-]+/[0-9A-Za-z_.-]+$`)
)

func PrepareReleaseChart(chart, version, sourceRepository string) error {
	if !versionPattern.MatchString(version) {
		return fmt.Errorf("invalid release version %q", version)
	}
	if !sourceRepositoryPattern.MatchString(sourceRepository) {
		return fmt.Errorf("invalid source repository %q", sourceRepository)
	}

	chartPath := filepath.Join(chart, "Chart.yaml")
	chartContent, err := os.ReadFile(chartPath)
	if err != nil {
		return fmt.Errorf("read Chart.yaml: %w", err)
	}
	chartDocument := yamlv3.Node{}
	if err := yamlv3.Unmarshal(chartContent, &chartDocument); err != nil {
		return fmt.Errorf("parse Chart.yaml: %w", err)
	}
	chartRoot, err := yamlDocumentMapping(&chartDocument, "Chart.yaml")
	if err != nil {
		return err
	}
	if err := setYAMLScalar(chartRoot, "version", version); err != nil {
		return fmt.Errorf("set Chart.yaml version: %w", err)
	}
	if err := setYAMLScalar(chartRoot, "appVersion", version); err != nil {
		return fmt.Errorf("set Chart.yaml appVersion: %w", err)
	}
	annotations := yamlMappingValue(chartRoot, "annotations")
	if annotations == nil || annotations.Kind != yamlv3.MappingNode {
		return errors.New("Chart.yaml annotations must be a mapping")
	}
	change := fmt.Sprintf("- \"[Changed]: See Agentio %s release notes: https://github.com/%s/releases/tag/%s\"", version, sourceRepository, version)
	if err := setYAMLScalar(annotations, "artifacthub.io/changes", change); err != nil {
		return fmt.Errorf("set Chart.yaml release annotation: %w", err)
	}
	preparedChart, err := encodeYAMLDocument(&chartDocument)
	if err != nil {
		return fmt.Errorf("encode Chart.yaml: %w", err)
	}

	valuesPath := filepath.Join(chart, "values.yaml")
	valuesContent, err := os.ReadFile(valuesPath)
	if err != nil {
		return fmt.Errorf("read values.yaml: %w", err)
	}
	valuesDocument := yamlv3.Node{}
	if err := yamlv3.Unmarshal(valuesContent, &valuesDocument); err != nil {
		return fmt.Errorf("parse values.yaml: %w", err)
	}
	valuesRoot, err := yamlDocumentMapping(&valuesDocument, "values.yaml")
	if err != nil {
		return err
	}
	wantImages := map[string]int{
		"pilot": 1, "proxy-init": 1, "proxyv2": 2,
		"install-cni": 1, "ztunnel": 1, "agentio-epe": 1,
	}
	imageCounts := map[string]int{}
	updateReleaseImageTags(valuesRoot, version, wantImages, imageCounts)
	for name, want := range wantImages {
		if imageCounts[name] != want {
			return fmt.Errorf("values.yaml image %q count = %d, want %d", name, imageCounts[name], want)
		}
	}
	preparedValues, err := encodeYAMLDocument(&valuesDocument)
	if err != nil {
		return fmt.Errorf("encode values.yaml: %w", err)
	}

	if err := writeFileAtomically(chartPath, preparedChart, 0o644); err != nil {
		return fmt.Errorf("write Chart.yaml: %w", err)
	}
	if err := writeFileAtomically(valuesPath, preparedValues, 0o644); err != nil {
		return fmt.Errorf("write values.yaml: %w", err)
	}
	if err := BuildIntegrationBundle(chart, filepath.Join(chart, "integrations", "openkruise")); err != nil {
		return fmt.Errorf("build OpenKruise integration bundle: %w", err)
	}
	return nil
}

func yamlDocumentMapping(document *yamlv3.Node, description string) (*yamlv3.Node, error) {
	if len(document.Content) != 1 || document.Content[0].Kind != yamlv3.MappingNode {
		return nil, fmt.Errorf("%s must contain a YAML mapping", description)
	}
	return document.Content[0], nil
}

func setYAMLScalar(mapping *yamlv3.Node, key, value string) error {
	if mapping == nil || mapping.Kind != yamlv3.MappingNode {
		return errors.New("parent is not a YAML mapping")
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value != key {
			continue
		}
		if mapping.Content[i+1].Kind != yamlv3.ScalarNode {
			return fmt.Errorf("%s is not a scalar", key)
		}
		mapping.Content[i+1].Value = value
		mapping.Content[i+1].Tag = "!!str"
		return nil
	}
	return fmt.Errorf("missing key %s", key)
}

func encodeYAMLDocument(document *yamlv3.Node) ([]byte, error) {
	var out bytes.Buffer
	encoder := yamlv3.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func updateReleaseImageTags(node *yamlv3.Node, version string, wanted, counts map[string]int) {
	if node == nil {
		return
	}
	if node.Kind == yamlv3.MappingNode {
		name := yamlMappingValue(node, "name")
		tag := yamlMappingValue(node, "tag")
		if name != nil && tag != nil && name.Kind == yamlv3.ScalarNode && tag.Kind == yamlv3.ScalarNode {
			if _, found := wanted[name.Value]; found {
				tag.Value = version
				tag.Tag = "!!str"
				counts[name.Value]++
			}
		}
	}
	for _, child := range node.Content {
		updateReleaseImageTags(child, version, wanted, counts)
	}
}
