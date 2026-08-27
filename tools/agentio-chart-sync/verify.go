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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"sigs.k8s.io/yaml"
)

var versionMetadataPattern = regexp.MustCompile(`(?m)^[ \t]*(chartVersion|appVersion|sourceCommit)[ \t]*:`)

func VerifyIntegrationBundle(bundle string) error {
	manager := filepath.Join(bundle, "sandbox-manager")
	managerValues, err := os.ReadFile(filepath.Join(manager, "values.yaml"))
	if err != nil {
		return fmt.Errorf("read sandbox-manager values: %w", err)
	}
	if err := validatePreparedBlock(managerValues, valuesBegin, valuesEnd, "sandbox-manager values"); err != nil {
		return err
	}
	managerDocument := map[string]any{}
	if err := yaml.Unmarshal(managerValues, &managerDocument); err != nil {
		return fmt.Errorf("parse sandbox-manager values: %w", err)
	}
	agentio, ok := managerDocument["agentio"].(map[string]any)
	if !ok {
		return errors.New("sandbox-manager values must contain agentio mapping")
	}
	if enabled, ok := agentio["enabled"].(bool); !ok || enabled {
		return errors.New("sandbox-manager agentio.enabled must be false")
	}
	for _, key := range []string{"ambient", "sidecarInjector", "ztunnel", "proxy", "proxyInit"} {
		if _, found := agentio[key]; found {
			return fmt.Errorf("sandbox-manager values contain unsupported agentio.%s", key)
		}
	}
	if global, ok := agentio["global"].(map[string]any); ok {
		for _, key := range []string{"enableFirewallRules", "enableClusterTrustBundle"} {
			if _, found := global[key]; found {
				return fmt.Errorf("sandbox-manager values contain unsupported agentio.global.%s", key)
			}
		}
	}
	if key := findForbiddenMetadataKey(managerDocument); key != "" {
		return fmt.Errorf("sandbox-manager values contain forbidden version metadata %s", key)
	}

	managerTemplates := filepath.Join(manager, "templates", "agentio")
	if err := verifyExcludedPaths(managerTemplates, sandboxManagerExcludedTemplates); err != nil {
		return err
	}
	managerFiles := filepath.Join(manager, "files", "agentio")
	if err := verifyExcludedPaths(managerFiles, sandboxManagerExcludedFiles); err != nil {
		return err
	}

	controller := filepath.Join(bundle, "sandbox-controller")
	controllerValues, err := os.ReadFile(filepath.Join(controller, "values.yaml"))
	if err != nil {
		return fmt.Errorf("read sandbox-controller values: %w", err)
	}
	if err := validatePreparedBlock(controllerValues, controllerValuesBegin, controllerValuesEnd, "sandbox-controller values"); err != nil {
		return err
	}
	controllerDocument := map[string]any{}
	if err := yaml.Unmarshal(controllerValues, &controllerDocument); err != nil {
		return fmt.Errorf("parse sandbox-controller values: %w", err)
	}
	if key := findForbiddenMetadataKey(controllerDocument); key != "" {
		return fmt.Errorf("sandbox-controller values contain forbidden version metadata %s", key)
	}
	_, controllerTemplate, err := findSandboxInjectionConfigTemplate(filepath.Join(controller, "templates"))
	if err != nil {
		return err
	}
	if controllerTemplate == nil {
		return errors.New("sandbox-controller bundle does not contain sandbox-injection-config")
	}
	if _, err := extractMarkedBlock(controllerTemplate, trafficProxyBegin, trafficProxyEnd, "sandbox-controller traffic-proxy template"); err != nil {
		return err
	}
	if path, key, err := findVersionMetadataInTree(bundle); err != nil {
		return err
	} else if key != "" {
		return fmt.Errorf("integration file %q contains forbidden version metadata %s", path, key)
	}
	return nil
}

func verifyExcludedPaths(root string, excluded map[string]struct{}) error {
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("validate integration directory %q: %w", root, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("integration path %q is not a directory", root)
	}
	for name := range excluded {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(name))); err == nil {
			return fmt.Errorf("integration bundle contains unsupported path %s", name)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("validate unsupported path %s: %w", name, err)
		}
	}
	return nil
}

func findForbiddenMetadataKey(value any) string {
	forbidden := map[string]struct{}{"chartVersion": {}, "appVersion": {}, "sourceCommit": {}}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if _, found := forbidden[key]; found {
				return key
			}
			if found := findForbiddenMetadataKey(child); found != "" {
				return found
			}
		}
	case []any:
		for _, child := range typed {
			if found := findForbiddenMetadataKey(child); found != "" {
				return found
			}
		}
	}
	return ""
}

func findVersionMetadataInTree(root string) (string, string, error) {
	var foundPath string
	var foundKey string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		match := versionMetadataPattern.FindSubmatch(content)
		if match == nil {
			return nil
		}
		foundPath = path
		foundKey = string(match[1])
		return fs.SkipAll
	})
	if err != nil {
		return "", "", fmt.Errorf("scan integration templates: %w", err)
	}
	return foundPath, foundKey, nil
}
