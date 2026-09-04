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

package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func applyStrictFile(cfg *Config, path string) (map[string]bool, error) {
	fields := make(map[string]bool)
	if strings.TrimSpace(path) == "" {
		return fields, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read e2e config %q: %w", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("decode e2e config %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("decode e2e config %q: multiple YAML documents are not supported", path)
		}
		return nil, fmt.Errorf("decode e2e config %q: %w", path, err)
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("inspect e2e config %q: %w", path, err)
	}
	collectFields(node.Content, "", fields)
	return fields, nil
}

func collectFields(nodes []*yaml.Node, prefix string, fields map[string]bool) {
	if len(nodes) == 0 {
		return
	}
	node := nodes[0]
	if node.Kind == yaml.DocumentNode {
		collectFields(node.Content, prefix, fields)
		return
	}
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		path := key.Value
		if prefix != "" {
			path = prefix + "." + path
		}
		fields[path] = true
		collectFields([]*yaml.Node{value}, path, fields)
	}
}
