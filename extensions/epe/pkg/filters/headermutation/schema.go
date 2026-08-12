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

package headermutation

import (
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/net/http/httpguts"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/eval"
)

type spec struct {
	Set    []valueSpec `json:"set,omitempty"`
	Add    []valueSpec `json:"add,omitempty"`
	Remove []string    `json:"remove,omitempty"`
}

type valueSpec struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func parse(raw json.RawMessage) (Config, error) {
	var s spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return Config{}, err
	}
	if len(s.Set)+len(s.Add)+len(s.Remove) == 0 {
		return Config{}, fmt.Errorf("header mutation has no operations")
	}

	seen := make(map[string]string, len(s.Set)+len(s.Add)+len(s.Remove))
	validateName := func(kind, name string) (string, error) {
		if !httpguts.ValidHeaderFieldName(name) {
			return "", fmt.Errorf("%s header %q has an invalid name", kind, name)
		}
		normalized := strings.ToLower(name)
		if normalized == "host" {
			return "", fmt.Errorf("%s header %q cannot modify Host", kind, name)
		}
		if previous, exists := seen[normalized]; exists {
			return "", fmt.Errorf("%s header %q duplicates %s header %q", kind, name, previous, normalized)
		}
		seen[normalized] = kind
		return normalized, nil
	}

	compile := func(kind string, ops []valueSpec) ([]ValueOp, error) {
		out := make([]ValueOp, 0, len(ops))
		for _, op := range ops {
			name, err := validateName(kind, op.Name)
			if err != nil {
				return nil, err
			}
			tmpl, err := eval.CompileTemplate(kind+" header "+op.Name, op.Value)
			if err != nil {
				return nil, fmt.Errorf("compile %s header %q: %w", kind, op.Name, err)
			}
			out = append(out, ValueOp{Name: name, Value: tmpl})
		}
		return out, nil
	}

	set, err := compile("set", s.Set)
	if err != nil {
		return Config{}, err
	}
	add, err := compile("add", s.Add)
	if err != nil {
		return Config{}, err
	}
	remove := make([]string, len(s.Remove))
	for i, name := range s.Remove {
		normalized, err := validateName("remove", name)
		if err != nil {
			return Config{}, err
		}
		remove[i] = normalized
	}
	return Config{Set: set, Add: add, Remove: remove}, nil
}

// Definition binds the payload parser to the typed filter descriptor.
func Definition() filter.Definition { return filter.Define(Descriptor(), parse) }
