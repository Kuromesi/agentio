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
package tokentransform

import (
	"encoding/json"
	"fmt"

	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

// renderParams evaluates compiled credential-provider parameters against
// the unit scope; each result is JSON-normalized, and null is rejected.
func renderParams(params map[string]ParamSource, scope *inputs.Scope) (map[string]any, error) {
	if len(params) == 0 {
		return nil, nil
	}
	if scope == nil {
		return nil, fmt.Errorf("credential parameter evaluation scope is not configured")
	}
	metadata := make(map[string]any, len(params))
	for name, source := range params {
		value, err := renderParamSource(source, scope)
		if err != nil {
			return nil, fmt.Errorf("render credential parameter %q: %w", name, err)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("render credential parameter %q: result is not JSON-compatible: %w", name, err)
		}
		var normalized any
		if err := json.Unmarshal(encoded, &normalized); err != nil {
			return nil, fmt.Errorf("render credential parameter %q: normalize result: %w", name, err)
		}
		if normalized == nil {
			return nil, fmt.Errorf("render credential parameter %q: result is null", name)
		}
		metadata[name] = normalized
	}
	return metadata, nil
}

func renderParamSource(source ParamSource, scope *inputs.Scope) (any, error) {
	switch {
	case source.Value != nil:
		return *source.Value, nil
	case source.Template != nil:
		return eval.RenderToString(source.Template, scope)
	case source.Cel != nil:
		activation, release := scope.Activation()
		defer release()
		return eval.EvalValue(source.Cel, activation)
	default:
		return nil, fmt.Errorf("exactly one of value, cel or template must be set")
	}
}
