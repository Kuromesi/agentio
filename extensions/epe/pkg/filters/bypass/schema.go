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
package bypass

import (
	"encoding/json"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// parse accepts any document. bypass carries no configuration; mounting it
// at all is the entire policy statement (`bypass: true`
// becomes `bypass: {}`).
func parse(json.RawMessage) (Config, error) { return Config{}, nil }

// Definition returns the typed bypass definition.
func Definition() filter.Definition { return filter.Define(Descriptor(), parse) }
