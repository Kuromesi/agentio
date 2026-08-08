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

// schema.go is block's payload contract: the JSON document a policy source
// must produce for this filter, and the only place block's own config type
// is built. block.go stays free of it — the filter never sees a document.
package block

import (
	"encoding/json"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// spec is the wire form of a block payload. The tags mirror the
// SecurityProfile CRD's BlockAction so a CRD-shaped document parses
// unchanged; they are explicit because renaming a Go
// field must never silently change the wire.
type spec struct {
	StatusCode int32 `json:"statusCode,omitempty"`
	// Body is a pointer so a configured empty body stays distinguishable
	// from no body at all — the distinction Config.HasBody carries.
	Body *string `json:"body,omitempty"`
}

// parse builds a Config from one payload document.
func parse(raw json.RawMessage) (Config, error) {
	var s spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return Config{}, err
	}
	cfg := Config{Status: int(s.StatusCode)}
	if s.Body != nil {
		cfg.Body, cfg.HasBody = *s.Body, true
	}
	return cfg, nil
}

// Definition returns the typed block definition.
func Definition() filter.Definition { return filter.Define(Descriptor(), parse) }
