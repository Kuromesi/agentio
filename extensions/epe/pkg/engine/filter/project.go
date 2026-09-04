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

package filter

import "encoding/json"

// Project maps one unit's payload documents onto the registration set. The
// returned slices are parallel to regs, so a config's index is its chain
// position — the shape engine.Unit.Cfgs already expects.
//
// This is the generic half of turning a policy unit into per-filter configs. It
// knows nothing about any policy API — a payload map keyed by registered filter
// name is the whole contract, so any policy source reuses it unchanged.
//
// A registration whose name has no payload gets a nil config and a nil
// error: the unit does not mount that filter. A registration whose payload
// fails to parse gets a nil config and the error, which the caller must
// turn into a fail-closed request (this is a malformed policy, not an
// absent one).
func Project(regs []Registration, payloads map[string]json.RawMessage) ([]any, []error) {
	cfgs := make([]any, len(regs))
	errs := make([]error, len(regs))
	for i, reg := range regs {
		raw, ok := payloads[reg.Name]
		if !ok {
			continue
		}
		cfg, err := reg.Parse(raw)
		if err != nil {
			errs[i] = err
			continue
		}
		cfgs[i] = cfg
	}
	return cfgs, errs
}
