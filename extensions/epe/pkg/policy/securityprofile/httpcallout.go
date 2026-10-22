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

package securityprofile

import (
	"encoding/json"
	"fmt"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

// httpCalloutPayload translates the public disclosure controls into the filter schema.
func httpCalloutPayload(a *v1alpha1.HTTPCalloutAction) (json.RawMessage, error) {
	failOpen := false
	switch a.FailStrategy {
	case "", v1alpha1.FailStrategyBlock:
	case v1alpha1.FailStrategyAllow, v1alpha1.FailStrategyIgnore:
		failOpen = true
	default:
		return nil, fmt.Errorf("unknown fail strategy %q", a.FailStrategy)
	}
	type headersSpec struct {
		Mode      string   `json:"mode"`
		Allowlist []string `json:"allowlist,omitempty"`
		Denylist  []string `json:"denylist,omitempty"`
	}
	type phaseSpec struct {
		Headers      headersSpec `json:"headers"`
		Body         bool        `json:"body,omitempty"`
		MaxBodyBytes int64       `json:"maxBodyBytes,omitempty"`
	}
	phases := make([]*phaseSpec, 2)
	for i, phase := range []*v1alpha1.HTTPCalloutPhase{a.Request, a.Response} {
		if phase == nil {
			continue
		}
		out := &phaseSpec{Headers: headersSpec{Mode: "none"}}
		if h := phase.Headers; h != nil && h.Enabled {
			out.Headers.Mode = "all"
			if f := h.Filter; f != nil {
				if (len(f.AllowList) == 0) == (len(f.DenyList) == 0) {
					return nil, fmt.Errorf("header filter requires exactly one non-empty allowList or denyList")
				}
				if len(f.AllowList) > 0 {
					out.Headers = headersSpec{Mode: "allowlist", Allowlist: f.AllowList}
				} else {
					out.Headers = headersSpec{Mode: "denylist", Denylist: f.DenyList}
				}
			}
		}
		if b := phase.Body; b != nil && b.Enabled {
			if b.MaxBytes < 0 || b.MaxBytes > 8<<20 {
				return nil, fmt.Errorf("body maxBytes must be between 1 and 8388608")
			}
			out.Body, out.MaxBodyBytes = true, b.MaxBytes
		}
		phases[i] = out
	}
	return json.Marshal(struct {
		Provider string     `json:"provider"`
		Request  *phaseSpec `json:"request,omitempty"`
		Response *phaseSpec `json:"response,omitempty"`
		FailOpen bool       `json:"failOpen,omitempty"`
	}{a.Provider.Name, phases[0], phases[1], failOpen})
}
