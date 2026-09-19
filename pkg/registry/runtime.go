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

package registry

import (
	"fmt"
	"slices"
	"strings"
)

// SandboxRuntime identifies an optional integration used in Sandbox mode.
// Ordinary managed Pods remain Workloads and are not a configurable runtime.
type SandboxRuntime string

// SandboxRuntimeKruise discovers Kruise Agents Sandbox resources.
const SandboxRuntimeKruise SandboxRuntime = "kruise"

func (r SandboxRuntime) validate() error {
	switch r {
	case SandboxRuntimeKruise:
		return nil
	default:
		return fmt.Errorf(
			"unsupported sandbox runtime %q; supported runtimes: kruise",
			r,
		)
	}
}

// ParseSandboxRuntimes parses a comma-separated list, trims whitespace, and
// removes duplicates. An empty value enables no optional runtimes.
func ParseSandboxRuntimes(value string) ([]SandboxRuntime, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var runtimes []SandboxRuntime
	for name := range strings.SplitSeq(value, ",") {
		runtime := SandboxRuntime(strings.TrimSpace(name))
		if err := runtime.validate(); err != nil {
			return nil, err
		}
		if !slices.Contains(runtimes, runtime) {
			runtimes = append(runtimes, runtime)
		}
	}
	return runtimes, nil
}
