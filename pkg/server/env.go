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

package server

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"istio.io/istio/pkg/env"
)

// PrintEnvironment writes every registered variable, its default and its purpose.
func PrintEnvironment(writer io.Writer) {
	variables := env.VarDescriptions()
	sort.Slice(variables, func(i, j int) bool { return variables[i].Name < variables[j].Name })
	fmt.Fprintf(writer, "%-42s %-18s %s\n", "VARIABLE", "DEFAULT", "DESCRIPTION")
	for _, variable := range variables {
		if variable.Hidden {
			continue
		}
		defaultValue := variable.DefaultValue
		if defaultValue == "" {
			defaultValue = "-"
		}
		fmt.Fprintf(writer, "%-42s %-18s %s\n", variable.Name, defaultValue,
			strings.ReplaceAll(variable.Description, "\n", " "))
	}
}
