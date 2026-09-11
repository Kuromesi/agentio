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

// Package envdoc renders documentation from the process-wide environment registry.
package envdoc

import (
	"flag"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"

	"istio.io/istio/pkg/env"
)

// Options selects registered variables and supplies documentation for dynamic defaults.
// Empty options include all registered, non-hidden variables with their binary defaults.
type Options struct {
	Prefixes      []string
	DefaultValues map[string]string
}

// Flags configures environment documentation output without starting a server.
type Flags struct {
	Enabled bool
	Format  string
}

// Bind registers the environment documentation flags on a command.
func (f *Flags) Bind(flags *flag.FlagSet) {
	flags.BoolVar(&f.Enabled, "print-env", false, "print registered environment variables, then exit")
	flags.StringVar(&f.Format, "print-env-format", "text", "environment output format: text (all registered variables) or markdown (documented settings); requires -print-env")
}

// Validate rejects invalid output options before the command starts a server.
func (f Flags) Validate() error {
	if f.Format != "text" && f.Format != "markdown" {
		return fmt.Errorf("invalid -print-env-format %q: must be text or markdown", f.Format)
	}
	if !f.Enabled && f.Format != "text" {
		return fmt.Errorf("-print-env-format requires -print-env")
	}
	return nil
}

// Write emits all variables in text mode, or the selected settings in Markdown mode.
func (f Flags) Write(writer io.Writer, markdown Options) error {
	if err := f.Validate(); err != nil {
		return err
	}
	if f.Format == "text" {
		return Write(writer, "text", Options{})
	}
	return Write(writer, "markdown", markdown)
}

// Write renders registry metadata, never the current environment values.
func Write(writer io.Writer, format string, options Options) error {
	return render(writer, env.VarDescriptions(), format, options)
}

func render(writer io.Writer, variables []env.Var, format string, options Options) error {
	var out strings.Builder
	switch format {
	case "text":
		fmt.Fprintf(&out, "%-42s %-18s %s\n", "VARIABLE", "DEFAULT", "DESCRIPTION")
	case "markdown":
		out.WriteString("| Variable | Type | Binary default | Description |\n| --- | --- | --- | --- |\n")
	default:
		return fmt.Errorf("unsupported environment documentation format %q", format)
	}
	// Sorting also makes callers with synthetic registry entries deterministic.
	variables = append([]env.Var(nil), variables...)
	sort.Slice(variables, func(i, j int) bool { return variables[i].Name < variables[j].Name })
	for _, variable := range variables {
		if variable.Hidden || !selected(variable.Name, options.Prefixes) {
			continue
		}
		defaultValue := variable.DefaultValue
		if override, found := options.DefaultValues[variable.Name]; found {
			defaultValue = override
		}
		if format == "text" {
			if defaultValue == "" {
				defaultValue = "-"
			}
			fmt.Fprintf(&out, "%-42s %-18s %s\n", variable.Name, defaultValue,
				strings.ReplaceAll(variable.Description, "\n", " "))
			continue
		}
		defaultCell := "empty"
		if defaultValue != "" {
			defaultCell = "<code>" + escapeCell(defaultValue) + "</code>"
		}
		description := escapeCell(variable.Description)
		if variable.Deprecated {
			description = "**Deprecated.** " + description
		}
		fmt.Fprintf(&out, "| <code>%s</code> | %s | %s | %s |\n",
			html.EscapeString(variable.Name), escapeCell(typeName(variable)), defaultCell, description)
	}
	_, err := io.WriteString(writer, out.String())
	return err
}

func selected(name string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func typeName(variable env.Var) string {
	switch variable.Type {
	case env.STRING:
		return "String"
	case env.BOOL:
		return "Boolean"
	case env.INT:
		return "Integer"
	case env.FLOAT:
		return "Floating-point"
	case env.DURATION:
		return "Duration"
	default:
		return variable.GoType
	}
}

// Entities keep Markdown syntax, HTML, and embedded newlines inside one table cell.
func escapeCell(value string) string {
	value = html.EscapeString(strings.Join(strings.Fields(value), " "))
	return strings.NewReplacer("|", "&#124;", "`", "&#96;", "\\", "&#92;",
		"*", "&#42;", "_", "&#95;", "[", "&#91;", "]", "&#93;", "~", "&#126;").Replace(value)
}
