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

package envdoc

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"istio.io/istio/pkg/env"
)

func TestMarkdownRegistryMetadata(t *testing.T) {
	variables := []env.Var{
		{Name: "APP_Z", Type: env.INT, DefaultValue: "37", Description: "Computed default."},
		{Name: "OTHER_VALUE", Type: env.BOOL, DefaultValue: "false"},
		{Name: "APP_HIDDEN", Hidden: true},
		{Name: "APP_A", Type: env.STRING, Deprecated: true, Description: "Use a | b\nwith <tag>, `code`, *stars* and [links](url)."},
	}
	var out strings.Builder
	err := render(&out, variables, "markdown", Options{
		Prefixes:      []string{"APP_"},
		DefaultValues: map[string]string{"APP_Z": "automatic"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if strings.Contains(body, "OTHER_VALUE") || strings.Contains(body, "APP_HIDDEN") {
		t.Fatalf("hidden or unselected variables leaked: %s", body)
	}
	if strings.Index(body, "APP_A") > strings.Index(body, "APP_Z") {
		t.Fatalf("variables are not sorted: %s", body)
	}
	for _, want := range []string{"| String | empty | **Deprecated.**", "| Integer | <code>automatic</code>",
		"a &#124; b with &lt;tag&gt;", "&#96;code&#96;", "&#42;stars&#42;", "&#91;links&#93;"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in %s", want, body)
		}
	}
	if len(strings.Split(strings.TrimSpace(body), "\n")) != 4 {
		t.Fatalf("a cell introduced extra rows: %s", body)
	}
	if variables[0].Name != "APP_Z" || variables[0].DefaultValue != "37" {
		t.Fatal("render mutated its input")
	}
}

func TestWriteUsesDefaultsDespiteEnvironmentOverrides(t *testing.T) {
	const name = "ENV_DOC_TEST_DEFAULT"
	env.Register(name, 123, "Test registered default.")
	t.Setenv(name, "987")
	for _, format := range []string{"text", "markdown"} {
		var out strings.Builder
		if err := Write(&out, format, Options{Prefixes: []string{name}}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "123") || strings.Contains(out.String(), "987") {
			t.Fatalf("%s output used the environment value: %s", format, out.String())
		}
	}
}

func TestMarkdownTypesAndDefaultEscaping(t *testing.T) {
	for _, tc := range []struct {
		typ    env.VarType
		goType string
		want   string
	}{
		{env.STRING, "", "String"}, {env.BOOL, "", "Boolean"},
		{env.INT, "", "Integer"}, {env.FLOAT, "", "Floating-point"},
		{env.DURATION, "", "Duration"}, {env.OTHER, "[]string", "&#91;&#93;string"},
	} {
		var out strings.Builder
		err := render(&out, []env.Var{{Name: "VALUE", Type: tc.typ, GoType: tc.goType,
			DefaultValue: "a|<b>`c`\nnext"}}, "markdown", Options{})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "| "+tc.want+" | <code>a&#124;&lt;b&gt;&#96;c&#96; next</code>") {
			t.Fatalf("unexpected row: %s", out.String())
		}
	}
}

func TestFlagsRejectInvalidExportRequests(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		valid bool
	}{
		{nil, true}, {[]string{"-print-env"}, true},
		{[]string{"-print-env", "-print-env-format=markdown"}, true},
		{[]string{"-print-env-format=markdown"}, false},
		{[]string{"-print-env", "-print-env-format=json"}, false},
	} {
		var options Flags
		flags := flag.NewFlagSet("test", flag.ContinueOnError)
		options.Bind(flags)
		if err := flags.Parse(tc.args); err != nil {
			t.Fatal(err)
		}
		if err := options.Validate(); (err == nil) != tc.valid {
			t.Errorf("%v: validation error = %v", tc.args, err)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriteReportsOutputErrors(t *testing.T) {
	for _, format := range []string{"text", "markdown"} {
		if err := Write(failingWriter{}, format, Options{}); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("%s: got %v, want closed pipe", format, err)
		}
	}
	var out strings.Builder
	if err := Write(&out, "json", Options{}); err == nil || out.Len() != 0 {
		t.Fatalf("unsupported output format: err=%v, output=%s", err, out.String())
	}
}
