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

package agentio

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestControlPlanePodSelector(t *testing.T) {
	if controlPlanePodSelector != "app=agentiod" {
		t.Fatalf("unexpected control-plane selector %q", controlPlanePodSelector)
	}
}

func TestHelmArgsIncludesValuesFilesBeforeSetOverrides(t *testing.T) {
	valuesFile := filepath.Join(t.TempDir(), "agentio-e2e-values.yaml")
	if err := os.WriteFile(valuesFile, []byte("proxy: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ValuesFiles: []string{valuesFile},
		Values: map[string]string{
			"ambient.enabled": "true",
		},
	}

	got, err := cfg.helmArgs()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--create-namespace",
		"--values", valuesFile,
		"--set", "ambient.enabled=true",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Helm args mismatch: got %v, want %v", got, want)
	}
}

func TestHelmArgsRejectsUnsafeValuesFilePath(t *testing.T) {
	cfg := Config{ValuesFiles: []string{"/tmp/values;echo.yaml"}}
	if _, err := cfg.helmArgs(); err == nil {
		t.Fatal("expected unsafe values file path to be rejected")
	}
}

func TestHelmArgsRejectsUnsafeSetArguments(t *testing.T) {
	for name, values := range map[string]map[string]string{
		"key":   {"global.enabled;touch": "true"},
		"value": {"global.enabled": "$(touch /tmp/pwned)"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := (Config{Values: values}).helmArgs(); err == nil {
				t.Fatalf("expected unsafe values %v to be rejected", values)
			}
		})
	}
}

func TestHelmArgsRejectsMissingAndNonRegularValuesFiles(t *testing.T) {
	for name, valuesFile := range map[string]string{
		"missing":   filepath.Join(t.TempDir(), "missing.yaml"),
		"directory": t.TempDir(),
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{ValuesFiles: []string{valuesFile}}
			if _, err := cfg.helmArgs(); err == nil {
				t.Fatalf("expected values file %q to be rejected", valuesFile)
			}
		})
	}
}

func TestHelmArgsPreservesValuesFileOrderAndSortsSetOverrides(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.yaml")
	second := filepath.Join(t.TempDir(), "second.yaml")
	for _, valuesFile := range []string{first, second} {
		if err := os.WriteFile(valuesFile, []byte("enabled: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{
		ValuesFiles: []string{first, second},
		Values: map[string]string{
			"z.key": "last",
			"a.key": "first",
		},
	}

	got, err := cfg.helmArgs()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--create-namespace",
		"--values", first,
		"--values", second,
		"--set", "a.key=first",
		"--set", "z.key=last",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Helm args mismatch: got %v, want %v", got, want)
	}
}
