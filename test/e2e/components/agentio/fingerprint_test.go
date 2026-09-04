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
	"testing"
)

func TestInstallationFingerprintTracksChartAndValues(t *testing.T) {
	chartPath := testChart(t)
	first, err := installationFingerprint(chartPath, []byte("profile: sidecar\n"))
	if err != nil {
		t.Fatal(err)
	}

	valuesChanged, err := installationFingerprint(chartPath, []byte("profile: ambient\n"))
	if err != nil {
		t.Fatal(err)
	}
	if valuesChanged == first {
		t.Fatal("fingerprint did not change with Helm values")
	}

	templatePath := filepath.Join(chartPath, "templates", "deployment.yaml")
	if err := os.MkdirAll(filepath.Dir(templatePath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(templatePath, []byte("kind: Deployment\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chartChanged, err := installationFingerprint(chartPath, []byte("profile: sidecar\n"))
	if err != nil {
		t.Fatal(err)
	}
	if chartChanged == first {
		t.Fatal("fingerprint did not change with chart content")
	}
}
