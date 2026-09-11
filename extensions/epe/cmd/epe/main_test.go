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

package main

import (
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestAuditWebhookVerifiesTLSByDefault(t *testing.T) {
	configured := flag.Lookup("audit-webhook-insecure-skip-verify")
	if configured == nil {
		t.Fatal("audit webhook TLS verification flag is not registered")
	}
	if configured.DefValue != "false" {
		t.Fatalf("audit webhook insecure-skip-verify default = %q, want false", configured.DefValue)
	}
}

func TestPrintEnvironmentExitsBeforeStartup(t *testing.T) {
	if os.Getenv("EPE_ENV_DOC_TEST_HELPER") == "true" {
		// Run in a subprocess because EPE owns the process-global flag set.
		os.Args = []string{"epe", "-print-env", "-print-env-format=" + os.Getenv("EPE_ENV_DOC_TEST_FORMAT")}
		flag.CommandLine = flag.NewFlagSet("epe", flag.ContinueOnError)
		if err := run(); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, format := range []string{"text", "markdown"} {
		command := exec.Command(os.Args[0], "-test.run=^TestPrintEnvironmentExitsBeforeStartup$")
		command.Env = append(os.Environ(), "EPE_ENV_DOC_TEST_HELPER=true", "EPE_ENV_DOC_TEST_FORMAT="+format,
			"CREDENTIAL_PROVIDER_MTLS_SOURCE=invalid", "KUBECONFIG=/does/not/exist")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s export attempted startup: %v\n%s", format, err, output)
		}
		for _, expected := range []string{"IDENTITY_PROVIDER_URL", "TOKEN_CACHE_TTL", "TOKEN_CACHE_MAX_SIZE",
			"STS_CACHE_MAX_SIZE", "CREDENTIAL_PROVIDER_MTLS_SOURCE", "AUDIT_WEBHOOK_DIAL_TIMEOUT"} {
			if !strings.Contains(string(output), expected) {
				t.Errorf("%s export missing %s", format, expected)
			}
		}
		if format == "markdown" && strings.Contains(string(output), "AGENTIO_CA_SECRET_NAME") {
			t.Fatal("EPE table includes unrelated control-plane settings")
		}
	}
}
