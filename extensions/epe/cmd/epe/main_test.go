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
