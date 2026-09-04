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

package model

import "testing"

func TestSandboxBindingValidateRequiresUID(t *testing.T) {
	if err := (SandboxBinding{SandboxUID: "sandbox-a"}).Validate(); err != nil {
		t.Fatalf("valid Sandbox binding rejected: %v", err)
	}
	if err := (SandboxBinding{}).Validate(); err == nil {
		t.Fatal("empty Sandbox binding accepted")
	}
}

func TestTunnelProtocolValidateRejectsUnknownProtocol(t *testing.T) {
	for _, protocol := range []TunnelProtocol{"", TunnelProtocolNone, TunnelProtocolHBONE} {
		if err := protocol.Validate(); err != nil {
			t.Fatalf("valid tunnel protocol %q rejected: %v", protocol, err)
		}
	}
	if err := (TunnelProtocol("unknown")).Validate(); err == nil {
		t.Fatal("unknown tunnel protocol accepted")
	}
}
