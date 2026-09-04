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

package mitm

import (
	"strings"
	"testing"
)

func TestOnDemandDomainValidation(t *testing.T) {
	tests := map[string]bool{
		"api.example.com":                 true,
		"API.Example.COM":                 true,
		"example.com.":                    true,
		"localhost":                       false,
		"127.0.0.1":                       false,
		"[::1]":                           false,
		"*.example.com":                   false,
		"example.com:443":                 false,
		"example.com/path":                false,
		" example.com":                    false,
		"example.123":                     false,
		"":                                false,
		strings.Repeat("a", 244) + ".com": false,
	}
	for domain, want := range tests {
		t.Run(domain, func(t *testing.T) {
			if got := IsValidDomain(domain); got != want {
				t.Fatalf("IsValidDomain(%q) = %t, want %t", domain, got, want)
			}
		})
	}
}

func TestOnDemandDomainCanonicalization(t *testing.T) {
	if got, want := CanonicalDomain("API.Example.COM."), "api.example.com"; got != want {
		t.Fatalf("CanonicalDomain() = %q, want %q", got, want)
	}
}
