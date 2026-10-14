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

// Package processor implements the gateway's CONNECT-only external processor.
package processor

import (
	"fmt"
	"strings"

	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

// HeaderSNI carries the application SNI observed by ztunnel.
const HeaderSNI = "x-agentio-sni"

// ConnectHeaders contains metadata observed by ztunnel. An absent SNI is empty;
// an explicitly empty or malformed header is rejected by ParseConnectHeaders.
type ConnectHeaders struct{ SNI string }

// ParseConnectHeaders validates and normalizes observed CONNECT metadata.
func ParseConnectHeaders(headers *extproc.HttpHeaders) (ConnectHeaders, error) {
	var result ConnectHeaders
	seen := false
	for _, header := range headers.GetHeaders().GetHeaders() {
		if header.GetKey() != HeaderSNI {
			continue
		}
		if seen {
			return result, fmt.Errorf("duplicate %s", HeaderSNI)
		}
		seen = true
		value := header.GetValue()
		if header.RawValue != nil {
			value = string(header.RawValue)
		}
		result.SNI = strings.TrimSuffix(strings.ToLower(value), ".")
		if errs := validation.IsDNS1123Subdomain(result.SNI); len(errs) != 0 {
			return result, fmt.Errorf("invalid %s: %s", HeaderSNI, strings.Join(errs, "; "))
		}
	}
	return result, nil
}
