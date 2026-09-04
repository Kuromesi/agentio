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

package network

import (
	"fmt"
	"net/netip"
)

func PrefixCIDR(address string, bits int) (string, error) {
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return "", fmt.Errorf("parse address %q: %w", address, err)
	}
	prefix := netip.PrefixFrom(parsed, bits)
	if !prefix.IsValid() {
		return "", fmt.Errorf("prefix length %d is invalid for %s", bits, parsed)
	}
	return prefix.Masked().String(), nil
}

func HostCIDR(address string) (string, error) {
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return "", fmt.Errorf("parse address %q: %w", address, err)
	}
	return netip.PrefixFrom(parsed, parsed.BitLen()).String(), nil
}
