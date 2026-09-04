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

package pki

// AppendCertificateChain returns an independent PEM chain containing leaf
// followed by bundle. It inserts one newline only when the leaf lacks one.
func AppendCertificateChain(leaf, bundle []byte) []byte {
	chain := append([]byte(nil), leaf...)
	if len(chain) > 0 && chain[len(chain)-1] != '\n' {
		chain = append(chain, '\n')
	}
	return append(chain, bundle...)
}
