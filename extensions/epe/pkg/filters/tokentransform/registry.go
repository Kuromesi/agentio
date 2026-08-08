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
package tokentransform

import "sync"

var (
	signerMu sync.RWMutex
	signers  = map[string]Signer{}
)

// RegisterSigner makes key servable in this build. Call from init() only
// — the registry is read at projection and chain-build time.
func RegisterSigner(key string, s Signer) {
	signerMu.Lock()
	defer signerMu.Unlock()
	if key == "" {
		panic("tokentransform: empty signer key")
	}
	if s == nil {
		panic("tokentransform: nil signer for key " + key)
	}
	if _, dup := signers[key]; dup {
		panic("tokentransform: duplicate signer key " + key)
	}
	signers[key] = s
}

// HasSigner is the projection-time guard: fromcrd fails closed on types
// this build cannot serve.
func HasSigner(key string) bool {
	signerMu.RLock()
	defer signerMu.RUnlock()
	_, ok := signers[key]
	return ok
}

// signerMap snapshots the registry for chain construction.
func signerMap() map[string]Signer {
	signerMu.RLock()
	defer signerMu.RUnlock()
	out := make(map[string]Signer, len(signers))
	for k, v := range signers {
		out[k] = v
	}
	return out
}

// swapSigners empties the registry and returns a func that restores the
// previous contents; tests only. It restores rather than merely clearing
// because the signers registered by init() must survive for the rest of
// the test binary — a test that leaves the registry empty breaks every
// later test that builds a chain through it.
func swapSigners() func() {
	signerMu.Lock()
	defer signerMu.Unlock()
	prev := signers
	signers = map[string]Signer{}
	return func() {
		signerMu.Lock()
		defer signerMu.Unlock()
		signers = prev
	}
}
