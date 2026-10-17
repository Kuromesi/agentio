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
package admin

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
)

const credentialInvalidationPath = "/cache/credentials/invalidate"
const maxCredentialInvalidationBodyBytes = 4096

// CredentialInvalidator is the shared cache control surface for trigger adapters.
type CredentialInvalidator interface {
	InvalidateCredentials(credential.InvalidationRequest) (credential.InvalidationResult, error)
}

func (h *handler) handleCredentialInvalidation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed; use POST")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCredentialInvalidationBodyBytes))
	decoder.DisallowUnknownFields()
	var request credential.InvalidationRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid cache invalidation request: "+err.Error())
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "cache invalidation request must contain exactly one JSON object")
		return
	}
	result, err := h.credentials.InvalidateCredentials(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
