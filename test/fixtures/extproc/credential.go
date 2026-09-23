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

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Each endpoint issues a different credential on every upstream call, so the
// data-path test can observe both cache reuse and invalidation in the origin's
// echoed request header. These are fixture values, never real credentials.
func credentialHandler() http.Handler {
	var mu sync.Mutex
	calls := map[string]int{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/credentials/")
		if r.Method != http.MethodPost || name == r.URL.Path || name == "" {
			http.NotFound(w, r)
			return
		}
		var request struct {
			ResourceID string `json:"resourceId"`
			Name       string `json:"credentialProviderName"`
			Type       string `json:"credentialType"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil ||
			request.ResourceID != "epe-e2e-client" || request.Name != "remote-e2e" || request.Type != "apiKey" ||
			r.Header.Get("Authorization") != "Bearer epe-e2e-access" ||
			r.Header.Get("X-Api-Action-Name") != "GetResourceCredential" {
			http.Error(w, "invalid credential request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		calls[name]++
		token := fmt.Sprintf("%s-%d", name, calls[name])
		mu.Unlock()
		body, err := json.Marshal(map[string]any{"apiKey": token, "cacheExpiresInSeconds": 3600})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(body); err != nil {
			// The client went away mid-response; nothing left to report to.
			return
		}
	})
}

func serveCredentialProvider(port int) error {
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           credentialHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}
