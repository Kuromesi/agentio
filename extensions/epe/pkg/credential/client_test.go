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
package credential

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/log"
	ctrlzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestNewClientExplicitConfiguration(t *testing.T) {
	c := NewClient("", &http.Client{}, nil, nil)
	if c == nil || c.providerURL != "" {
		t.Errorf("expected unset URL, got %q", c.providerURL)
	}

	c2 := NewClient("http://example.com/", &http.Client{}, nil, nil)
	if c2 == nil || c2.providerURL != "http://example.com/" {
		t.Errorf("expected explicit URL, got %q", c2.providerURL)
	}
}

// TestGetToken_BadURL covers http.NewRequestWithContext failure (invalid URL).
func TestGetToken_BadURL(t *testing.T) {
	c := NewClient("http://[::1", &http.Client{}, nil, nil)
	if _, err := c.GetToken(context.Background(), "a", "b", "c"); err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

func TestCredentialFailuresDoNotExposeResponseBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"http failure", 403, `{"apiKey":"sensitive-credential","message":"denied"}`, "status 403"},
		{"invalid JSON", 200, `{"apiKey":"sensitive-credential"`, "failed to unmarshal credential response"},
		{"invalid cache TTL", 200, `{"apiKey":"sensitive-credential","cacheExpiresInSeconds":"3600"}`, "failed to unmarshal credential response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			var out bytes.Buffer
			logger := ctrlzap.New(ctrlzap.WriteTo(&out))
			ctx := log.IntoContext(t.Context(), logger)
			client := NewClient(server.URL, server.Client(), nil, nil)
			_, err := client.GetToken(ctx, "sandbox-token", "client", "provider")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			// Callers also log the returned error, so both surfaces must be safe.
			logger.Error(err, "credential fetch failed")
			if strings.Contains(out.String(), "sensitive-credential") ||
				strings.Contains(err.Error(), "sensitive-credential") {
				t.Fatal("credential response body escaped into logs or the returned error")
			}
		})
	}
}
