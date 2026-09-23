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
	"context"
	"net/http"
	"testing"
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
