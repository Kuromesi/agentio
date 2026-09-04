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
package filter

import (
	"strings"
	"testing"
)

func TestValidateHeaderNameNormalizes(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind HeaderOpKind
		in   string
		want string
	}{
		{name: "mixed case set", kind: HeaderSet, in: "X-Tenant-ID", want: "x-tenant-id"},
		{name: "mixed case add", kind: HeaderAdd, in: "Set-Cookie", want: "set-cookie"},
		{name: "mixed case remove", kind: HeaderRemove, in: "Server", want: "server"},
		{name: "already lowercase", kind: HeaderSet, in: "x-a", want: "x-a"},
		{name: "content-length remove", kind: HeaderRemove, in: "Content-Length", want: "content-length"},
		{name: "transfer-encoding remove", kind: HeaderRemove, in: "Transfer-Encoding", want: "transfer-encoding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateHeaderName(tc.kind, tc.in)
			if err != nil {
				t.Fatalf("ValidateHeaderName(%v, %q): %v", tc.kind, tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalized name = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateHeaderNameRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind HeaderOpKind
		in   string
		want string
	}{
		{name: "invalid name", kind: HeaderSet, in: "bad header", want: `header "bad header" has an invalid name`},
		{name: "empty name", kind: HeaderSet, in: "", want: "has an invalid name"},
		// ValidHeaderFieldName rejects ":", so pseudo-headers never reach the
		// later rules. SetPath deliberately produces :path, which is why this
		// validator must stay off the fold and translate paths.
		{name: "pseudo path", kind: HeaderSet, in: ":path", want: `header ":path" has an invalid name`},
		{name: "pseudo status", kind: HeaderRemove, in: ":status", want: "has an invalid name"},
		{name: "host set", kind: HeaderSet, in: "Host", want: `header "Host" cannot modify Host`},
		{name: "host remove", kind: HeaderRemove, in: "host", want: "cannot modify Host"},
		{name: "x-envoy prefixed", kind: HeaderSet, in: "X-Envoy-Foo", want: `header "X-Envoy-Foo" is reserved by Envoy and would be ignored`},
		{name: "x-envoy exact", kind: HeaderRemove, in: "X-Envoy", want: "is reserved by Envoy"},
		{name: "x-envoy no hyphen", kind: HeaderAdd, in: "x-envoyer", want: "is reserved by Envoy"},
		{name: "connection", kind: HeaderSet, in: "Connection", want: `header "Connection" is connection-scoped and cannot be mutated`},
		{name: "keep-alive", kind: HeaderRemove, in: "Keep-Alive", want: "is connection-scoped"},
		{name: "proxy-connection", kind: HeaderRemove, in: "proxy-connection", want: "is connection-scoped"},
		{name: "upgrade", kind: HeaderAdd, in: "Upgrade", want: "is connection-scoped"},
		{name: "te", kind: HeaderRemove, in: "TE", want: "is connection-scoped"},
		{name: "trailer", kind: HeaderRemove, in: "Trailer", want: "is connection-scoped"},
		{name: "proxy-authenticate", kind: HeaderRemove, in: "Proxy-Authenticate", want: "is connection-scoped"},
		{name: "content-encoding", kind: HeaderRemove, in: "Content-Encoding", want: "is connection-scoped"},
		{name: "content-length set", kind: HeaderSet, in: "Content-Length", want: `header "Content-Length" controls message framing and can only be removed`},
		{name: "content-length add", kind: HeaderAdd, in: "content-length", want: "controls message framing and can only be removed"},
		{name: "transfer-encoding set", kind: HeaderSet, in: "Transfer-Encoding", want: "controls message framing and can only be removed"},
		{name: "transfer-encoding add", kind: HeaderAdd, in: "transfer-encoding", want: "controls message framing and can only be removed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateHeaderName(tc.kind, tc.in)
			if err == nil {
				t.Fatalf("ValidateHeaderName(%v, %q) = %q, want an error", tc.kind, tc.in, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.want)
			}
			if got != "" {
				t.Errorf("normalized name = %q, want empty on rejection", got)
			}
		})
	}
}

func TestValidateHeaderNameFramingDependsOnKind(t *testing.T) {
	for _, name := range []string{"content-length", "transfer-encoding"} {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateHeaderName(HeaderRemove, name); err != nil {
				t.Errorf("ValidateHeaderName(HeaderRemove, %q): %v", name, err)
			}
			for _, kind := range []HeaderOpKind{HeaderSet, HeaderAdd} {
				if _, err := ValidateHeaderName(kind, name); err == nil {
					t.Errorf("ValidateHeaderName(%v, %q) = nil, want an error", kind, name)
				}
			}
		})
	}
}
