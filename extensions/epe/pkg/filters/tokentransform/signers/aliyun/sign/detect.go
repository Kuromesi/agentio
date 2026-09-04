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
package sign

import (
	"net/url"
	"strings"
)

// Detect identifies the Aliyun signature scheme used to sign req. It
// inspects the Authorization header first (covers V3, V1-ROA, OSS-V4)
// then falls back to query-string heuristics (V1-RPC). Returns
// SignatureUnknown when no scheme is recognised; the caller is expected
// to apply its FailStrategy.
func Detect(req *RequestSnapshot) SignatureVersion {
	if req == nil {
		return SignatureUnknown
	}

	authz := strings.TrimSpace(req.Headers["authorization"])
	switch {
	case strings.HasPrefix(authz, "ACS3-HMAC-SHA256 "):
		return SignatureV3
	case strings.HasPrefix(authz, "OSS4-HMAC-SHA256 "):
		return SignatureOSSV4
	case strings.HasPrefix(authz, "acs ") && strings.Contains(authz, ":"):
		return SignatureV1ROA
	}

	if req.RawQuery != "" {
		q, err := url.ParseQuery(req.RawQuery)
		if err == nil &&
			q.Get("Signature") != "" &&
			q.Get("SignatureMethod") == "HMAC-SHA1" &&
			q.Get("AccessKeyId") != "" {
			return SignatureV1RPC
		}
	}
	return SignatureUnknown
}

// NeedsBody reports whether the given signature version requires the
// request body to recompute the signature.
//
// Only V1-RPC POST with a non-empty application/x-www-form-urlencoded
// body genuinely needs the body. The aliyun CLI and the V1 Go SDK
// (Core/1.63.x), used by many products such as ECS / VPC / RAM, place
// the full parameter set (including Signature) in the query string and
// leave the body empty. In that case the existing query string is
// sufficient to recompute the signature, and asking Envoy to deliver
// the body is not only wasteful but may not even happen — egress
// deployments commonly subscribe to ext-proc with header-only mode, so
// a ModeOverride to BUFFERED that arrives after the headers response
// may not result in any body message. Requiring body delivery there
// would silently block re-signing on every such request.
//
// A nil headers map is treated as "no body" so callers don't have to
// special-case it.
func NeedsBody(v SignatureVersion, method string, headers map[string]string) bool {
	if v != SignatureV1RPC || !strings.EqualFold(method, "POST") {
		return false
	}
	cl := strings.TrimSpace(headers["content-length"])
	if cl == "" || cl == "0" {
		return false
	}
	return isFormContentType(headers["content-type"])
}
