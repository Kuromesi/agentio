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
	"fmt"
	"strings"
)

// Signer is the entry point for re-signing intercepted Aliyun requests.
type Signer struct{}

// New returns a default Signer.
func New() *Signer { return &Signer{} }

// Resign dispatches to the per-version signer and returns the
// ResignResult ready to be turned into an Envoy header mutation.
func (s *Signer) Resign(v SignatureVersion, req *RequestSnapshot, t Triplet) (*ResignResult, error) {
	switch v {
	case SignatureV3:
		return SignV3(req, t)
	case SignatureV1RPC:
		return SignV1RPC(req, t)
	case SignatureV1ROA:
		return SignV1ROA(req, t)
	case SignatureOSSV4:
		region, err := extractOSSV4Region(req)
		if err != nil {
			return nil, err
		}
		return SignOSSV4(req, t, OSSV4Params{
			Region:            region,
			AdditionalHeaders: extractOSSV4AdditionalHeaders(req),
		})
	default:
		return nil, fmt.Errorf("aliyunsign: unknown signature version %d", v)
	}
}

// extractOSSV4AdditionalHeaders pulls the header names the client declared in
// the Authorization "AdditionalHeaders=" segment, e.g.
//
//	OSS4-HMAC-SHA256 Credential=…,Signature=…,AdditionalHeaders=if-match;range
//
// The segment is optional; a request without it yields nil. Names are returned
// raw (splitting on ';' and trimming) — SignOSSV4 lower-cases, filters and
// sorts them. Both ",Name=" and ", Name=" spellings are accepted since the
// official SDK emits the spaced form.
func extractOSSV4AdditionalHeaders(req *RequestSnapshot) []string {
	if req == nil {
		return nil
	}
	authz := req.Headers["authorization"]
	const marker = "AdditionalHeaders="
	_, tail, found := strings.Cut(authz, marker)
	if !found {
		return nil
	}
	// The segment runs to the next comma (or end of header).
	if j := strings.IndexByte(tail, ','); j >= 0 {
		tail = tail[:j]
	}
	var out []string
	for name := range strings.SplitSeq(tail, ";") {
		if n := strings.TrimSpace(name); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// extractOSSV4Region pulls the region segment from the existing
// "Credential=<AK>/<YYYYMMDD>/<region>/oss/aliyun_v4_request" field on
// the Authorization header. Errors if the field is malformed.
func extractOSSV4Region(req *RequestSnapshot) (string, error) {
	if req == nil {
		return "", fmt.Errorf("ossv4: nil request snapshot")
	}
	authz := req.Headers["authorization"]
	const credPrefix = "Credential="
	i := strings.Index(authz, credPrefix)
	if i < 0 {
		return "", fmt.Errorf("ossv4: cannot derive region: no Credential= in Authorization header")
	}
	tail := authz[i+len(credPrefix):]
	if j := strings.IndexByte(tail, ','); j >= 0 {
		tail = tail[:j]
	}
	parts := strings.Split(tail, "/")
	if len(parts) < 5 {
		return "", fmt.Errorf("ossv4: cannot derive region: Credential field has %d segments, want 5", len(parts))
	}
	region := parts[2]
	if region == "" {
		return "", fmt.Errorf("ossv4: empty region segment in Credential field")
	}
	return region, nil
}
