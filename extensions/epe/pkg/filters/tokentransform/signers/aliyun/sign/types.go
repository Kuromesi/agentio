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
// Package sign implements signature recomputation for intercepted
// Aliyun-SDK egress requests. Each supported signature version (V3,
// V1-RPC, V1-ROA, OSS-V4) lives in its own file and is dispatched through
// a single Signer.Resign entry point.
package sign

// Triplet is the Aliyun STS credential set required to (re)sign a request.
// AccessKeySecret participates in HMAC; the other two travel in headers
// (or query, for V1 RPC) and in the canonical request.
type Triplet struct {
	AccessKeyID     string
	AccessKeySecret string
	SecurityToken   string
}

// RequestSnapshot is the subset of HTTP request data Resign needs.
// Headers keys are lower-cased (Envoy convention). Body is populated
// only for signature versions that consume the request body
// (currently V1-RPC POST with application/x-www-form-urlencoded).
type RequestSnapshot struct {
	Method   string
	Scheme   string
	Host     string
	Path     string
	RawQuery string
	Headers  map[string]string
	Body     []byte
}

// HeaderKV is a single header mutation entry.
type HeaderKV struct {
	Name  string
	Value string
}

// ResignResult describes the Envoy header / path mutations to apply
// after a successful Resign. SetHeaders are upserted; RemoveHeaders are
// deleted; NewPath, when non-nil, replaces the :path pseudo-header
// (used by V1-RPC where Signature lives in the query string).
type ResignResult struct {
	SetHeaders    []HeaderKV
	RemoveHeaders []string
	NewPath       *string
}

// SignatureVersion identifies which Aliyun signing scheme produced an
// intercepted request.
type SignatureVersion int

const (
	// SignatureUnknown means the request did not match any known scheme.
	SignatureUnknown SignatureVersion = iota
	// SignatureV3 is ACS3-HMAC-SHA256 (V2 SDK default).
	SignatureV3
	// SignatureV1RPC is the V1 RPC HMAC-SHA1 scheme (SecurityToken in query).
	SignatureV1RPC
	// SignatureV1ROA is the V1 ROA HMAC-SHA1 scheme (x-acs-security-token header).
	SignatureV1ROA
	// SignatureOSSV4 is OSS4-HMAC-SHA256 (OSS V4 SDK default).
	SignatureOSSV4
)

// String returns a human-readable label suitable for logs and metrics.
func (v SignatureVersion) String() string {
	switch v {
	case SignatureV3:
		return "v3"
	case SignatureV1RPC:
		return "v1rpc"
	case SignatureV1ROA:
		return "v1roa"
	case SignatureOSSV4:
		return "ossv4"
	default:
		return "unknown"
	}
}
