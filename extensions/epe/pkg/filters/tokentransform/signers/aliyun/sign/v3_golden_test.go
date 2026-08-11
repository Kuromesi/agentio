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

// V3 conformance vectors.
//
// The other V3 tests recompute their expected Signature by calling
// computeV3Signature — the function under test — so they cannot detect a
// deviation from the ACS3 spec: change the canonicalization and the expected
// value changes with it. That is how the missing host header and the
// un-normalized canonical URI both stayed green.
//
// These vectors pin the canonical request as a literal instead. Every
// spec-conformance decision V3 makes is visible in that string — which headers
// are signed, how the URI and query are canonicalized, the component order and
// separator — and the literal is reviewable line by line against the reference
// signer (alibabacloud-go/openapi-util service.go GetAuthorization, which
// builds `method \n canonicalURI \n canonicalQueryString \n canonicalHeaders \n
// signedHeaders \n hashedPayload` and selects x-acs-*/host/content-type in
// getCanonicalHeaders). A change to any of it fails here loudly.
//
// The crypto below the canonical request (SHA-256, the algorithm line, HMAC,
// hex) is pinned separately. Those literals were produced by this
// implementation, so they are a regression guard, not an independent oracle —
// the independent part is the canonical request being readable against the
// reference.
package sign

import (
	"strings"
	"testing"
)

// ecsDescribeRegions is a realistic ECS DescribeRegions request in the shape
// the ext_proc adapter delivers: authority as ":authority", no literal "host"
// key, headers already lower-cased.
func ecsDescribeRegions() *RequestSnapshot {
	return &RequestSnapshot{
		Method: "POST",
		Scheme: "https",
		Host:   "ecs.cn-hangzhou.aliyuncs.com",
		Path:   "/",
		Headers: map[string]string{
			":authority":           "ecs.cn-hangzhou.aliyuncs.com",
			"content-type":         "application/x-www-form-urlencoded",
			"x-acs-action":         "DescribeRegions",
			"x-acs-version":        "2014-05-26",
			"x-acs-date":           "2026-05-24T10:00:00Z",
			"x-acs-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
}

// The canonical request, spelled out. Read it against the reference signer:
//
//	POST                     <- method, upper-cased
//	/                        <- canonical URI, empty path would be "/"
//	                         <- canonical query, empty here
//	content-type:...         <- canonical headers, lower-cased, sorted,
//	host:...                    trimmed, each terminated by "\n" — host is
//	x-acs-...                   present even though only ":authority" arrived
//	                         <- the blank line is that trailing "\n"
//	content-type;host;x-...  <- signed headers, same set, ";"-joined
//	e3b0c442...              <- hashed payload from x-acs-content-sha256
const wantECSCanonicalRequest = "POST\n" +
	"/\n" +
	"\n" +
	"content-type:application/x-www-form-urlencoded\n" +
	"host:ecs.cn-hangzhou.aliyuncs.com\n" +
	"x-acs-action:DescribeRegions\n" +
	"x-acs-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
	"x-acs-date:2026-05-24T10:00:00Z\n" +
	"x-acs-version:2014-05-26\n" +
	"\n" +
	"content-type;host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-version\n" +
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestV3CanonicalRequest_ConformsToSpecLayout(t *testing.T) {
	got, signedHeaders, err := v3CanonicalRequest(ecsDescribeRegions())
	if err != nil {
		t.Fatalf("v3CanonicalRequest: %v", err)
	}
	if got != wantECSCanonicalRequest {
		t.Errorf("canonical request differs from the pinned vector.\n got:\n%s\n\nwant:\n%s", got, wantECSCanonicalRequest)
	}
	// SignedHeaders must be exactly the header lines present above, in the same
	// order: the gateway rebuilds the canonical headers from this list.
	const wantSigned = "content-type;host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-version"
	if signedHeaders != wantSigned {
		t.Errorf("signedHeaders = %q, want %q", signedHeaders, wantSigned)
	}
	for _, name := range strings.Split(signedHeaders, ";") {
		if !strings.Contains(got, "\n"+name+":") {
			t.Errorf("header %q is listed in SignedHeaders but has no canonical line", name)
		}
	}
}

// A path and query exercise the canonicalization that the empty-path vector
// above cannot: URI normalization and the sorted, re-encoded canonical query.
func TestV3CanonicalRequest_NormalizesURIAndQuery(t *testing.T) {
	req := ecsDescribeRegions()
	req.Method = "get"
	req.Path = "/clusters/c-abc*x+y"
	req.RawQuery = "b=2&a=1&c=a%2fb"

	got, _, err := v3CanonicalRequest(req)
	if err != nil {
		t.Fatalf("v3CanonicalRequest: %v", err)
	}
	lines := strings.Split(got, "\n")
	// Method upper-cased, '*' -> %2A and '+' -> %20 per the reference signer.
	if lines[0] != "GET" {
		t.Errorf("method line = %q, want GET", lines[0])
	}
	if want := "/clusters/c-abc%2Ax%20y"; lines[1] != want {
		t.Errorf("canonical URI = %q, want %q", lines[1], want)
	}
	// Query sorted by key and re-encoded, so '/' becomes %2F.
	if want := "a=1&b=2&c=a%2Fb"; lines[2] != want {
		t.Errorf("canonical query = %q, want %q", lines[2], want)
	}
}

// The crypto chain over the canonical request: SHA-256 of it, the algorithm
// line, then HMAC-SHA256 with the secret, hex-encoded. Pinned so a refactor of
// the chain cannot pass silently. Produced by this implementation, so it guards
// against regression rather than proving spec conformance — the canonical
// request above carries that part.
func TestSignV3_PinnedSignatureForCanonicalVector(t *testing.T) {
	const wantSig = "f7590bbb8c19bf6217807652a9282a508867773f19820f677956dd601920308e"

	got, _, err := computeV3SignatureAndHeaders(ecsDescribeRegions(),
		Triplet{AccessKeyID: "AK", AccessKeySecret: "SECRET"})
	if err != nil {
		t.Fatalf("computeV3SignatureAndHeaders: %v", err)
	}
	if got != wantSig {
		t.Errorf("signature = %q, want the pinned %q\n"+
			"If the canonical-request test above still passes, the crypto chain changed; "+
			"re-pin deliberately. If it also fails, the canonicalization changed and this "+
			"is a spec-conformance regression.", got, wantSig)
	}
}
