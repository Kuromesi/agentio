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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const v3Algorithm = "ACS3-HMAC-SHA256"

// SignV3 swaps the triplet into req and returns the ResignResult.
// SetHeaders contains the rewritten Authorization, x-acs-accesskey-id,
// x-acs-security-token; RemoveHeaders / NewPath are empty.
func SignV3(req *RequestSnapshot, t Triplet) (*ResignResult, error) {
	if err := validateV3Request(req, t); err != nil {
		return nil, err
	}

	// Build a request copy with the new triplet headers in place so the
	// canonical headers reflect the values we are about to send. We
	// don't mutate the caller's map.
	headers := make(map[string]string, len(req.Headers)+2)
	for k, v := range req.Headers {
		headers[strings.ToLower(k)] = v
	}
	headers["x-acs-accesskey-id"] = t.AccessKeyID
	if t.SecurityToken != "" {
		headers["x-acs-security-token"] = t.SecurityToken
	} else {
		delete(headers, "x-acs-security-token")
	}
	patched := *req
	patched.Headers = headers

	sig, signedHeaders, err := computeV3SignatureAndHeaders(&patched, t)
	if err != nil {
		return nil, err
	}

	authz := fmt.Sprintf("%s Credential=%s,SignedHeaders=%s,Signature=%s",
		v3Algorithm, t.AccessKeyID, signedHeaders, sig)

	out := &ResignResult{
		SetHeaders: []HeaderKV{
			{Name: "Authorization", Value: authz},
			{Name: "x-acs-accesskey-id", Value: t.AccessKeyID},
		},
	}
	if t.SecurityToken != "" {
		out.SetHeaders = append(out.SetHeaders,
			HeaderKV{Name: "x-acs-security-token", Value: t.SecurityToken})
	} else {
		out.RemoveHeaders = append(out.RemoveHeaders, "x-acs-security-token")
	}
	return out, nil
}

// computeV3Signature is the test-visible wrapper that returns only the
// signature hex string, for use in golden-test assertions.
func computeV3Signature(req *RequestSnapshot, t Triplet) (string, error) {
	if err := validateV3Request(req, t); err != nil {
		return "", err
	}
	headers := make(map[string]string, len(req.Headers)+2)
	for k, v := range req.Headers {
		headers[strings.ToLower(k)] = v
	}
	headers["x-acs-accesskey-id"] = t.AccessKeyID
	if t.SecurityToken != "" {
		headers["x-acs-security-token"] = t.SecurityToken
	}
	patched := *req
	patched.Headers = headers
	sig, _, err := computeV3SignatureAndHeaders(&patched, t)
	return sig, err
}

// v3CanonicalRequest assembles the canonical request V3 signs, and returns it
// alongside the SignedHeaders list that has to be echoed in Authorization.
//
// This is where every spec-conformance decision lives — which headers are
// signed, how the URI and query are canonicalized, the component order and the
// "\n" separator — so it is split out from the crypto below to be assertable on
// its own. The layout mirrors the reference signer
// (alibabacloud-go/openapi-util service.go GetAuthorization):
//
//	method \n canonicalURI \n canonicalQueryString \n
//	canonicalHeaders \n signedHeaders \n hashedPayload
func v3CanonicalRequest(req *RequestSnapshot) (canonicalRequest, signedHeaders string, err error) {
	canonQuery, err := canonicalQuery(req.RawQuery)
	if err != nil {
		return "", "", fmt.Errorf("v3: canonical query: %w", err)
	}
	canonHeaders, signedHeaders := canonicalHeaders(req, acsHeaderPredicate)

	return strings.Join([]string{
		strings.ToUpper(req.Method),
		v3CanonicalURI(req.Path),
		canonQuery,
		canonHeaders,
		signedHeaders,
		req.Headers["x-acs-content-sha256"], // hashed payload
	}, "\n"), signedHeaders, nil
}

func computeV3SignatureAndHeaders(req *RequestSnapshot, t Triplet) (string, string, error) {
	canonicalRequest, signedHeaders, err := v3CanonicalRequest(req)
	if err != nil {
		return "", "", err
	}

	crHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := v3Algorithm + "\n" + hex.EncodeToString(crHash[:])

	mac := hmac.New(sha256.New, []byte(t.AccessKeySecret))
	mac.Write([]byte(stringToSign))
	return hex.EncodeToString(mac.Sum(nil)), signedHeaders, nil
}

// v3CanonicalURI normalizes the request path the way the reference signer does
// (alibabacloud-go/openapi-util GetAuthorization): '+' becomes %20, '*' becomes
// %2A, and an escaped tilde becomes literal '~'. The gateway applies the same
// normalization to the path it received before recomputing the signature, so
// signing the raw wire path diverges for any path carrying those characters.
//
// The path is otherwise signed as received: it is already percent-encoded on
// the wire, and re-encoding it would double-escape.
func v3CanonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	path = strings.ReplaceAll(path, "+", "%20")
	path = strings.ReplaceAll(path, "*", "%2A")
	return strings.ReplaceAll(path, "%7E", "~")
}

func validateV3Request(req *RequestSnapshot, t Triplet) error {
	if req == nil {
		return fmt.Errorf("v3: nil request snapshot")
	}
	if t.AccessKeySecret == "" {
		return fmt.Errorf("v3: empty AccessKeySecret in triplet")
	}
	if req.Headers["x-acs-content-sha256"] == "" {
		return fmt.Errorf("v3: missing required header x-acs-content-sha256")
	}
	return nil
}
