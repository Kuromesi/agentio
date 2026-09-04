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
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// SignV1ROA implements the V1 ROA HMAC-SHA1 scheme. The Authorization
// header is rebuilt as "acs <AK>:<Base64Signature>" and x-acs-* headers
// (notably x-acs-security-token) are swapped to the new triplet.
func SignV1ROA(req *RequestSnapshot, t Triplet) (*ResignResult, error) {
	if err := validateV1ROARequest(req, t); err != nil {
		return nil, err
	}

	sig, err := computeV1ROASignature(req, t)
	if err != nil {
		return nil, err
	}

	out := &ResignResult{
		SetHeaders: []HeaderKV{
			{Name: "Authorization", Value: "acs " + t.AccessKeyID + ":" + sig},
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

// computeV1ROASignature is the test-visible wrapper that recomputes the
// base64 HMAC-SHA1 signature from req+triplet. It patches x-acs-security-token
// with the new triplet value before canonicalization so callers can pass the
// original request snapshot and still get the same signature SignV1ROA
// produces.
func computeV1ROASignature(req *RequestSnapshot, t Triplet) (string, error) {
	if err := validateV1ROARequest(req, t); err != nil {
		return "", err
	}
	headers := lowerHeaderKeys(req.Headers)
	if t.SecurityToken != "" {
		headers["x-acs-security-token"] = t.SecurityToken
	} else {
		delete(headers, "x-acs-security-token")
	}
	patched := *req
	patched.Headers = headers
	return computeV1ROASignatureRaw(&patched, t)
}

func validateV1ROARequest(req *RequestSnapshot, t Triplet) error {
	if req == nil {
		return fmt.Errorf("v1roa: nil request snapshot")
	}
	if t.AccessKeySecret == "" {
		return fmt.Errorf("v1roa: empty AccessKeySecret in triplet")
	}
	return nil
}

func computeV1ROASignatureRaw(req *RequestSnapshot, t Triplet) (string, error) {
	// CanonicalizedHeaders: every "x-acs-*" header, lower-cased, sorted,
	// joined as "name:value\n".
	type kv struct{ k, v string }
	var acs []kv
	for name, val := range req.Headers {
		ln := strings.ToLower(name)
		if !strings.HasPrefix(ln, "x-acs-") {
			continue
		}
		acs = append(acs, kv{ln, strings.TrimSpace(val)})
	}
	sort.Slice(acs, func(i, j int) bool { return acs[i].k < acs[j].k })
	var ch strings.Builder
	for _, p := range acs {
		ch.WriteString(p.k)
		ch.WriteByte(':')
		ch.WriteString(p.v)
		ch.WriteByte('\n')
	}

	// CanonicalizedResource: path + sorted query
	cr := req.Path
	if req.RawQuery != "" {
		vals, err := url.ParseQuery(req.RawQuery)
		if err != nil {
			return "", fmt.Errorf("v1roa: canonical query: %w", err)
		}
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var qb strings.Builder
		for i, k := range keys {
			vs := vals[k]
			sort.Strings(vs)
			for j, v := range vs {
				if i > 0 || j > 0 {
					qb.WriteByte('&')
				}
				qb.WriteString(k)
				if v != "" {
					qb.WriteByte('=')
					qb.WriteString(v)
				}
			}
		}
		cr += "?" + qb.String()
	}

	stringToSign := strings.Join([]string{
		strings.ToUpper(req.Method),
		req.Headers["accept"],
		req.Headers["content-md5"],
		req.Headers["content-type"],
		req.Headers["date"],
		ch.String() + cr,
	}, "\n")

	mac := hmac.New(sha1.New, []byte(t.AccessKeySecret))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
