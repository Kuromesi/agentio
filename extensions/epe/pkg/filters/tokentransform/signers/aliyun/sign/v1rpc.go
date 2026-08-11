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

// SignV1RPC implements the V1 RPC HMAC-SHA1 scheme. The new Signature
// goes back into the query string (which the dispatcher surfaces to
// Envoy via ResignResult.NewPath = path + "?" + new query). Form bodies
// on POST requests merge into the signing parameter set.
func SignV1RPC(req *RequestSnapshot, t Triplet) (*ResignResult, error) {
	if req == nil {
		return nil, fmt.Errorf("v1rpc: nil request snapshot")
	}
	if t.AccessKeySecret == "" {
		return nil, fmt.Errorf("v1rpc: empty AccessKeySecret in triplet")
	}

	q, err := url.ParseQuery(req.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("v1rpc: parse query: %w", err)
	}
	q.Set("AccessKeyId", t.AccessKeyID)
	if t.SecurityToken != "" {
		q.Set("SecurityToken", t.SecurityToken)
	} else {
		q.Del("SecurityToken")
	}
	q.Del("Signature")

	signParams := cloneValues(q)
	if strings.EqualFold(req.Method, "POST") &&
		isFormContentType(req.Headers["content-type"]) &&
		len(req.Body) > 0 {
		form, err := url.ParseQuery(string(req.Body))
		if err != nil {
			return nil, fmt.Errorf("v1rpc: parse form body: %w", err)
		}
		mergeValues(signParams, form)
	}

	sig, err := computeV1RPCSignatureFromParams(req.Method, signParams, t.AccessKeySecret)
	if err != nil {
		return nil, err
	}
	q.Set("Signature", sig)

	newPath := req.Path + "?" + q.Encode()
	return &ResignResult{NewPath: &newPath}, nil
}

// computeV1RPCSignatureFromParams runs the V1 RPC signature over the
// already-merged parameter set (query + optional form body). Exposed
// for tests that want to recompute the reference value. The "Signature"
// key is stripped from a local clone so callers can pass a fully-formed
// query (even one that already carries a Signature) and still get the
// canonical signing string.
func computeV1RPCSignatureFromParams(method string, params url.Values, secret string) (string, error) {
	working := cloneValues(params)
	working.Del("Signature")

	keys := make([]string, 0, len(working))
	for k := range working {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		vs := working[k]
		sort.Strings(vs)
		for _, v := range vs {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(percentEncode(k))
			b.WriteByte('=')
			b.WriteString(percentEncode(v))
		}
	}
	stringToSign := strings.ToUpper(method) + "&" + percentEncode("/") + "&" + percentEncode(b.String())

	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// computeV1RPCSignatureFromMerged is the form-body convenience for tests:
// merges body into the query params and delegates to the params variant.
func computeV1RPCSignatureFromMerged(method string, query url.Values, secret string, body []byte) (string, error) {
	merged := cloneValues(query)
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return "", err
	}
	mergeValues(merged, form)
	merged.Del("Signature")
	return computeV1RPCSignatureFromParams(method, merged, secret)
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func mergeValues(dst, src url.Values) {
	for k, vs := range src {
		dst[k] = append(dst[k], vs...)
	}
}

func isFormContentType(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded")
}
