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
	"net/url"
	"sort"
	"strings"
)

const upperHex = "0123456789ABCDEF"

const ossV4Algorithm = "OSS4-HMAC-SHA256"
const ossV4Service = "oss"

// OSSV4Params carries OSS-V4-specific knobs that aren't in the request
// snapshot. The Resign dispatcher extracts these from the incoming
// Authorization header: Region from the Credential= field and
// AdditionalHeaders from the AdditionalHeaders= field.
type OSSV4Params struct {
	Region string
	// AdditionalHeaders are the non-default header names the client chose
	// to include in its signature, as declared in the original
	// Authorization "AdditionalHeaders=" segment. They must be carried
	// through re-signing verbatim: the OSS server reads this segment to
	// decide which extra headers to canonicalize, so dropping it (or
	// adding to it) changes the server's canonical request. Names are
	// lower-cased and filtered the same way the official SDK does.
	AdditionalHeaders []string
}

// SignOSSV4 implements the OSS V4 scheme. Differences from V3:
//   - algorithm prefix is OSS4-HMAC-SHA256
//   - canonical headers include x-oss-* (not x-acs-*)
//   - x-oss-content-sha256 may be "UNSIGNED-PAYLOAD" (treated as-is)
//   - signing key is derived through 4 nested HMACs from the date,
//     region and service ("oss")
func SignOSSV4(req *RequestSnapshot, t Triplet, p OSSV4Params) (*ResignResult, error) {
	if req == nil {
		return nil, fmt.Errorf("ossv4: nil request snapshot")
	}
	if t.AccessKeySecret == "" {
		return nil, fmt.Errorf("ossv4: empty AccessKeySecret in triplet")
	}
	if p.Region == "" {
		return nil, fmt.Errorf("ossv4: empty region")
	}

	// Lower-case the header keys up front so both validation and
	// canonicalization are insensitive to the wire casing. Envoy lower-cases
	// headers in production, but the signer must not silently depend on it.
	headers := lowerHeaderKeys(req.Headers)
	if len(headers["x-oss-date"]) < 8 {
		return nil, fmt.Errorf("ossv4: x-oss-date header too short or missing (got %q)", headers["x-oss-date"])
	}
	if t.SecurityToken != "" {
		headers["x-oss-security-token"] = t.SecurityToken
	} else {
		delete(headers, "x-oss-security-token")
	}
	patched := *req
	patched.Headers = headers

	sig, signedHeaders, err := computeOSSV4SignatureAndHeaders(&patched, t, p)
	if err != nil {
		return nil, err
	}

	datePart := headers["x-oss-date"][:8] // YYYYMMDD prefix of YYYYMMDDTHHMMSSZ
	scope := fmt.Sprintf("%s/%s/%s/aliyun_v4_request", datePart, p.Region, ossV4Service)
	authz := fmt.Sprintf("%s Credential=%s/%s,Signature=%s",
		ossV4Algorithm, t.AccessKeyID, scope, sig)
	// Aliyun's OSS server rejects an empty "AdditionalHeaders=" segment
	// with "Authorization header value is empty". Match the official
	// SDK's behaviour: emit the segment only when the client declared
	// additional headers, and echo exactly the (filtered, sorted) set that
	// participated in the signature.
	if signedHeaders != "" {
		authz += ",AdditionalHeaders=" + signedHeaders
	}

	out := &ResignResult{
		SetHeaders: []HeaderKV{
			{Name: "Authorization", Value: authz},
		},
	}
	if t.SecurityToken != "" {
		out.SetHeaders = append(out.SetHeaders,
			HeaderKV{Name: "x-oss-security-token", Value: t.SecurityToken})
	} else {
		out.RemoveHeaders = append(out.RemoveHeaders, "x-oss-security-token")
	}
	return out, nil
}

// computeOSSV4Signature is the test-visible wrapper that returns only the
// signature hex string. It patches x-oss-security-token with the triplet
// value before canonicalization so callers can pass the original request
// snapshot and still get the same signature SignOSSV4 produces.
func computeOSSV4Signature(req *RequestSnapshot, t Triplet, p OSSV4Params) (string, error) {
	headers := lowerHeaderKeys(req.Headers)
	if t.SecurityToken != "" {
		headers["x-oss-security-token"] = t.SecurityToken
	} else {
		delete(headers, "x-oss-security-token")
	}
	patched := *req
	patched.Headers = headers
	sig, _, err := computeOSSV4SignatureAndHeaders(&patched, t, p)
	return sig, err
}

// computeOSSV4SignatureAndHeaders returns (signature, additionalHeadersList).
// additionalHeadersList is the ";"-joined, filtered and sorted set of
// client-declared extra headers that goes both into the canonical request's
// AdditionalHeaders line and into the Authorization AdditionalHeaders= segment
// (empty when the client declared none).
func computeOSSV4SignatureAndHeaders(req *RequestSnapshot, t Triplet, p OSSV4Params) (string, string, error) {
	canonQuery := ossV4CanonicalQuery(req.RawQuery)
	additional := normalizeOSSV4AdditionalHeaders(p.AdditionalHeaders)
	canonHeaders, _ := canonicalHeaders(req, ossV4HeaderPredicate(additional))
	additionalList := strings.Join(additional, ";")
	// The payload-hash line is taken from the header as-is; the signer never
	// rewrites it. OSS V4 header-mode signing accepts exactly one value here —
	// anything else is refused before authentication matters, with
	// 400 InvalidArgument / EC 0002-00000214 "The x-oss-content-sha256 only
	// supports UNSIGNED-PAYLOAD". So this line is a fixed sentinel, NOT a digest
	// of the body: OSS V4 signatures do not cover the request body at all. Body
	// integrity comes from Content-MD5, which is in the default signed header
	// set and therefore already protected here.
	//
	// The official SDKs overwrite this header because they construct the request;
	// this signer re-signs someone else's, so it does not correct an illegal
	// value on the client's behalf — that request earns the service's own 400
	// either way, and rewriting it would mask a client bug. The fallback below
	// only covers a client that omitted the header entirely.
	hashedPayload := req.Headers["x-oss-content-sha256"]
	if hashedPayload == "" {
		hashedPayload = "UNSIGNED-PAYLOAD"
	}

	canonicalRequest := strings.Join([]string{
		strings.ToUpper(req.Method),
		ossCanonicalResource(req.Host, req.Path),
		canonQuery,
		canonHeaders,
		additionalList, // empty unless the client declared AdditionalHeaders
		hashedPayload,
	}, "\n")

	crHash := sha256.Sum256([]byte(canonicalRequest))
	dateStamp := req.Headers["x-oss-date"][:8]
	scope := fmt.Sprintf("%s/%s/%s/aliyun_v4_request", dateStamp, p.Region, ossV4Service)
	stringToSign := strings.Join([]string{
		ossV4Algorithm,
		req.Headers["x-oss-date"],
		scope,
		hex.EncodeToString(crHash[:]),
	}, "\n")

	signingKey := deriveOSSV4SigningKey(t.AccessKeySecret, dateStamp, p.Region)
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(stringToSign))
	return hex.EncodeToString(mac.Sum(nil)), additionalList, nil
}

func deriveOSSV4SigningKey(secret, dateStamp, region string) []byte {
	kDate := hmacSHA256([]byte("aliyun_v4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(ossV4Service))
	return hmacSHA256(kService, []byte("aliyun_v4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// ossCanonicalResource returns the OSS V4 canonical URI. OSS V4 always signs
// the bucket-qualified resource "/<bucket>/<key>" — the same form the official
// SDK (oss2) and the OSS server compute — regardless of addressing style.
//
// Two normalizations are required to match the server:
//
//  1. Encoding: oss2 puts the object key on the wire percent-encoded with NO
//     safe characters (so '/' becomes "%2F"), but signs the canonical URI
//     using OSS V4 encoding that PRESERVES '/'. The server decodes the wire
//     path and re-canonicalizes the same way. Envoy hands us the raw wire
//     path, so we url-decode it and re-encode per OSS V4 rules with '/' kept.
//     Signing the raw "%2F" form yields SignatureDoesNotMatch on every keyed
//     object request.
//
//  2. Bucket: for virtual-hosted-style requests the bucket lives in the Host
//     header while Envoy's :path carries only "/<key>", so the bucket is
//     spliced back in. For path-style / service requests the bucket is already
//     the first path segment (or there is no bucket), so it is left as-is.
//     Bucket names are DNS-safe (RFC3986-unreserved), so prefixing is
//     encoding-neutral.
func ossCanonicalResource(host, rawPath string) string {
	// url.PathUnescape decodes %-escapes but, unlike QueryUnescape, leaves '+'
	// as a literal '+' — matching how the OSS server decodes a path. Fall back
	// to the raw path if it is not valid percent-encoding.
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		decoded = rawPath
	}
	if decoded == "" {
		decoded = "/"
	}
	canonicalKey := ossV4EncodeResourcePath(decoded)
	bucket := virtualHostedBucket(host)
	if bucket == "" {
		return canonicalKey
	}
	return "/" + bucket + canonicalKey
}

// ossV4CanonicalQuery builds the OSS V4 canonical query string from the raw
// wire query. It deliberately does NOT reuse canonicalQuery (the V3 / V1-ROA
// helper), because OSS V4 differs on two points that both change the signature:
//
//   - A parameter with an empty value is rendered as bare "k", NOT "k=".
//     Emitting "k=" breaks every OSS sub-resource API (?acl, ?uploads,
//     ?delete, ?append, ?restore, ?symlink, …).
//   - Key/value text is taken from the wire VERBATIM, with only "+" folded to
//     "%20"; entries are then sorted by that verbatim key.
//
// The verbatim rule mirrors the official Go SDK's
// SignerV4.calcCanonicalRequest. The server also accepts a normalized form,
// so this is deliberate alignment with the reference implementation rather
// than a home-grown normalization that could drift from it.
//
// Repeated keys keep every value (sorted by key, then value). The Go SDK
// collapses them into a map, which makes "a=1&a=2" sign as "a=2&a=2"; keeping
// both values is the more defensible reading and is equivalent whenever keys
// are unique, which is the case for all real OSS APIs.
func ossV4CanonicalQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	// OSS V4 treats "+" in the query as an encoded space and signs it as %20.
	rawQuery = strings.ReplaceAll(rawQuery, "+", "%20")
	type kv struct {
		k, v     string
		hasValue bool
	}
	var pairs []kv
	for seg := range strings.SplitSeq(rawQuery, "&") {
		if seg == "" {
			continue
		}
		key, val, _ := strings.Cut(seg, "=")
		// An empty value is "no value", so "?acl" and "?acl=" both
		// canonicalize to "acl".
		pairs = append(pairs, kv{k: key, v: val, hasValue: val != ""})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})

	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.k)
		if p.hasValue {
			b.WriteByte('=')
			b.WriteString(p.v)
		}
	}
	return b.String()
}

// normalizeOSSV4AdditionalHeaders lower-cases, de-duplicates and sorts the
// client-declared additional header names, dropping any that OSS V4 signs by
// default anyway (x-oss-*, content-type, content-md5). This mirrors the
// official SDK's __get_additional_signed_headers, so the list we echo in
// Authorization is exactly the list the server will canonicalize.
func normalizeOSSV4AdditionalHeaders(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		name := strings.ToLower(strings.TrimSpace(n))
		if name == "" || ossHeaderPredicate(name) {
			continue // already signed by default; the SDK filters these out
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// ossV4HeaderPredicate returns a canonicalHeaders predicate that selects the
// OSS V4 default set plus the given (already normalized) additional headers.
func ossV4HeaderPredicate(additional []string) func(string) bool {
	if len(additional) == 0 {
		return ossHeaderPredicate
	}
	extra := make(map[string]struct{}, len(additional))
	for _, n := range additional {
		extra[n] = struct{}{}
	}
	return func(name string) bool {
		if ossHeaderPredicate(name) {
			return true
		}
		_, ok := extra[name]
		return ok
	}
}

// ossV4EncodeResourcePath applies OSS V4's URI encoding to the canonical
// resource path: every byte is percent-encoded except the RFC3986 unreserved
// set (A-Za-z0-9-_.~) and '/', which stays literal. Encoding is byte-wise so
// multi-byte UTF-8 keys are handled correctly. Mirrors the official Go SDK's
// escapePath(path, encodeSep=false) and oss2's __v4_uri_encode(…, True).
//
// Note the deliberate asymmetry with ossV4CanonicalQuery, which signs the wire
// text verbatim instead of decoding and re-encoding. It is not an oversight:
//   - The path MUST be decoded then re-encoded. The object key is a semantic
//     value; the wire form carries it fully escaped ("/" as "%2F") while the
//     signed form keeps "/" literal, so skipping the round-trip mismatches the
//     server. This one is load-bearing.
//   - The query follows the reference SDK, which takes it verbatim. Empirically
//     the server also accepts a normalized query, so this side is about
//     matching the reference implementation rather than about correctness.
//
// Both behaviours are pinned by golden vectors (oss2 for the path, the Go SDK
// for the query).
func ossV4EncodeResourcePath(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '_', c == '-', c == '~', c == '.', c == '/':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&0x0f])
		}
	}
	return b.String()
}

// virtualHostedBucket extracts the bucket name from a virtual-hosted-style OSS
// host, or returns "" when the host carries no bucket prefix (path-style /
// service endpoint) or is not a recognizable OSS endpoint (custom domain).
//
// The decision is made on label positions rather than a prefix match, because
// OSS has two structurally different endpoint families. Per the official
// endpoint reference (OSS user guide, "通过Endpoint和Bucket域名访问OSS"):
//
//	public      oss-<region>.aliyuncs.com           <bucket>.oss-<region>.aliyuncs.com
//	internal    oss-<region>-internal.aliyuncs.com  <bucket>.oss-<region>-internal.aliyuncs.com
//	accelerate  oss-accelerate.aliyuncs.com         <bucket>.oss-accelerate.aliyuncs.com
//	dual-stack  <region>.oss.aliyuncs.com           <bucket>.<region>.oss.aliyuncs.com
//
// The dual-stack family puts the region FIRST and a bare "oss" label second, so
// a prefix test on the remainder gets both cases wrong: it reads
// "<region>.oss.aliyuncs.com" as bucket=<region> (fabricating a path segment)
// and misses the bucket in "<bucket>.<region>.oss.aliyuncs.com" (dropping the
// real one). Either way the canonical resource differs from the server's and the
// request fails with SignatureDoesNotMatch.
//
// Custom domains (CNAME) return "" and remain a deliberate gap: such a host
// carries no bucket, so it cannot be recovered here.
//
// The host is already port-stripped by matcher.ParseRequestInfo.
func virtualHostedBucket(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) < 3 {
		return "" // too short to be any OSS endpoint
	}
	// First label is the endpoint itself => path-style, no bucket prefix.
	if strings.HasPrefix(labels[0], "oss-") {
		return ""
	}
	// "<region>.oss.aliyuncs.com" => dual-stack service endpoint, no bucket.
	if labels[1] == "oss" {
		return ""
	}
	// "<bucket>.oss-<region>[-internal]|oss-accelerate.aliyuncs.com"
	if strings.HasPrefix(labels[1], "oss-") {
		return labels[0]
	}
	// "<bucket>.<region>.oss.aliyuncs.com" => dual-stack virtual-hosted.
	if labels[2] == "oss" {
		return labels[0]
	}
	return ""
}
