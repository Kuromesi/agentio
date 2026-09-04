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
	"sort"
	"strings"
)

// lowerHeaderKeys copies headers into a new map with lower-cased keys, so
// signers can add authorization headers to the copy and never mutate the
// caller's map.
func lowerHeaderKeys(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers)+2)
	for k, v := range headers {
		out[strings.ToLower(k)] = v
	}
	return out
}

// canonicalQuery returns the V3-style canonical query string built from
// rawQuery. Keys and values are individually percent-encoded with the
// Aliyun-specific RFC3986 ruleset; entries are sorted by key, then by
// value for repeated keys; an empty value is rendered as "k=". Returns
// "" when rawQuery is empty.
func canonicalQuery(rawQuery string) (string, error) {
	if rawQuery == "" {
		return "", nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", err
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		vs := values[k]
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
	return b.String(), nil
}

// percentEncode applies Aliyun's RFC3986 encoding: same as
// url.QueryEscape but '+' becomes "%20", '*' becomes "%2A", and "%7E"
// is decoded back to '~'.
func percentEncode(s string) string {
	escaped := url.QueryEscape(s)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "*", "%2A")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	return escaped
}

// hostHeader is the canonical spelling of the authority in a signed header
// set. Envoy delivers it as the ":authority" pseudo-header instead.
const hostHeader = "host"

// authorityPseudoHeader is how HTTP/2 — and Envoy's internal header map for
// HTTP/1.1 too — spells the authority.
const authorityPseudoHeader = ":authority"

// hostOf returns the request authority as it arrived on the wire.
//
// The pseudo-header wins over the snapshot's Host field, because
// attributes.splitHostPort peels the port off into HTTPRequest.Port and leaves
// Host bare. The gateway canonicalizes the authority it received, port and all,
// so signing the port-less form would diverge for any request sent to an
// explicit port — the same class of mismatch as signing no host at all.
func hostOf(req *RequestSnapshot) string {
	if a := req.Headers[authorityPseudoHeader]; a != "" {
		return a
	}
	return req.Host
}

// canonicalHeaders builds the (canonicalHeadersBlock, signedHeadersList)
// pair from req.Headers, including only headers whose lower-cased name
// matches predicate. Header values are lower-cased-name : trimmed-value,
// sorted, terminated by "\n". signedHeadersList is the same set as a
// semicolon-joined string.
func canonicalHeaders(req *RequestSnapshot, predicate func(name string) bool) (string, string) {
	type kv struct{ k, v string }
	var pairs []kv
	sawHost := false
	for name, val := range req.Headers {
		lname := strings.ToLower(name)
		if lname == hostHeader {
			sawHost = true
		}
		if !predicate(lname) {
			continue
		}
		pairs = append(pairs, kv{lname, strings.TrimSpace(val)})
	}
	// Envoy delivers the authority as the ":authority" pseudo-header — its
	// header map maps the legacy "host" key onto the same inline slot — so a
	// literal "host" key is absent from ext_proc's map for HTTP/1.1 and
	// HTTP/2 alike. A scheme that signs host must therefore take it from the
	// snapshot, or it would sign a canonical request the gateway cannot
	// reproduce from the request it received.
	if !sawHost && predicate(hostHeader) {
		if host := strings.TrimSpace(hostOf(req)); host != "" {
			pairs = append(pairs, kv{hostHeader, host})
		}
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })

	var cb, sb strings.Builder
	for i, p := range pairs {
		cb.WriteString(p.k)
		cb.WriteByte(':')
		cb.WriteString(p.v)
		cb.WriteByte('\n')
		if i > 0 {
			sb.WriteByte(';')
		}
		sb.WriteString(p.k)
	}
	return cb.String(), sb.String()
}

// acsHeaderPredicate selects headers that participate in V3 canonical headers:
// host, content-type, and any "x-acs-*". Only SignV3 uses it — V1-ROA builds
// its signed set in computeV1ROASignature and does not go through
// canonicalHeaders, so changes here do not reach it.
func acsHeaderPredicate(name string) bool {
	if name == "host" || name == "content-type" {
		return true
	}
	return strings.HasPrefix(name, "x-acs-")
}

// ossHeaderPredicate selects headers for OSS V4 canonical headers:
// content-type, content-md5, and any "x-oss-*". These are exactly OSS V4's
// default signed headers, per both official SDKs (oss2's DEFAULT_SIGNED_HEADERS
// and the Go SDK's isDefaultSignedHeader, plus the x-oss-* rule).
//
// host is deliberately NOT signed: OSS V4 signs it only when it is declared in
// the Authorization AdditionalHeaders segment, and signing it without declaring
// it would make the canonical request diverge from the server's. Envoy delivers
// the authority as the ":authority" pseudo-header, so a literal "host" key is
// usually absent; the predicate is deliberately strict so behaviour does not
// depend on which spelling arrives.
func ossHeaderPredicate(name string) bool {
	if name == "content-md5" || name == "content-type" {
		return true
	}
	return strings.HasPrefix(name, "x-oss-")
}
