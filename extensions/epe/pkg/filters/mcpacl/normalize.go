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

// Request-body normalization. The ACL must read the same message the upstream
// MCP server will act on, so content coding and byte-order marks are undone
// before parsing: an encoding this filter cannot read but a mainstream JSON
// stack can is a way to hide a tool call from the policy.
package mcpacl

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// maxDecodedBodyBytes caps the decompressed body. Envoy already bounds the
// wire body by the connection buffer limit, so this exists to stop a small
// compressed payload from expanding without limit. A JSON-RPC tool call is
// orders of magnitude smaller; a body that needs more than this cannot be
// read, and an unreadable body is denied.
const maxDecodedBodyBytes = 8 << 20

// contentEncodingHeader carries the content coding applied to the body. Header
// map keys are lowercased by the request handler.
const contentEncodingHeader = "content-encoding"

// maxContentCodings caps how many codings one body may declare. Every coding is
// another decompression pass over up to maxDecodedBodyBytes, and the list comes
// straight from a client-supplied header, so an uncapped chain
// ("gzip, gzip, gzip, ...") buys unbounded CPU with a tiny body. Real clients
// send one coding; two would already be unusual.
const maxContentCodings = 2

// normalizeBody returns the body as UTF-8 JSON text, undoing any content
// coding and byte-order mark. ok is false when the declared coding cannot be
// decoded, the decoded body exceeds maxDecodedBodyBytes, or the bytes are not
// valid text — all cases where this filter cannot see what the upstream would
// act on, so the caller denies rather than guesses.
func normalizeBody(headers map[string]string, body []byte) (out []byte, ok bool) {
	decoded, ok := decodeContentEncoding(headers[contentEncodingHeader], body)
	if !ok {
		return nil, false
	}
	return decodeText(decoded)
}

// decodeContentEncoding undoes the Content-Encoding chain. Codings are applied
// in the order listed, so they are undone in reverse. "identity" and an absent
// header pass through untouched.
func decodeContentEncoding(header string, body []byte) ([]byte, bool) {
	if strings.TrimSpace(header) == "" || len(body) == 0 {
		return body, true
	}
	codings := strings.Split(header, ",")
	if len(codings) > maxContentCodings {
		return nil, false
	}
	for i := len(codings) - 1; i >= 0; i-- {
		coding := strings.ToLower(strings.TrimSpace(codings[i]))
		switch coding {
		case "", "identity":
			continue
		case "gzip", "x-gzip":
			zr, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				return nil, false
			}
			decoded, ok := readCapped(zr)
			zr.Close()
			if !ok {
				return nil, false
			}
			body = decoded
		case "deflate":
			// RFC 7230 "deflate" is zlib-wrapped, but bare deflate streams are
			// common enough in the wild that both are tried.
			decoded, ok := inflate(body)
			if !ok {
				return nil, false
			}
			body = decoded
		default:
			// A coding this filter cannot undo (br, zstd, ...). The upstream
			// may well decode it, so the body is not readable here and the
			// caller must not pass it through unjudged.
			return nil, false
		}
	}
	return body, true
}

func inflate(body []byte) ([]byte, bool) {
	if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
		decoded, ok := readCapped(zr)
		zr.Close()
		if ok {
			return decoded, true
		}
		return nil, false
	}
	fr := flate.NewReader(bytes.NewReader(body))
	defer fr.Close()
	return readCapped(fr)
}

// readCapped reads at most maxDecodedBodyBytes. A stream that has more to give
// is rejected rather than truncated: judging a prefix of a body the upstream
// will read in full is the same hazard as not judging it at all.
func readCapped(r io.Reader) ([]byte, bool) {
	decoded, err := io.ReadAll(io.LimitReader(r, maxDecodedBodyBytes+1))
	if err != nil {
		return nil, false
	}
	if len(decoded) > maxDecodedBodyBytes {
		return nil, false
	}
	return decoded, true
}

// decodeText strips a byte-order mark and transcodes UTF-16 to UTF-8. MCP
// mandates UTF-8, but Go's JSON decoder rejects a leading BOM that
// System.Text.Json and Jackson skip, and Jackson auto-detects BOM-marked
// UTF-16 — so a BOM would otherwise hide the message from this ACL while the
// upstream read it fine.
func decodeText(body []byte) ([]byte, bool) {
	switch {
	case bytes.HasPrefix(body, []byte{0xEF, 0xBB, 0xBF}):
		body = body[3:]
	case bytes.HasPrefix(body, []byte{0xFF, 0xFE}):
		return utf16ToUTF8(body[2:], binary.LittleEndian)
	case bytes.HasPrefix(body, []byte{0xFE, 0xFF}):
		return utf16ToUTF8(body[2:], binary.BigEndian)
	}
	// Invalid UTF-8 cannot be the JSON text the upstream parses, and guessing
	// an encoding would reintroduce the very ambiguity this function removes.
	if !utf8.Valid(body) {
		return nil, false
	}
	return body, true
}

func utf16ToUTF8(body []byte, order binary.ByteOrder) ([]byte, bool) {
	if len(body)%2 != 0 {
		return nil, false
	}
	units := make([]uint16, 0, len(body)/2)
	for i := 0; i < len(body); i += 2 {
		units = append(units, order.Uint16(body[i:i+2]))
	}
	return []byte(string(utf16.Decode(units))), true
}
