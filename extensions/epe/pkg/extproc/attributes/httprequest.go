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
package attributes

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/logging"
)

const connectUDPMasquePrefix = "/.well-known/masque/udp/"

// splitHostPort extracts (host, port) from a request authority. IPv6
// authorities in bracket form (e.g. "[::1]:8080") are returned without the
// brackets and the trailing port. A non-numeric or out-of-range port is
// returned as 0 (no match for any non-empty Ports list).
func splitHostPort(authority string) (string, int32) {
	if authority == "" {
		return "", 0
	}
	if authority[0] == '[' {
		end := strings.IndexByte(authority, ']')
		if end <= 0 {
			return authority, 0
		}
		host := authority[1:end]
		if end+1 < len(authority) && authority[end+1] == ':' {
			return host, parsePort(authority[end+2:])
		}
		return host, 0
	}
	if idx := strings.IndexByte(authority, ':'); idx >= 0 {
		return authority[:idx], parsePort(authority[idx+1:])
	}
	return authority, 0
}

// parsePort returns the port number, or 0 when the input is empty,
// non-numeric, or out of the [1, 65535] range.
func parsePort(s string) int32 {
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 || v > 65535 {
		return 0
	}
	return int32(v)
}

// splitPathAndQuery separates the "/path" and "query=string" halves of a
// raw ":path" pseudo-header. The returned query is the verbatim text after
// the first "?" (empty when the path has no query).
func splitPathAndQuery(rawPath string) (string, string) {
	if idx := strings.IndexByte(rawPath, '?'); idx >= 0 {
		return rawPath[:idx], rawPath[idx+1:]
	}
	return rawPath, ""
}

// parseHTTPRequest extracts httpreq.HTTPRequest from Envoy header values.
// Envoy sends pseudo-headers (:method, :path, :authority, :scheme) and the
// Host header. :authority is the gRPC/HTTP2 equivalent of Host.
//
// Splits performed here:
//   - :authority "host:port"  -> Host, Port
//   - :path "/p?q=1"          -> Path, Query
//
// Port inference: when :authority does not include an explicit port, the
// default port is taken from :scheme — http=80, https=443. The :scheme
// value itself is stored on HTTPRequest.Scheme.
//
// Query-string parse errors are logged at DEBUG via the logger in ctx (the
// returned Query still holds whatever url.ParseQuery managed to extract).
func parseHTTPRequest(ctx context.Context, headers map[string]string) httpreq.HTTPRequest {
	info := httpreq.HTTPRequest{Headers: headers}

	if auth, ok := headers[":authority"]; ok && auth != "" {
		info.Host, info.Port = splitHostPort(auth)
	} else if host, ok := headers["host"]; ok && host != "" {
		info.Host, info.Port = splitHostPort(host)
	}

	if info.Port == 0 {
		info.Port = inferPortFromScheme(headers[":scheme"])
	}

	if path, ok := headers[":path"]; ok {
		var rawQuery string
		info.Path, rawQuery = splitPathAndQuery(path)
		info.RawQuery = rawQuery
		if rawQuery != "" {
			var err error
			info.Query, err = url.ParseQuery(rawQuery)
			if err != nil {
				log.FromContext(ctx).V(logging.DEBUG).Info(
					"Failed to parse request query string; using partial result",
					"rawQuery", rawQuery, "error", err.Error())
			}
		}
	}

	if method, ok := headers[":method"]; ok {
		info.Method = method
	}

	if scheme, ok := headers[":scheme"]; ok {
		info.Scheme = scheme
	}

	return info
}

// normalizeConnectUDPMasqueTarget projects an RFC 9298 CONNECT-UDP request onto
// the destination tuple understood by SecurityProfile. The outer HTTP authority
// names the Waypoint; the actual UDP host and port are carried in the MASQUE
// path. UDP has no application HTTP path or query to expose to policy.
func normalizeConnectUDPMasqueTarget(info *httpreq.HTTPRequest, routeName string) bool {
	// Envoy presents RFC 8441 extended CONNECT to HTTP filters in its internal
	// HTTP/1 upgrade form (GET + Upgrade: connect-udp). Accept native CONNECT as
	// well so the policy projection does not depend on that codec detail.
	methodIsConnect := strings.EqualFold(info.Method, "CONNECT")
	methodIsEnvoyUpgrade := strings.EqualFold(info.Method, "GET") &&
		strings.EqualFold(info.Headers["upgrade"], "connect-udp")
	if !strings.HasPrefix(routeName, "connect-udp:") ||
		(!methodIsConnect && !methodIsEnvoyUpgrade) ||
		info.Headers["capsule-protocol"] != "?1" ||
		!strings.HasPrefix(info.Path, connectUDPMasquePrefix) {
		return false
	}
	tail := strings.TrimPrefix(info.Path, connectUDPMasquePrefix)
	parts := strings.Split(tail, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] != "" {
		return false
	}
	host, err := url.PathUnescape(parts[0])
	if err != nil || host == "" || strings.ContainsAny(host, "/\\") {
		return false
	}
	portText, err := url.PathUnescape(parts[1])
	if err != nil {
		return false
	}
	port := parsePort(portText)
	if port == 0 {
		return false
	}
	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if !strings.EqualFold(routeName, "connect-udp:"+host+":"+strconv.Itoa(int(port))) {
		return false
	}

	info.Host = host
	info.Port = port
	info.Path = ""
	info.Query = nil
	info.RawQuery = ""
	info.Scheme = "udp"
	info.Method = "CONNECT"
	return true
}

// inferPortFromScheme returns the conventional default port for the scheme,
// or 0 when the scheme is empty or unrecognized.
func inferPortFromScheme(scheme string) int32 {
	switch strings.ToLower(scheme) {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}
