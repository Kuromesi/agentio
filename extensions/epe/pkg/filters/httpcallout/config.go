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

// Package httpcallout defines the contract for delegating one HTTP exchange to
// an external service: the Invocation EPE sends, the Decision it accepts back,
// and the per-unit Config bounding the call. It is deliberately independent of
// policy APIs and ext_proc protobufs; adapters translate at those edges.
//
// The name marks which hop this is. Envoy calls EPE over gRPC ext_proc; from
// here EPE calls out over HTTP/JSON to a third party. Naming this half
// "ext_proc" too would collapse two distinct hops into one word.
package httpcallout

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

const (
	// FilterName is the engine registration and attribution name.
	FilterName = "httpcallout"
	// DefaultTimeout bounds one callout invocation when Config.Timeout is zero.
	DefaultTimeout = 500 * time.Millisecond
	// DefaultMaxBodyBytes bounds one request or response body when
	// Config.MaxBodyBytes is zero.
	DefaultMaxBodyBytes int64 = 1 << 20
)

// RequestHeaderMode selects which original request headers enter an
// callout invocation.
type RequestHeaderMode string

const (
	// RequestHeadersNone hides all request headers. It is the default.
	RequestHeadersNone RequestHeaderMode = "none"
	// RequestHeadersAll includes all request headers.
	RequestHeadersAll RequestHeaderMode = "all"
	// RequestHeadersAllowlist includes only explicitly named request headers.
	RequestHeadersAllowlist RequestHeaderMode = "allowlist"
)

// neverForwardNames must not reach a third-party callout under any mode: they
// carry caller credentials, and the endpoint is outside the mesh trust
// boundary. set-cookie is absent on purpose — it is a response header, and
// RequestHeadersConfig governs only request headers.
var neverForwardNames = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
}

// neverForwardHeader reports whether name is a credential header the callout
// must never see. It lower-cases before testing so it holds for any casing the
// wire or an operator uses.
//
// Enforcement for RequestHeadersAll belongs to the code that builds an
// Invocation, which does not exist yet; until it calls this, all mode still
// forwards credentials.
func neverForwardHeader(name string) bool {
	_, found := neverForwardNames[strings.ToLower(name)]
	return found
}

// RequestHeadersConfig controls request-header disclosure to the callout service.
type RequestHeadersConfig struct {
	Mode      RequestHeaderMode
	Allowlist []string
}

// Config is the CRD-free configuration for one policy unit's callout.
// Endpoint is shared by the enabled request and response phases.
type Config struct {
	Endpoint string
	Request  bool
	Response bool

	Timeout      time.Duration
	MaxBodyBytes int64
	FailOpen     bool

	RequestHeaders RequestHeadersConfig
}

// Effective validates c, applies zero-value defaults, and returns an owned
// copy safe for the filter to retain.
func (c Config) Effective() (Config, error) {
	if !c.Request && !c.Response {
		return Config{}, fmt.Errorf("callout config must enable at least one phase")
	}
	if err := validateEndpoint(c.Endpoint); err != nil {
		return Config{}, err
	}
	if c.Timeout < 0 {
		return Config{}, fmt.Errorf("callout timeout must not be negative")
	}
	if c.MaxBodyBytes < 0 {
		return Config{}, fmt.Errorf("callout maximum body bytes must not be negative")
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = DefaultMaxBodyBytes
	}

	headers, err := effectiveRequestHeaders(c.RequestHeaders)
	if err != nil {
		return Config{}, err
	}
	c.RequestHeaders = headers
	return c, nil
}

func validateEndpoint(endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("callout endpoint is empty")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse callout endpoint: %w", err)
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("callout endpoint must be an absolute URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("callout endpoint scheme %q is not http or https", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("callout endpoint must not contain user info")
	}
	if u.Fragment != "" {
		return fmt.Errorf("callout endpoint must not contain a fragment")
	}
	return nil
}

func effectiveRequestHeaders(in RequestHeadersConfig) (RequestHeadersConfig, error) {
	mode := in.Mode
	if mode == "" {
		mode = RequestHeadersNone
	}
	if mode != RequestHeadersNone && mode != RequestHeadersAll && mode != RequestHeadersAllowlist {
		return RequestHeadersConfig{}, fmt.Errorf("unknown request header mode %q", in.Mode)
	}
	if mode != RequestHeadersAllowlist {
		if len(in.Allowlist) != 0 {
			return RequestHeadersConfig{}, fmt.Errorf("request header allowlist requires allowlist mode")
		}
		return RequestHeadersConfig{Mode: mode}, nil
	}
	if len(in.Allowlist) == 0 {
		return RequestHeadersConfig{}, fmt.Errorf("request header allowlist is empty")
	}

	seen := make(map[string]struct{}, len(in.Allowlist))
	out := make([]string, 0, len(in.Allowlist))
	for _, raw := range in.Allowlist {
		name := strings.ToLower(raw)
		if !httpguts.ValidHeaderFieldName(name) {
			return RequestHeadersConfig{}, fmt.Errorf("invalid request header name %q", raw)
		}
		// Reject rather than drop silently: an operator who wrote the name
		// deserves an error, not a surprise.
		if neverForwardHeader(name) {
			return RequestHeadersConfig{}, fmt.Errorf("request header %q is never forwarded to a callout", raw)
		}
		if _, found := seen[name]; found {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return RequestHeadersConfig{Mode: mode, Allowlist: out}, nil
}
