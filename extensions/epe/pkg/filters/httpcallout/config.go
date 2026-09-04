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

// HeaderMode selects which original headers of one direction enter a callout
// invocation. The four modes mean the same thing for requests and responses, so
// one type serves both.
type HeaderMode string

const (
	// HeaderModeNone hides all headers of the direction. It is the default in
	// both directions.
	HeaderModeNone HeaderMode = "none"
	// HeaderModeAll includes every header of the direction, credentials
	// included: authorization and cookie on the request side, set-cookie and
	// the authenticate challenges on the response side. The endpoint sits
	// outside the mesh trust boundary, so this mode hands a third party
	// whatever the caller sent and whatever the upstream minted.
	HeaderModeAll HeaderMode = "all"
	// HeaderModeAllowlist includes only explicitly named headers.
	HeaderModeAllowlist HeaderMode = "allowlist"
	// HeaderModeDenylist includes every header of the direction except the
	// named ones. It is how an operator writes the credential rule this
	// package once hardcoded — denylist: [authorization, proxy-authorization,
	// cookie] — and is the recommended baseline for an endpoint outside the
	// trust boundary, because it appears where it can be reviewed.
	HeaderModeDenylist HeaderMode = "denylist"
)

// HeadersConfig controls header disclosure to the callout service for one
// direction. Allowlist and Denylist are separate fields rather than one list the
// mode reinterprets: a shared field would let a one-word mode edit silently
// invert "only these" into "all but these", which is the worst possible failure
// for a disclosure control.
type HeadersConfig struct {
	Mode      HeaderMode
	Allowlist []string
	Denylist  []string
}

// PhaseConfig is one direction's settings. Its presence enables the phase, which
// makes a header mode on a disabled phase unrepresentable rather than merely
// discouraged.
type PhaseConfig struct {
	// Headers defaults to none: disclosure is opt-in in either direction.
	Headers HeadersConfig
	// Body opts into buffering. It also moves the callout's dispatch point —
	// false runs it in the headers phase, so Envoy buffers nothing for a
	// header-only callout. See Filter.
	Body bool
}

// Config is the CRD-free configuration for one policy unit's callout.
// Endpoint is shared by the enabled request and response phases.
type Config struct {
	Endpoint string

	Timeout      time.Duration
	MaxBodyBytes int64
	FailOpen     bool

	// Request and Response are nil when that phase is disabled.
	Request  *PhaseConfig
	Response *PhaseConfig
}

// Effective validates c, applies zero-value defaults, and returns an owned
// copy safe for the filter to retain. The phase configs are freshly allocated
// rather than shared: a shallow struct copy of a pointer field would leave the
// filter holding whatever the caller edits next.
func (c Config) Effective() (Config, error) {
	if c.Request == nil && c.Response == nil {
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

	request, err := effectivePhase(c.Request, "request")
	if err != nil {
		return Config{}, err
	}
	response, err := effectivePhase(c.Response, "response")
	if err != nil {
		return Config{}, err
	}
	c.Request = request
	c.Response = response
	return c, nil
}

// effectivePhase validates one direction and returns a phase config the caller
// cannot reach. A nil input stays nil: presence is what enables the phase, so
// defaulting a disabled direction into an enabled one would invent a callout.
func effectivePhase(in *PhaseConfig, direction string) (*PhaseConfig, error) {
	if in == nil {
		return nil, nil
	}
	headers, err := effectiveHeaders(in.Headers, direction)
	if err != nil {
		return nil, err
	}
	return &PhaseConfig{Headers: headers, Body: in.Body}, nil
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

// effectiveHeaders validates and normalizes one direction's disclosure config.
// direction appears in every message so an operator with both fields set can tell
// which one is wrong.
//
// The list a mode does not own must be empty rather than ignored: silently
// dropping it would let a config that reads like "all but these" behave like
// "everything".
func effectiveHeaders(in HeadersConfig, direction string) (HeadersConfig, error) {
	mode := in.Mode
	if mode == "" {
		mode = HeaderModeNone
	}
	switch mode {
	case HeaderModeNone, HeaderModeAll:
		if len(in.Allowlist) != 0 {
			return HeadersConfig{}, fmt.Errorf("%s header allowlist requires allowlist mode", direction)
		}
		if len(in.Denylist) != 0 {
			return HeadersConfig{}, fmt.Errorf("%s header denylist requires denylist mode", direction)
		}
		return HeadersConfig{Mode: mode}, nil
	case HeaderModeAllowlist:
		if len(in.Denylist) != 0 {
			return HeadersConfig{}, fmt.Errorf("%s header denylist requires denylist mode", direction)
		}
		// An empty owned list is an error rather than a synonym for a mode that
		// already exists: it is what a half-finished config looks like.
		if len(in.Allowlist) == 0 {
			return HeadersConfig{}, fmt.Errorf("%s header allowlist is empty", direction)
		}
		names, err := normalizeHeaderNames(in.Allowlist, direction)
		if err != nil {
			return HeadersConfig{}, err
		}
		return HeadersConfig{Mode: mode, Allowlist: names}, nil
	case HeaderModeDenylist:
		if len(in.Allowlist) != 0 {
			return HeadersConfig{}, fmt.Errorf("%s header allowlist requires allowlist mode", direction)
		}
		if len(in.Denylist) == 0 {
			return HeadersConfig{}, fmt.Errorf("%s header denylist is empty", direction)
		}
		names, err := normalizeHeaderNames(in.Denylist, direction)
		if err != nil {
			return HeadersConfig{}, err
		}
		return HeadersConfig{Mode: mode, Denylist: names}, nil
	default:
		return HeadersConfig{}, fmt.Errorf("unknown %s header mode %q", direction, in.Mode)
	}
}

// normalizeHeaderNames lower-cases and deduplicates one list, so a match at
// forwarding time never depends on the casing an operator wrote. Any valid header
// name is accepted, credentials included: a name written in a reviewed CRD is a
// decision, not an accident.
func normalizeHeaderNames(raw []string, direction string) ([]string, error) {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		name := strings.ToLower(entry)
		if !httpguts.ValidHeaderFieldName(name) {
			return nil, fmt.Errorf("invalid %s header name %q", direction, entry)
		}
		if _, found := seen[name]; found {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out, nil
}
