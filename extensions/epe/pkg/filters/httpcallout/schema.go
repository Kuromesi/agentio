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
package httpcallout

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// spec is the wire form of Config. Field names mirror the Config fields so an
// operator reading either one recognizes the other.
type spec struct {
	Endpoint string `json:"endpoint,omitempty"`
	// Request and Response are pointers because presence is enablement: an absent
	// key disables the direction, while "request": {} enables it with nothing
	// disclosed and nothing buffered.
	Request  *phaseSpec `json:"request,omitempty"`
	Response *phaseSpec `json:"response,omitempty"`
	// Timeout is a Go duration string ("500ms", "2s") rather than a number: a
	// bare number would be ambiguous between seconds and milliseconds, and
	// because zero means "use the default", a wrong guess would be silent
	// instead of an error.
	Timeout      string `json:"timeout,omitempty"`
	MaxBodyBytes int64  `json:"maxBodyBytes,omitempty"`
	FailOpen     bool   `json:"failOpen,omitempty"`
}

// phaseSpec is the wire form of PhaseConfig.
type phaseSpec struct {
	Headers *headersSpec `json:"headers,omitempty"`
	Body    bool         `json:"body,omitempty"`
}

// headersSpec is the wire form of HeadersConfig, shared by both directions
// because the modes mean the same thing in each.
type headersSpec struct {
	Mode string `json:"mode,omitempty"`
	// Allowlist and Denylist are separate keys because the mode they belong to
	// is what they mean: one list whose sense flipped with the mode string would
	// turn a typo into an inverted disclosure control.
	Allowlist []string `json:"allowlist,omitempty"`
	Denylist  []string `json:"denylist,omitempty"`
}

// empty reports whether the document says nothing at all. A payload under this
// filter's name that carries no fields is an authoring mistake, not a request for
// every default: there is no default endpoint to call.
//
// Compared field by field rather than against a zero spec because the phase
// pointers make the struct incomparable.
func (s spec) empty() bool {
	return s.Endpoint == "" && s.Request == nil && s.Response == nil &&
		s.Timeout == "" && s.MaxBodyBytes == 0 && !s.FailOpen
}

func parse(raw json.RawMessage) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// An unknown key is more likely a typo in a security control than a field
	// from a newer version, and silently ignoring one would disable the setting
	// the author believed they had made.
	decoder.DisallowUnknownFields()

	var s spec
	if err := decoder.Decode(&s); err != nil {
		return Config{}, err
	}
	if s.empty() {
		return Config{}, fmt.Errorf("callout config is empty")
	}

	timeout, err := parseTimeout(s.Timeout)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Endpoint:     s.Endpoint,
		Request:      phaseFromSpec(s.Request),
		Response:     phaseFromSpec(s.Response),
		Timeout:      timeout,
		MaxBodyBytes: s.MaxBodyBytes,
		FailOpen:     s.FailOpen,
	}
	// Effective owns validation and defaulting, so a hand-built Config and a
	// parsed one cannot drift.
	return cfg.Effective()
}

// phaseFromSpec maps one direction, preserving the absent-versus-empty
// distinction the wire draws: nil in stays nil out, so the phase stays disabled.
func phaseFromSpec(s *phaseSpec) *PhaseConfig {
	if s == nil {
		return nil
	}
	phase := &PhaseConfig{Body: s.Body}
	if s.Headers != nil {
		phase.Headers = HeadersConfig{
			Mode:      HeaderMode(s.Headers.Mode),
			Allowlist: s.Headers.Allowlist,
			Denylist:  s.Headers.Denylist,
		}
	}
	return phase
}

// parseTimeout maps an absent or empty value to zero, which Effective turns into
// DefaultTimeout.
func parseTimeout(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("callout timeout %q is not a duration such as %q", raw, "500ms")
	}
	return timeout, nil
}

// NewDefinition binds the payload parser to the typed descriptor. Deps is
// threaded through rather than captured globally so the shared client is owned by
// the composition root.
func NewDefinition(deps Deps) filter.Definition {
	return filter.Define(NewDescriptor(deps), parse)
}
