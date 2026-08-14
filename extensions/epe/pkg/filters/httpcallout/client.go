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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client performs one callout. Implementations must not retry: a retry would
// double a side effect the callout may have already taken.
type Client interface {
	Call(ctx context.Context, cfg Config, inv Invocation) (Decision, error)
}

// Deps carries what the filter needs from wiring. Client is shared across all
// rules so one connection pool serves the process.
type Deps struct {
	Client Client
}

// Transport tuning. These are plain constants rather than env-registered knobs
// because Config already exposes the one bound an operator has a reason to
// change per unit — Timeout — and the rest describe the shared pool.
const (
	maxIdleConns          = 256
	maxIdleConnsPerHost   = 64
	maxConnsPerHost       = 128
	idleConnTimeout       = 90 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
	expectContinueTimeout = 1 * time.Second
	dialTimeout           = 5 * time.Second
	dialKeepAlive         = 30 * time.Second
)

// HTTPClient calls out over HTTP/JSON. One instance is shared by every rule, so
// its connection pool is process-wide; the per-unit bounds come from Config on
// each call.
type HTTPClient struct {
	client *http.Client
}

var _ Client = (*HTTPClient)(nil)

// NewHTTPClient builds the shared client once. There is deliberately no
// http.Client.Timeout: Config.Timeout is per-unit, so the deadline has to be
// derived per call instead.
func NewHTTPClient() *HTTPClient {
	return &HTTPClient{client: &http.Client{
		// A redirect would send the invocation, body and all, to a URL that
		// never passed validateEndpoint. Surfacing the 3xx as a failure is the
		// safe reading.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			MaxIdleConns:        maxIdleConns,
			MaxIdleConnsPerHost: maxIdleConnsPerHost,
			MaxConnsPerHost:     maxConnsPerHost,
			IdleConnTimeout:     idleConnTimeout,
			TLSHandshakeTimeout: tlsHandshakeTimeout,
			// No ResponseHeaderTimeout: Config.Timeout already bounds the whole
			// call, and a second, longer bound here would only confuse.
			ExpectContinueTimeout: expectContinueTimeout,
			DialContext: (&net.Dialer{
				Timeout:   dialTimeout,
				KeepAlive: dialKeepAlive,
			}).DialContext,
			ForceAttemptHTTP2: true,
		},
	}}
}

// Call sends one invocation and decodes the decision. Every failure is returned
// as an error for the framework's fail-open/fail-closed policy to resolve.
//
// Errors name what went wrong but never the endpoint or the remote's response
// text: the same hygiene tokentransform's blockReply documents. The endpoint is
// operator configuration and the response body is third-party text, and the
// caller reading the resulting deny is untrusted.
func (c *HTTPClient) Call(ctx context.Context, cfg Config, inv Invocation) (Decision, error) {
	payload, err := json.Marshal(inv)
	if err != nil {
		return Decision{}, fmt.Errorf("marshal callout invocation: %w", err)
	}

	// Per call, not on the shared client: Config.Timeout is per-unit, so one
	// http.Client.Timeout could not express two rules with different bounds.
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return Decision{}, fmt.Errorf("build callout request: %w", scrubURL(err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return Decision{}, fmt.Errorf("callout request failed: %w", scrubURL(err))
	}
	defer func() {
		// Drain a little so the connection can be reused, then close.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Decision{}, fmt.Errorf("callout endpoint returned status %d", resp.StatusCode)
	}

	// Read one byte past the limit so hitting it is distinguishable from a body
	// that merely ends there. A truncated JSON that happened to parse would be a
	// decision nobody sent.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxBodyBytes+1))
	if err != nil {
		return Decision{}, fmt.Errorf("read callout response: %w", scrubURL(err))
	}
	if int64(len(raw)) > cfg.MaxBodyBytes {
		return Decision{}, fmt.Errorf("callout response body exceeds the %d byte limit", cfg.MaxBodyBytes)
	}

	var decision Decision
	if err := json.Unmarshal(raw, &decision); err != nil {
		// The remote's body is not quoted: it is third-party text on a path that
		// ends in a client-visible deny.
		return Decision{}, errors.New("callout response is not a valid decision document")
	}
	return decision, nil
}

// scrubURL strips the URL net/http records on transport errors. *url.Error
// stringifies as `Post "https://host/path": ...`, which would put the configured
// endpoint into every log line and, worse, into anything derived from the error.
func scrubURL(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}
