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
	"net/http"
	"net/url"

	"istio.io/istio/pkg/env"

	"github.com/openkruise/agentio/extensions/epe/pkg/httpclient"
)

const defaultMaxResponseBytes = 1 << 20

var maxResponseBytes = env.Register("HTTP_CALLOUT_MAX_RESPONSE_BYTES", defaultMaxResponseBytes,
	"Maximum response body bytes read by HTTP callouts; a non-positive value falls back to 1048576 bytes (1 MiB)")

// Client performs one callout. Implementations must not retry: a retry would
// double a side effect the callout may have already taken.
type Client interface {
	Call(ctx context.Context, provider string, inv Invocation) (Decision, error)
}

// Deps carries what the filter needs from wiring. Client is shared across all
// rules and resolves the named provider for each call.
type Deps struct {
	Client Client
}

// HTTPDoer sends requests through named HTTPCallout providers. Implementations own
// endpoint selection, TLS and timeouts. They must not follow redirects or retry
// failed HTTP responses.
type HTTPDoer interface {
	Do(ctx context.Context, provider, method string, headers http.Header, body io.Reader) (*http.Response, error)
}

// HTTPClient encodes callout invocations and decodes decisions. Its providers
// supply the HTTP connections independently of the callout protocol.
type HTTPClient struct {
	providers        HTTPDoer
	maxResponseBytes int64
}

// NewHTTPClient constructs a callout protocol client over named HTTPCallout providers.
// The response limit is read from the environment once when the client is created.
func NewHTTPClient(providers HTTPDoer) *HTTPClient {
	limit := maxResponseBytes.Get()
	if limit <= 0 {
		limit = defaultMaxResponseBytes
	}
	return &HTTPClient{providers: providers, maxResponseBytes: int64(limit)}
}

// Call sends one invocation and decodes the decision. Every failure is returned
// as an error for the framework's fail-open/fail-closed policy to resolve.
//
// Errors name what went wrong but never the endpoint or the remote's response
// text: the same hygiene tokentransform's blockReply documents. The endpoint is
// operator configuration and the response body is third-party text, and the
// caller reading the resulting deny is untrusted.
func (c *HTTPClient) Call(ctx context.Context, provider string, inv Invocation) (Decision, error) {
	payload, err := json.Marshal(inv)
	if err != nil {
		return Decision{}, fmt.Errorf("marshal callout invocation: %w", err)
	}

	resp, err := c.providers.Do(ctx, provider, http.MethodPost, http.Header{
		"Content-Type": {"application/json"},
		"Accept":       {"application/json"},
	}, bytes.NewReader(payload))
	if err != nil {
		return Decision{}, fmt.Errorf("callout request failed: %w", scrubURL(err))
	}
	// Drain a little so the connection can be reused, then close.
	defer httpclient.DrainForReuse(resp)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Decision{}, fmt.Errorf("callout endpoint returned status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes))
	if err != nil {
		return Decision{}, fmt.Errorf("read callout response: %w", scrubURL(err))
	}
	if int64(len(raw)) == c.maxResponseBytes {
		// Probe one more byte so an exact-size body succeeds, but a truncated
		// document is never accepted even if the prefix happens to be valid JSON.
		var extra [1]byte
		if n, readErr := io.ReadFull(resp.Body, extra[:]); n > 0 {
			return Decision{}, fmt.Errorf("callout response body exceeds the %d byte limit", c.maxResponseBytes)
		} else if !errors.Is(readErr, io.EOF) {
			return Decision{}, fmt.Errorf("read callout response: %w", scrubURL(readErr))
		}
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
