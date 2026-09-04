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

// Package httpclient builds the outbound HTTP clients EPE uses for
// operator-configured endpoints (audit webhooks, callouts). The pool tuning
// and the never-follow-redirects policy are shared invariants; per-caller
// bounds come through Options.
package httpclient

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"
)

// The shared pool tuning. One process-wide client per caller reuses these
// connections across every endpoint it talks to.
const (
	DefaultMaxIdleConns          = 256
	DefaultMaxIdleConnsPerHost   = 64
	DefaultMaxConnsPerHost       = 128
	DefaultIdleConnTimeout       = 90 * time.Second
	DefaultTLSHandshakeTimeout   = 5 * time.Second
	DefaultExpectContinueTimeout = 1 * time.Second
	DefaultDialTimeout           = 5 * time.Second
	DefaultDialKeepAlive         = 30 * time.Second
)

// Options carries the full transport configuration; use DefaultOptions and
// override individual fields. A zero ResponseHeaderTimeout means no separate
// header bound, which is right when the caller already bounds the whole call.
type Options struct {
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	ExpectContinueTimeout time.Duration
	DialTimeout           time.Duration
	DialKeepAlive         time.Duration
	InsecureSkipVerify    bool
}

// DefaultOptions returns the shared pool tuning with no response-header
// bound and certificate verification on.
func DefaultOptions() Options {
	return Options{
		MaxIdleConns:          DefaultMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		MaxConnsPerHost:       DefaultMaxConnsPerHost,
		IdleConnTimeout:       DefaultIdleConnTimeout,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ExpectContinueTimeout: DefaultExpectContinueTimeout,
		DialTimeout:           DefaultDialTimeout,
		DialKeepAlive:         DefaultDialKeepAlive,
	}
}

// New returns an outbound client with the given tuning. Redirects are never
// followed: a redirect would resend the request, body and all, to a URL that
// never passed the caller's endpoint validation, so the 3xx is surfaced to
// the caller instead.
func New(opts Options) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:          opts.MaxIdleConns,
		MaxIdleConnsPerHost:   opts.MaxIdleConnsPerHost,
		MaxConnsPerHost:       opts.MaxConnsPerHost,
		IdleConnTimeout:       opts.IdleConnTimeout,
		TLSHandshakeTimeout:   opts.TLSHandshakeTimeout,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
		ExpectContinueTimeout: opts.ExpectContinueTimeout,
		DialContext: (&net.Dialer{
			Timeout:   opts.DialTimeout,
			KeepAlive: opts.DialKeepAlive,
		}).DialContext,
		ForceAttemptHTTP2: true,
	}
	if opts.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: transport,
	}
}

// DrainForReuse reads a bounded prefix of resp.Body and closes it, so the
// connection can return to the pool instead of being discarded.
func DrainForReuse(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
	_ = resp.Body.Close()
}
