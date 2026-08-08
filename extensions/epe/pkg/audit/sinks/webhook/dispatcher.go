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
package webhook

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/extensions/epe/pkg/audit"
	"istio.io/istio/pkg/env"
)

// DefaultBufferSize is the dispatcher channel capacity.
const DefaultBufferSize = 8192

var (
	maxIdleConns = env.Register("AUDIT_WEBHOOK_MAX_IDLE_CONNS", 256,
		"Maximum number of idle HTTP connections across all hosts for the audit webhook client").Get()

	maxIdleConnsPerHost = env.Register("AUDIT_WEBHOOK_MAX_IDLE_CONNS_PER_HOST", 64,
		"Maximum number of idle HTTP connections per host for the audit webhook client").Get()

	maxConnsPerHost = env.Register("AUDIT_WEBHOOK_MAX_CONNS_PER_HOST", 128,
		"Maximum number of HTTP connections per host for the audit webhook client").Get()

	idleConnTimeout = env.Register("AUDIT_WEBHOOK_IDLE_CONN_TIMEOUT", 90*time.Second,
		"Maximum idle time for a keep-alive HTTP connection in the audit webhook client").Get()

	tlsHandshakeTimeout = env.Register("AUDIT_WEBHOOK_TLS_HANDSHAKE_TIMEOUT", 5*time.Second,
		"Maximum duration for a TLS handshake in the audit webhook client").Get()

	responseHeaderTimeout = env.Register("AUDIT_WEBHOOK_RESPONSE_HEADER_TIMEOUT", 10*time.Second,
		"Maximum time to wait for server response headers in the audit webhook client").Get()

	expectContinueTimeout = env.Register("AUDIT_WEBHOOK_EXPECT_CONTINUE_TIMEOUT", 1*time.Second,
		"Maximum time to wait for 100-continue response in the audit webhook client").Get()

	dialTimeout = env.Register("AUDIT_WEBHOOK_DIAL_TIMEOUT", 5*time.Second,
		"Maximum duration for establishing a TCP connection in the audit webhook client").Get()

	dialKeepAlive = env.Register("AUDIT_WEBHOOK_DIAL_KEEPALIVE", 30*time.Second,
		"Interval between TCP keep-alive probes for active connections in the audit webhook client").Get()
)

// DefaultWorkers is the default worker pool size.
const DefaultWorkers = 96

// Dispatcher accepts Delivery enqueues from the request goroutine and
// delivers them on a worker pool.
type Dispatcher interface {
	Enqueue(evt Delivery)
}

// Delivery is the unit of work the dispatcher processes. All templates
// have already been rendered by the caller.
type Delivery struct {
	ProfileNN   types.NamespacedName
	RuleName    string
	EntryName   string
	Method      string
	URL         string
	Headers     [][2]string
	Body        []byte
	ContentType string
	Timeout     time.Duration
}

// NewBuffered constructs a Buffered dispatcher. When insecureSkipVerify
// is true, the HTTP client skips TLS certificate verification for HTTPS
// webhook targets.
func NewBuffered(logger logr.Logger, bufferSize, workers int, insecureSkipVerify bool) *Buffered {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	if workers <= 0 {
		workers = DefaultWorkers
	}
	transport := &http.Transport{
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		MaxConnsPerHost:       maxConnsPerHost,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		ExpectContinueTimeout: expectContinueTimeout,
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: dialKeepAlive,
		}).DialContext,
		DisableCompression: false,
		ForceAttemptHTTP2:  true,
	}
	if insecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	b := &Buffered{
		client: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: transport,
		},
		logger: logger,
	}
	// On ctx cancellation the workers drain the backlog and exit without
	// closing the queue, so streams still finishing under GracefulStop can
	// keep enqueuing safely — see the Dispatcher type documentation.
	b.d = audit.NewDispatcher("audit-webhook", bufferSize, workers,
		b.dispatchOne,
		func(reason audit.DropReason) {
			DroppedTotal.WithLabelValues(string(reason)).Inc()
		})
	return b
}

// Buffered is an async Dispatcher backed by a bounded channel and a
// fixed-size worker pool.
type Buffered struct {
	d      *audit.Dispatcher[Delivery]
	client *http.Client
	logger logr.Logger
}

// Enqueue is non-blocking. Full channel → drop + counter increment.
func (d *Buffered) Enqueue(evt Delivery) {
	if d == nil {
		return
	}
	d.d.Enqueue(evt)
}

// Start implements runnable.Runnable.
func (d *Buffered) Start(ctx context.Context) error {
	return d.d.Start(ctx)
}

// DispatchNow delivers one event synchronously on the calling goroutine,
// running the exact same code path as the worker pool. For tests and
// synchronous callers.
func (d *Buffered) DispatchNow(ctx context.Context, evt Delivery) {
	d.dispatchOne(ctx, evt)
}

// Drain blocks until every enqueued delivery has completed or ctx is done.
func (d *Buffered) Drain(ctx context.Context) error {
	return d.d.Drain(ctx)
}

func (d *Buffered) dispatchOne(parentCtx context.Context, evt Delivery) {
	if evt.URL == "" {
		DroppedTotal.WithLabelValues("render_url").Inc()
		return
	}

	// compileAudit resolves every timeout at profile load, so a Delivery from
	// the production path always carries a positive one. This guard only
	// covers a hand-built Delivery, where a zero would otherwise mean "expire
	// immediately" rather than "use the default".
	timeout := evt.Timeout
	if timeout <= 0 {
		timeout = audit.DefaultWebhookTimeout
	}
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, evt.Method, evt.URL, bytes.NewReader(evt.Body))
	if err != nil {
		DispatchedTotal.WithLabelValues("transport_error").Inc()
		d.logger.V(1).Info("audit request build failed; dropping",
			"err", err, "url", evt.URL)
		return
	}
	if evt.Body != nil {
		req.Header.Set("Content-Type", evt.ContentType)
	}
	for _, kv := range evt.Headers {
		req.Header.Set(kv[0], kv[1])
	}

	start := time.Now()
	resp, err := d.client.Do(req)
	DurationSeconds.Observe(time.Since(start).Seconds())
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			DispatchedTotal.WithLabelValues("timeout").Inc()
		} else {
			DispatchedTotal.WithLabelValues("transport_error").Inc()
		}
		d.logger.V(1).Info("audit http call failed",
			"err", err, "url", evt.URL, "profile", evt.ProfileNN.String(), "rule", evt.RuleName, "entry", evt.EntryName)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		DispatchedTotal.WithLabelValues("http_error").Inc()
		return
	}
	DispatchedTotal.WithLabelValues("success").Inc()
}
