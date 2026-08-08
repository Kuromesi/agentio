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
	"errors"
	"strings"

	"github.com/go-logr/logr"

	"istio.io/istio/extensions/epe/pkg/audit"
)

// Sink is an audit.Sink implementation that delivers audit events
// via HTTP webhook.
type Sink struct {
	dispatcher Dispatcher
	logger     logr.Logger
}

// NewSink wraps a Dispatcher as an audit.Sink. Production wiring passes the
// asynchronous *Buffered; tests may pass a synchronous Dispatcher.
func NewSink(d Dispatcher, logger logr.Logger) *Sink {
	return &Sink{dispatcher: d, logger: logger}
}

// Enqueue renders the audit.Event's templates into a Delivery and
// pushes it onto the dispatcher.
func (s *Sink) Enqueue(e audit.Event) {
	if s == nil || s.dispatcher == nil {
		return
	}
	if e.Audit == nil || e.Audit.Webhook == nil {
		DroppedTotal.WithLabelValues("render_url").Inc()
		return
	}
	scope := e.Scope
	if scope == nil {
		scope = &audit.Scope{}
	}

	rawURL, err := RenderURL(e.Audit, scope)
	if err != nil {
		reason := "render_url"
		if strings.Contains(err.Error(), "invalid url scheme") {
			reason = "invalid_scheme"
		}
		DroppedTotal.WithLabelValues(reason).Inc()
		s.logger.V(1).Info("audit url render failed; dropping",
			"err", err, "profile", e.ProfileNN.String(), "rule", e.RuleName, "entry", e.ActionName)
		return
	}

	headers, err := RenderHeaders(e.Audit, scope)
	if err != nil {
		DroppedTotal.WithLabelValues("render_header").Inc()
		s.logger.V(1).Info("audit header render failed; dropping",
			"err", err, "profile", e.ProfileNN.String(), "rule", e.RuleName, "entry", e.ActionName)
		return
	}

	body, contentType, err := RenderBody(e.Audit, scope)
	if err != nil {
		reason := "render_body"
		if errors.Is(err, errBodyTooLarge) {
			reason = "body_too_large"
		}
		DroppedTotal.WithLabelValues(reason).Inc()
		s.logger.V(1).Info("audit body render failed; dropping",
			"err", err, "profile", e.ProfileNN.String(), "rule", e.RuleName, "entry", e.ActionName)
		return
	}

	s.dispatcher.Enqueue(Delivery{
		ProfileNN:   e.ProfileNN,
		RuleName:    e.RuleName,
		EntryName:   e.ActionName,
		Method:      e.Audit.Webhook.Method,
		URL:         rawURL,
		Headers:     headers,
		Body:        body,
		ContentType: contentType,
		Timeout:     e.Audit.Webhook.Timeout,
	})
}
