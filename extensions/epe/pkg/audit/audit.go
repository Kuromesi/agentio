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

// audit.go defines the compiled audit entry the sinks consume. The type
// carries no API types — only text/template and cel.Program — so sinks never
// import the policy layer. The compilers that turn a SecurityProfile
// AuditAction into one of these live in pkg/policy/securityprofile.
package audit

import (
	"text/template"
	"time"

	"github.com/google/cel-go/cel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MaxRequestTimeout caps the per-call HTTP timeout an operator can
// configure via AuditAction.Timeout.
const MaxRequestTimeout = 30 * time.Second

// DefaultWebhookTimeout is the per-call HTTP timeout for an audit entry that
// does not configure one. It is applied once, at profile load, so a compiled
// Audit always carries a positive timeout and no sink has to re-default.
const DefaultWebhookTimeout = 2 * time.Second

// SinkKindWebhook is the Kind discriminator for webhook audit sinks.
const SinkKindWebhook = "webhook"

// Audit is the sink-agnostic envelope produced from a single audit entry.
// Compiled once at profile-load time so the per-request hot path only
// renders + evaluates.
type Audit struct {
	Name    string
	When    cel.Program
	Kind    string
	Webhook *Webhook
}

// Webhook holds the pre-compiled templates for a webhook audit entry.
type Webhook struct {
	URL     *template.Template
	Method  string
	Headers []Header
	Body    Body
	Timeout time.Duration
}

// Header holds a pre-compiled header name/value template pair.
type Header struct {
	Name  string
	Value *template.Template
}

// Body is one of two modes: a JSON tree (with string leaves templated) or
// a single text template.
type Body struct {
	JSONRoot any
	TextTmpl *template.Template
	IsJSON   bool
	HasBody  bool
}

// TimeoutOrDefault returns the user-configured timeout, capped at
// MaxRequestTimeout, or fallback if not configured.
func TimeoutOrDefault(d *metav1.Duration, fallback time.Duration) time.Duration {
	if d == nil {
		return fallback
	}
	if d.Duration > MaxRequestTimeout {
		return MaxRequestTimeout
	}
	if d.Duration <= 0 {
		return fallback
	}
	return d.Duration
}

// DurationPtr is a test helper.
func DurationPtr(d time.Duration) *metav1.Duration {
	return &metav1.Duration{Duration: d}
}
