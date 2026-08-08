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
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"text/template"

	"istio.io/istio/extensions/epe/pkg/audit"
	"istio.io/istio/extensions/epe/pkg/eval"
)

// errBodyTooLarge reports a rendered body over MaxRenderedBodyBytes. The
// event is dropped rather than truncated: slicing at the byte cap produces
// unparseable JSON and can cut a multi-byte rune in half, so a truncated
// record is worse at the receiver than a missing one — and the drop is
// visible as DroppedTotal{reason="body_too_large"}.
var errBodyTooLarge = errors.New("rendered body exceeds cap")

const (
	// MaxRenderedBodyBytes caps the per-request webhook body.
	MaxRenderedBodyBytes = 64 * 1024

	contentTypeJSON = "application/json; charset=utf-8"
	contentTypeText = "text/plain; charset=utf-8"
)

// RenderURL renders the URL template and validates the scheme.
func RenderURL(ca *audit.Audit, ctx *audit.Scope) (string, error) {
	if ca.Webhook == nil {
		return "", fmt.Errorf("render url: nil webhook payload")
	}
	raw, err := eval.RenderToString(ca.Webhook.URL, ctx)
	if err != nil {
		return "", fmt.Errorf("render url: %w", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("invalid url scheme %q (only http/https allowed)", u.Scheme)
	}
	return raw, nil
}

// RenderHeaders renders every header value template.
func RenderHeaders(ca *audit.Audit, ctx *audit.Scope) ([][2]string, error) {
	if ca.Webhook == nil {
		return nil, fmt.Errorf("render headers: nil webhook payload")
	}
	out := make([][2]string, 0, len(ca.Webhook.Headers))
	for _, h := range ca.Webhook.Headers {
		v, err := eval.RenderToString(h.Value, ctx)
		if err != nil {
			return nil, fmt.Errorf("render header %q: %w", h.Name, err)
		}
		out = append(out, [2]string{h.Name, v})
	}
	return out, nil
}

// RenderBody renders the body template (if any).
func RenderBody(ca *audit.Audit, ctx *audit.Scope) ([]byte, string, error) {
	if ca.Webhook == nil {
		return nil, "", fmt.Errorf("render body: nil webhook payload")
	}
	if !ca.Webhook.Body.HasBody {
		return nil, contentTypeJSON, nil
	}
	if ca.Webhook.Body.IsJSON {
		rendered, err := renderJSONNode(ca.Webhook.Body.JSONRoot, ctx)
		if err != nil {
			return nil, "", fmt.Errorf("render body: %w", err)
		}
		b, err := json.Marshal(rendered)
		if err != nil {
			return nil, "", fmt.Errorf("marshal body: %w", err)
		}
		capped, err := capBody(b)
		if err != nil {
			return nil, "", err
		}
		return capped, contentTypeJSON, nil
	}
	s, err := eval.RenderToString(ca.Webhook.Body.TextTmpl, ctx)
	if err != nil {
		return nil, "", fmt.Errorf("render body: %w", err)
	}
	capped, err := capBody([]byte(s))
	if err != nil {
		return nil, "", err
	}
	return capped, contentTypeText, nil
}

func renderJSONNode(node any, ctx *audit.Scope) (any, error) {
	switch v := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, child := range v {
			rendered, err := renderJSONNode(child, ctx)
			if err != nil {
				return nil, err
			}
			out[k] = rendered
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			rendered, err := renderJSONNode(child, ctx)
			if err != nil {
				return nil, err
			}
			out[i] = rendered
		}
		return out, nil
	case *template.Template:
		s, err := eval.RenderToString(v, ctx)
		if err != nil {
			return nil, err
		}
		return s, nil
	default:
		return v, nil
	}
}

func capBody(b []byte) ([]byte, error) {
	if len(b) > MaxRenderedBodyBytes {
		return nil, fmt.Errorf("%w: %d bytes exceeds %d", errBodyTooLarge, len(b), MaxRenderedBodyBytes)
	}
	return b, nil
}
