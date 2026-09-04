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

// audit.go compiles SecurityProfile AuditAction entries into the neutral
// audit.Audit the sinks consume. Only the compilation is CRD-shaped, which
// is why it lives here and the compiled type lives with its consumers in
// pkg/audit.
package securityprofile

import (
	"encoding/json"
	"fmt"
	"text/template"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
	"github.com/openkruise/agentio/extensions/epe/pkg/eval"
)

// compileAudit pre-compiles every template + CEL expression in an
// AuditAction.
func compileAudit(a *v1alpha1.AuditAction) (*audit.Audit, error) {
	if a == nil {
		return nil, fmt.Errorf("audit action is nil")
	}
	if a.Webhook == nil {
		return nil, fmt.Errorf("audit action %q: webhook is required", a.Name)
	}

	when, err := eval.CompileBool(a.When)
	if err != nil {
		return nil, fmt.Errorf("when: %w", err)
	}

	wh := a.Webhook
	cw := &audit.Webhook{
		Method:  defaultMethod(wh),
		Timeout: audit.TimeoutOrDefault(wh.Timeout, audit.DefaultWebhookTimeout),
	}

	urlTmpl, err := compileText("url", wh.URL)
	if err != nil {
		return nil, err
	}
	cw.URL = urlTmpl

	if wh.Request != nil {
		for _, h := range wh.Request.Headers {
			ht, err := compileText("header["+h.Name+"]", h.Value)
			if err != nil {
				return nil, err
			}
			cw.Headers = append(cw.Headers, audit.Header{Name: h.Name, Value: ht})
		}
		if wh.Request.Body != nil {
			body, err := compileBody(wh.Request.Body)
			if err != nil {
				return nil, fmt.Errorf("body: %w", err)
			}
			cw.Body = body
		}
	}

	return &audit.Audit{
		Name:    a.Name,
		When:    when,
		Kind:    audit.SinkKindWebhook,
		Webhook: cw,
	}, nil
}

// compileAuditList compiles every entry in an []AuditAction in order.
func compileAuditList(actions []v1alpha1.AuditAction) ([]*audit.Audit, error) {
	if len(actions) == 0 {
		return nil, nil
	}
	out := make([]*audit.Audit, 0, len(actions))
	for i := range actions {
		ca, err := compileAudit(&actions[i])
		if err != nil {
			return nil, fmt.Errorf("audit[%q]: %w", actions[i].Name, err)
		}
		out = append(out, ca)
	}
	return out, nil
}

func defaultMethod(wh *v1alpha1.AuditWebhook) string {
	if wh != nil && wh.Request != nil && wh.Request.Method != "" {
		return wh.Request.Method
	}
	return "POST"
}

func compileText(label, raw string) (*template.Template, error) {
	return eval.CompileTemplate(label, raw)
}

func compileBody(b *v1alpha1.AuditBody) (audit.Body, error) {
	hasJSON := b.JSON != nil && len(b.JSON.Raw) > 0
	hasText := b.Text != nil
	if hasJSON && hasText {
		return audit.Body{}, fmt.Errorf("exactly one of json or text must be set")
	}
	if hasJSON {
		var raw any
		if err := json.Unmarshal(b.JSON.Raw, &raw); err != nil {
			return audit.Body{}, fmt.Errorf("invalid JSON: %w", err)
		}
		walked, err := compileJSONNode(raw)
		if err != nil {
			return audit.Body{}, err
		}
		return audit.Body{JSONRoot: walked, IsJSON: true, HasBody: true}, nil
	}
	if hasText {
		t, err := compileText("body.text", *b.Text)
		if err != nil {
			return audit.Body{}, err
		}
		return audit.Body{TextTmpl: t, HasBody: true}, nil
	}
	return audit.Body{}, nil
}

func compileJSONNode(node any) (any, error) {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			c, err := compileJSONNode(child)
			if err != nil {
				return nil, fmt.Errorf("[%s]: %w", k, err)
			}
			v[k] = c
		}
		return v, nil
	case []any:
		for i, child := range v {
			c, err := compileJSONNode(child)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			v[i] = c
		}
		return v, nil
	case string:
		t, err := eval.CompileTemplate("body.json.leaf", v)
		if err != nil {
			return nil, err
		}
		return t, nil
	default:
		return v, nil
	}
}
