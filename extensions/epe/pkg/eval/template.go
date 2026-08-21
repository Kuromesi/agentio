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
package eval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"text/template"

	sprig "github.com/Masterminds/sprig/v3"
)

// bufPool reuses render buffers to reduce GC pressure on the hot path.
var bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// helperFuncs is the standard template helper allowlist, shared by every
// template site (audit webhook payloads and token-injection values). It is
// built once: sprig.TxtFuncMap() copies its whole generic map, and only these
// entries may reach policy authors — the rest of sprig includes env,
// expandenv, and getHostByName.
var helperFuncs = buildHelperFuncs()

func buildHelperFuncs() template.FuncMap {
	sprigFuncs := sprig.TxtFuncMap()
	return template.FuncMap{
		"default": func(fallback, v string) string {
			if v == "" {
				return fallback
			}
			return v
		},
		"json": func(v any) (string, error) {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
		"fromJson":  sprigFuncs["fromJson"],
		"kindIs":    sprigFuncs["kindIs"],
		"trim":      sprigFuncs["trim"],
		"hasPrefix": sprigFuncs["hasPrefix"],
		"fail":      sprigFuncs["fail"],
		"values":    sprigFuncs["values"],
		"first":     sprigFuncs["first"],
	}
}

// probeFuncs replaces the helpers whose outcome is a function of request data
// rather than of the template text. A compile-time probe render has no request
// to work with, so the real implementations would report an authoring error
// where there is none: fail is exactly what a request-time guard calls,
// fromJson returns nil for the empty probe value, and the helpers downstream of
// it reject that nil — first panics on it, and the string-typed helpers refuse
// it with "invalid value; expected string" because a missing map key yields an
// untyped nil, not "".
//
// Every stub therefore accepts any and returns a benign value of the helper's
// own result type, which is what keeps a chain like
// `default "anon" (index (fromJson (.Request.Header "x")) "sub")` — the
// documented idiom — from reading as an authoring error. A helper added to
// helperFuncs with a concrete parameter type belongs here too.
var probeFuncs = template.FuncMap{
	"fail":      func(any) (string, error) { return "", nil },
	"fromJson":  func(any) any { return map[string]any{} },
	"first":     func(any) any { return "" },
	"values":    func(any) []any { return []any{""} },
	"default":   func(any, any) string { return "" },
	"trim":      func(any) string { return "" },
	"hasPrefix": func(any, any) bool { return false },
}

// CompileTemplate parses raw into a template with the standard helper funcs
// and missingkey=zero (missing map keys render as the zero value).
func CompileTemplate(label, raw string) (*template.Template, error) {
	t, err := template.New(label).Funcs(helperFuncs).Option("missingkey=zero").Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return t, nil
}

// ProbeRender executes t against zero-valued data to surface authoring errors
// that parsing cannot catch — above all a reference to a field the render
// scope does not have, which text/template only reports at execution.
//
// It validates data references, not helper behavior: the helpers listed in
// probeFuncs are stubbed, because their real outcome depends on the request
// this probe does not have. Callers use it at compile time, where a false
// positive would reject a working policy.
func ProbeRender(t *template.Template, data any) (string, error) {
	probe, err := t.Clone()
	if err != nil {
		return "", err
	}
	return RenderToString(probe.Funcs(probeFuncs), data)
}

// RenderToString executes t against data using a pooled buffer.
func RenderToString(t *template.Template, data any) (string, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		if buf.Cap() <= 64*1024 {
			bufPool.Put(buf)
		}
	}()
	if err := t.Execute(buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
