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
)

// bufPool reuses render buffers to reduce GC pressure on the hot path.
var bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// HelperFuncs returns the standard template helper function map, shared by
// every template site (audit webhook payloads and token-injection values).
func HelperFuncs() template.FuncMap {
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
	}
}

// CompileTemplate parses raw into a template with the standard helper funcs
// and missingkey=zero (missing map keys render as the zero value).
func CompileTemplate(label, raw string) (*template.Template, error) {
	t, err := template.New(label).Funcs(HelperFuncs()).Option("missingkey=zero").Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return t, nil
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
