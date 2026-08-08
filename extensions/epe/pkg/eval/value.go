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
	"fmt"
	"text/template"

	"github.com/google/cel-go/cel"
)

// Value is the unified compiled artifact for every "dynamic string" in the
// API (token value, webhook URL/header, body leaves). Exactly one branch is
// set. Eval supports the Literal and Tmpl branches; the Prog branch is not
// wired and evaluating it returns an error.
type Value struct {
	Literal string
	Tmpl    *template.Template
	Prog    cel.Program
}

// Eval renders the value against the evaluation root. The Literal branch
// never consults data and never fails.
func (v *Value) Eval(data any) (string, error) {
	switch {
	case v.Prog != nil:
		return "", fmt.Errorf("cel value branch is not wired yet")
	case v.Tmpl != nil:
		var buf bytes.Buffer
		if err := v.Tmpl.Execute(&buf, data); err != nil {
			return "", err
		}
		return buf.String(), nil
	default:
		return v.Literal, nil
	}
}
