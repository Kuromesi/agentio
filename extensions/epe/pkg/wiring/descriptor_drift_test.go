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

package wiring

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/pkg/kube"
)

// phaseOfMethod maps a Filter method name to its Phase bit.
var phaseOfMethod = map[string]filter.Phase{
	"OnRequestHeaders":  filter.PhaseRequestHeaders,
	"OnRequestBody":     filter.PhaseRequestBody,
	"OnResponseHeaders": filter.PhaseResponseHeaders,
	"OnResponseBody":    filter.PhaseResponseBody,
}

// Descriptor.Phases must match the methods the filter actually overrides,
// or the bitmask becomes the next "comment that disagrees with the code".
// Overridden = declared as a method in the filter's own
// package rather than promoted from the embedded PassThrough.
func TestDescriptorPhasesMatchOverriddenMethods(t *testing.T) {
	srcDirs := map[string]string{
		"bypass":         "../filters/bypass",
		"block":          "../filters/block",
		"headermutation": "../filters/headermutation",
		"mcpacl":         "../filters/mcpacl",
		"tokentransform": "../filters/tokentransform",
	}
	regs, err := BuildFilters(Deps{Kube: kube.NewFakeClient(), Stop: t.Context().Done()})
	if err != nil {
		t.Fatalf("BuildFilters: %v", err)
	}
	for _, reg := range regs {
		dir, ok := srcDirs[reg.Name]
		if !ok {
			t.Errorf("no source dir mapped for filter %q; extend the drift test", reg.Name)
			continue
		}
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", dir, err)
		}
		var got filter.Phase
		for _, pkg := range pkgs {
			for _, file := range pkg.Files {
				for _, decl := range file.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok || fn.Recv == nil {
						continue
					}
					if p, ok := phaseOfMethod[fn.Name.Name]; ok {
						got |= p
					}
				}
			}
		}
		if got != reg.Phases {
			t.Errorf("%s: Descriptor.Phases = %06b but overridden methods say %06b", reg.Name, reg.Phases, got)
		}
	}
}
