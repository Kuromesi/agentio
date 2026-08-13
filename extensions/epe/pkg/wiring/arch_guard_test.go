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

// Architecture guards: the layering rules
// are worthless as prose — these tests make them mechanical. They live in
// the wiring package because wiring is the composition root that is
// *allowed* to know everything the guarded packages must not.
package wiring

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"strings"
	"testing"

	k8sfake "k8s.io/client-go/kubernetes/fake"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

const modPrefix = "istio.io/istio/extensions/epe/"

// deps returns the full dependency closure of a package.
func deps(t *testing.T, pkg string) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", modPrefix+pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
	}
	return string(out)
}

// listPkgs enumerates the extension's packages under the given pattern,
// stripped of the module prefix. Every guard below derives its subject list
// this way rather than enumerating it: a hand-written list is a silent
// failure mode — a new filter nobody remembers to add escapes the guard
// entirely.
func listPkgs(t *testing.T, pattern string, skip func(string) bool) []string {
	t.Helper()
	out, err := exec.Command("go", "list", modPrefix+pattern).CombinedOutput()
	if err != nil {
		t.Fatalf("go list %s: %v\n%s", pattern, err, out)
	}
	var pkgs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		p := strings.TrimPrefix(strings.TrimSpace(line), modPrefix)
		if p == "" || (skip != nil && skip(p)) {
			continue
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		t.Fatalf("no packages found under %s", pattern)
	}
	return pkgs
}

// enginePkgs is every package under pkg/engine/ plus every concrete filter
// under pkg/filters/. Both trees carry the same closure rules; wiring lives
// outside them because it is the composition root: it is *supposed* to
// reach the policy layer, which is how it wires the audit stream logger up.
func enginePkgs(t *testing.T) []string {
	t.Helper()
	return append(listPkgs(t, "pkg/engine/...", nil), listPkgs(t, "pkg/filters/...", nil)...)
}

// The engine and the ext_proc adapter must not depend on the policy API in
// their FULL dependency closure — not merely in their direct imports. The
// subject list is derived from the package tree, so a newly added filter is
// guarded on the day it is created, and deleting an optional signer needs no
// edit here.
//
// pkg/extproc/... is covered too: a regression there means someone gave
// the adapter a policy type again.
func TestEngineClosureFreeOfPolicyAPI(t *testing.T) {
	subjects := append(enginePkgs(t), listPkgs(t, "pkg/extproc/...", nil)...)
	for _, pkg := range append(subjects, "pkg/httpreq") {
		if strings.Contains(deps(t, pkg), "openkruise/agents-api") {
			t.Errorf("%s: dependency closure contains openkruise/agents-api; "+
				"only pkg/policy/** and the composition root may know the CRD", pkg)
		}
	}
}

// crdTypes is the CRD's vocabulary — the types a policy document is written
// in. The generated clientset is deliberately NOT part of this: it is how a
// process talks to the apiserver, not what a policy means, and a composition
// root must be able to construct one.
const crdTypes = "github.com/openkruise/agents-api/agents/"

// Only the policy layer may name the CRD's types. There is
// no package list to forget to extend, so a new package cannot escape the
// guard by omission — the silent failure mode a hand-written list invites.
//
// Stated over DIRECT imports, because a closure rule would flag every
// composition root that merely wires the policy layer up. The exceptions are
// the packages that adapt the CRD into or out of the policy model and
// are not themselves policy; each is listed with the reason, so an added
// entry has to justify itself in review.
func TestOnlyPolicyLayerNamesTheCRD(t *testing.T) {
	allowed := map[string]string{
		"pkg/admin":              "debug rendering of CRD-typed views",
		"pkg/testing/enginetest": "authors CRD objects for tests",
	}
	for _, pkg := range listPkgs(t, "...", nil) {
		if strings.HasPrefix(pkg, "pkg/policy/") {
			continue
		}
		if _, ok := allowed[pkg]; ok {
			continue
		}
		for _, imp := range directImports(t, pkg) {
			if strings.HasPrefix(imp, crdTypes) {
				t.Errorf("%s directly imports %s; move the CRD knowledge into pkg/policy/", pkg, imp)
			}
		}
	}
}

// directImports returns a package's non-test direct imports.
func directImports(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`, modPrefix+pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list imports %s: %v\n%s", pkg, err, out)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

// The ext_proc adapter and its server assembly must not name the policy layer.
// They need the engine's neutral units plus an optional opaque stream logger;
// neither interprets a policy type. Holding a policy store or binder there
// would couple the protocol edge to one policy API, blocking "add a second
// policy API without touching the engine or server".
//
// This checks DIRECT imports; the closure is covered by
// TestEngineClosureFreeOfPolicyAPI. What is specific to this test is the
// narrower statement that the protocol edge must not name a policy package
// even to hold one behind an interface.
func TestProtocolEdgeDoesNotImportPolicyPackages(t *testing.T) {
	for _, pkg := range []string{"pkg/extproc", "pkg/server"} {
		for _, imp := range directImports(t, pkg) {
			if strings.HasPrefix(imp, modPrefix+"pkg/policy/") {
				t.Errorf("%s directly imports %s; it should take a resolver "+
					"function and treat policy results as opaque", pkg, imp)
			}
		}
	}
}

// Filters and the engine must never see ext_proc protos: the adapter
// (pkg/extproc) translates once at the edge and lives outside the engine
// tree, so the rule is unconditional — no exception list to maintain.
func TestEngineClosureFreeOfExtProcProtos(t *testing.T) {
	for _, pkg := range enginePkgs(t) {
		out := deps(t, pkg)
		if strings.Contains(out, "envoy/service/ext_proc") || strings.Contains(out, "envoy/extensions/filters/http/ext_proc") {
			t.Errorf("%s: dependency closure contains ext_proc protos; only the adapter (pkg/extproc) may import them", pkg)
		}
	}
}

// Block, bypass, and header mutation must not depend on credential, Kubernetes,
// or HTTP clients.
func TestHeaderOnlyControlFiltersCannotReachNetworkClients(t *testing.T) {
	forbidden := []string{
		modPrefix + "pkg/credential",
		"k8s.io/client-go/kubernetes",
		"net/http",
	}
	for _, pkg := range []string{
		"pkg/filters/block",
		"pkg/filters/bypass",
		"pkg/filters/headermutation",
	} {
		out := deps(t, pkg)
		for _, dep := range forbidden {
			for _, line := range strings.Split(out, "\n") {
				if line == dep {
					t.Errorf("%s: header-only control filter package depends on %s", pkg, dep)
				}
			}
		}
	}
}

// phaseOfMethod maps a Filter method name to its Phase bit.
var phaseOfMethod = map[string]filter.Phase{
	"OnRequestHeaders":  filter.PhaseRequestHeaders,
	"OnRequestBody":     filter.PhaseRequestBody,
	"OnResponseHeaders": filter.PhaseResponseHeaders,
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
	regs, err := BuildFilters(Deps{Kube: k8sfake.NewClientset()})
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
