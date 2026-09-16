// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

// Command gostyle checks layout conventions that gofmt intentionally preserves.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type finding struct {
	line    int
	message string
}

type lineRange struct {
	start int
	end   int
}

func main() {
	base := flag.String("base", "HEAD", "Git revision to compare; explicit file arguments check the entire file")
	flag.Parse()
	if err := run(*base, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(base string, files []string) error {
	explicit := len(files) > 0
	if !explicit {
		var err error
		files, err = changedFiles(base)
		if err != nil {
			return err
		}
	}
	count := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		findings, err := check(file, data)
		if err != nil {
			return err
		}
		var ranges []lineRange
		if !explicit && len(findings) > 0 {
			diff, err := git("diff", "--no-ext-diff", "--no-color", "--no-renames", "--unified=0", base, "--", file)
			if err != nil {
				return err
			}
			ranges, err = addedLines(diff)
			if err != nil {
				return err
			}
			// Untracked files have no diff against the base, but every line is new.
			untracked, err := git("ls-files", "--others", "--exclude-standard", "--", file)
			if err != nil {
				return err
			}
			if len(untracked) > 0 {
				ranges = []lineRange{{start: 1, end: strings.Count(string(data), "\n") + 1}}
			}
		}
		for _, issue := range findings {
			if explicit || slices.ContainsFunc(ranges, func(r lineRange) bool {
				return r.start <= issue.line && issue.line <= r.end
			}) {
				fmt.Printf("%s:%d: %s (gostyle)\n", file, issue.line, issue.message)
				count++
			}
		}
	}
	if count > 0 {
		return fmt.Errorf(
			"%d Go style findings; expand fields/statements onto separate lines, then run make fmt",
			count,
		)
	}
	return nil
}

func changedFiles(base string) ([]string, error) {
	if _, err := git("rev-parse", "--verify", "--end-of-options", base+"^{commit}"); err != nil {
		return nil, err
	}
	tracked, err := git("diff", "--name-only", "-z", "--diff-filter=ACMR", base, "--", "*.go")
	if err != nil {
		return nil, err
	}
	untracked, err := git("ls-files", "--others", "--exclude-standard", "-z", "--", "*.go")
	if err != nil {
		return nil, err
	}
	var files []string
	for file := range strings.SplitSeq(string(tracked)+string(untracked), "\x00") {
		if file != "" && !strings.HasPrefix(file, "vendor/") && !strings.Contains(file, "/vendor/") {
			files = append(files, file)
		}
	}
	slices.Sort(files)
	return slices.Compact(files), nil
}

func git(args ...string) ([]byte, error) {
	output, err := exec.Command("git", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, output)
	}
	return output, nil
}

var hunkHeader = regexp.MustCompile(`(?m)^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

func addedLines(diff []byte) ([]lineRange, error) {
	var ranges []lineRange
	for _, match := range hunkHeader.FindAllSubmatch(diff, -1) {
		start, err := strconv.Atoi(string(match[1]))
		if err != nil {
			return nil, fmt.Errorf("parse diff line number: %w", err)
		}
		count := 1
		if len(match[2]) > 0 {
			count, err = strconv.Atoi(string(match[2]))
			if err != nil {
				return nil, fmt.Errorf("parse diff line count: %w", err)
			}
		}
		if count > 0 {
			ranges = append(ranges, lineRange{start: start, end: start + count - 1})
		}
	}
	return ranges, nil
}

func check(name string, data []byte) ([]finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, data, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	if ast.IsGenerated(file) {
		return nil, nil
	}
	line := func(pos token.Pos) int { return fset.PositionFor(pos, false).Line }
	var findings []finding
	report := func(pos token.Pos, message string) {
		findings = append(findings, finding{line: line(pos), message: message})
	}
	statements := func(body []ast.Stmt) {
		for i := 1; i < len(body); i++ {
			if line(body[i-1].End()) == line(body[i].Pos()) {
				report(body[i].Pos(), "put each statement on its own line")
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.CompositeLit:
			if line(n.Lbrace) == line(n.Rbrace) {
				break
			}
			for i := 1; i < len(n.Elts); i++ {
				_, previousKeyed := n.Elts[i-1].(*ast.KeyValueExpr)
				_, currentKeyed := n.Elts[i].(*ast.KeyValueExpr)
				if previousKeyed && currentKeyed && line(n.Elts[i-1].End()) == line(n.Elts[i].Pos()) {
					report(n.Elts[i].Pos(), "put each field of a multiline keyed literal on its own line")
				}
			}
		case *ast.StructType:
			for _, field := range n.Fields.List {
				if len(field.Names) > 1 {
					report(field.Pos(), "declare each struct field separately")
				}
			}
		case *ast.BlockStmt:
			statements(n.List)
		case *ast.CaseClause:
			statements(n.Body)
		case *ast.CommClause:
			statements(n.Body)
		}
		return true
	})
	slices.SortFunc(findings, func(a, b finding) int {
		if a.line != b.line {
			return a.line - b.line
		}
		return strings.Compare(a.message, b.message)
	})
	return slices.Compact(findings), nil
}
