package utils

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// httpx -screenshot without -system-chrome makes rod download a Chromium build at runtime, with no
// checksum, from storage.googleapis.com or a mirror. Like pdUpdateCheckGuard_test.go this reads the
// compiled source, so an argv that adds -screenshot without -system-chrome goes red.
func TestHttpxScreenshotAlwaysUsesSystemChrome(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	literals := func(list []ast.Expr) map[string]bool {
		out := map[string]bool{}
		for _, e := range list {
			if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					out[s] = true
				}
			}
		}
		return out
	}

	sites := 0
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			var list []ast.Expr
			switch x := n.(type) {
			case *ast.CompositeLit:
				list = x.Elts
			case *ast.CallExpr:
				list = x.Args
			}
			lits := literals(list)
			if lits["-screenshot"] {
				sites++
				if !lits["-system-chrome"] {
					t.Errorf("%s: -screenshot without -system-chrome", fset.Position(n.Pos()))
				}
			}
			return true
		})
	}
	if sites == 0 {
		t.Fatal("found no -screenshot site; the guard is checking nothing")
	}
}
