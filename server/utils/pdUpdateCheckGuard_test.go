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

// Every ProjectDiscovery tool the server runs performs an update check (a request to
// ProjectDiscovery) on each invocation unless -duc is passed. The runner owns that flag. This reads
// the compiled source with go/parser, like httpNoFollowGuard_test.go, so a new exec site that forgets
// -duc goes red instead of quietly phoning home. nuclei is not listed: docker/nuclei/Dockerfile sets
// disable-update-check in the image config, which covers every nuclei invocation.
var pdExecBinaries = map[string]string{
	"ars0n-framework-v2-subfinder-1":  "subfinder",
	"ars0n-framework-v2-dnsx-1":       "dnsx",
	"ars0n-framework-v2-katana-1":     "katana",
	"ars0n-framework-v2-httpx-1":      "httpx",
	"ars0n-framework-v2-shuffledns-1": "shuffledns",
}

func TestProjectDiscoveryToolsAlwaysRunWithDUC(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	literal := func(e ast.Expr) string {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return ""
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return ""
		}
		return s
	}

	sites := map[string]int{}
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
			for i, e := range list {
				binary, ok := pdExecBinaries[literal(e)]
				if !ok || i+1 >= len(list) || literal(list[i+1]) != binary {
					continue // not a run of the tool itself (cat, ls, docker cp ...)
				}
				sites[binary]++
				if i+2 >= len(list) || literal(list[i+2]) != "-duc" {
					t.Errorf("%s: %s is run without -duc straight after the binary, so it makes an "+
						"update check on every invocation", fset.Position(e.Pos()), binary)
				}
			}
			return true
		})
	}
	for _, binary := range pdExecBinaries {
		if sites[binary] == 0 {
			t.Errorf("found no exec site for %s; the guard is scanning nothing for it", binary)
		}
	}
}
