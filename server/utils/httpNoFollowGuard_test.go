package utils

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------------------------
// THE GUARD THAT DID NOT EXIST.
//
// Twelve call sites were moved off http.Client + http.ErrUseLastResponse, because net/http parses
// the Location header of a 3xx BEFORE it consults CheckRedirect and discards the whole response
// when that parse fails. Exactly ONE of them had a test pinning the conversion
// (detectedFlowRun_test.go). The other eleven could be reverted to a raw http.Client by accident,
// by a merge, or by someone "simplifying" an unfamiliar type, and nothing would go red: the code
// would compile, the scans would run, and the only symptom would be findings quietly not being
// reported.
//
// These tests read the source with go/parser rather than by grepping text, so a mention in a
// comment, in a string literal or in a test fixture cannot satisfy or trip them. What is asserted
// is the shape of the code that actually compiles.
// ---------------------------------------------------------------------------------------------

// noFollowSites never walk a chain. Each must build a NoFollowClient and none may reach
// http.ErrUseLastResponse, which is only meaningful on the redirect loop they no longer enter.
var noFollowSites = []string{
	"authFlowsUtils.go",
	"consolidateAttackSurface.go",
	"detectedFlowRun.go",
	"flowConditions.go",
	"redirectPayloads.go",
	"redirectProbe.go",
	"scanHTTP.go",
	"triageEncode.go",
	"urlScanUtils.go",
}

// followingSites genuinely want the chain walked, so they keep an http.Client and must go through
// the recovery. Without it an unparseable Location anywhere in the chain loses the WHOLE page,
// not just the hop.
var followingSites = []string{
	"endpointInvestigationUtils.go",
	"investigateUtils.go",
	"ffufURLScan.go",
	"ipPortScanUtils.go",
	"metaDataUtils.go",
}

// errUseLastResponseIsAllowed names the only files where http.ErrUseLastResponse is still correct,
// with the reason. Anything else that reaches for it is a site going back to the broken loop.
var errUseLastResponseIsAllowed = map[string]string{
	// Caps the chain at three hops inside CheckRedirect. It is a hop LIMIT here, not a refusal to
	// follow, and the site is covered by the GetFollowing assertion below instead.
	"investigateUtils.go": "hop limit inside CheckRedirect, not a no-follow client",
	// The same: a ten-hop cap inside CheckRedirect on a client that is meant to follow. Covered
	// by the DoFollowing assertion below.
	"endpointInvestigationUtils.go": "hop limit inside CheckRedirect, not a no-follow client",
	// FetchPreludeTokens takes an *http.Client by signature, so its client cannot be a
	// NoFollowClient. It is protected by LocationNeutralizingTransport instead, which is only
	// sound because the prelude never reads Location.
	"triageRun.go": "prelude client, protected by LocationNeutralizingTransport",
}

func TestNoConvertedSiteHasQuietlyReintroducedTheRedirectLoop(t *testing.T) {
	for _, name := range noFollowSites {
		f := parseSourceFile(t, name)
		if usesSelector(f, "http", "ErrUseLastResponse") {
			t.Errorf("%s: http.ErrUseLastResponse is back in compiled code. That only means "+
				"anything inside net/http's redirect loop, and entering that loop is what "+
				"discards a 3xx whose Location will not parse: the response that proves an open "+
				"redirect is the response most likely to be thrown away.", name)
		}
		if !callsFunc(f, "NewNoFollowClient") {
			t.Errorf("%s: no NewNoFollowClient call, so this site is no longer converted and is "+
				"back to losing a response the target delivered in full.", name)
		}
	}

	for _, name := range followingSites {
		f := parseSourceFile(t, name)
		if !callsFunc(f, "DoFollowing") && !callsFunc(f, "GetFollowing") {
			t.Errorf("%s: a client that follows with no recovery loses the WHOLE page when any "+
				"hop carries an unparseable Location, not just that hop.", name)
		}
	}
}

// The list above can only pin the sites someone thought to list. This catches the next one: any
// file in the package reaching for http.ErrUseLastResponse that is not on the allow-list.
func TestNoNewSiteReachesForErrUseLastResponse(t *testing.T) {
	var offenders []string
	for _, path := range packageGoFiles(t) {
		name := filepath.Base(path)
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		if _, ok := errUseLastResponseIsAllowed[name]; ok {
			continue
		}
		if usesSelector(parseSourceFile(t, name), "http", "ErrUseLastResponse") {
			offenders = append(offenders, name)
		}
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("http.ErrUseLastResponse in %v. It reads as \"do not follow\" and is not: "+
			"net/http parses Location and discards the response BEFORE CheckRedirect is "+
			"consulted, so the setting never runs on the case that matters. Use "+
			"NewNoFollowClient. If this site genuinely must keep it, add it to "+
			"errUseLastResponseIsAllowed with the reason.", offenders)
	}
}

// NoFollowClient must never hand its *http.Client back out, or the broken loop becomes reachable
// again through it and every guard above is decorative.
func TestNoFollowClientNeverExposesAnHTTPClient(t *testing.T) {
	f := parseSourceFile(t, "httpNoFollow.go")
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Type.Results == nil {
			return true
		}
		if !strings.Contains(typeString(fn.Recv.List[0].Type), "NoFollowClient") {
			return true
		}
		for _, res := range fn.Type.Results.List {
			if strings.Contains(typeString(res.Type), "http.Client") {
				t.Errorf("(*NoFollowClient).%s returns an *http.Client, so a caller can reach "+
					"the redirect loop again and the type stops being a guarantee", fn.Name.Name)
			}
		}
		return true
	})
}

// --- helpers -----------------------------------------------------------------------------------

func parseSourceFile(t *testing.T, name string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return f
}

func packageGoFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
			out = append(out, e.Name())
		}
	}
	if len(out) == 0 {
		t.Fatal("no .go files found; the guard would pass vacuously")
	}
	return out
}

// usesSelector reports whether the file contains the expression pkg.Name in compiled code.
// Comments are not in the AST and a string literal is not a selector, so neither can trip it.
func usesSelector(f *ast.File, pkg, name string) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == pkg {
			found = true
		}
		return true
	})
	return found
}

// callsFunc reports whether the file calls a package-local function by that name.
func callsFunc(f *ast.File, name string) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == name {
			found = true
		}
		return true
	})
	return found
}

func typeString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return "*" + typeString(t.X)
	case *ast.SelectorExpr:
		return typeString(t.X) + "." + t.Sel.Name
	case *ast.Ident:
		return t.Name
	}
	return ""
}
