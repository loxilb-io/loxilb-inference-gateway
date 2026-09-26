/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package restapi

// audit_gate_routes_test.go — the route enumeration behind the audit gate.
//
// The gate's contract is that no management route can change state
// without a record. A predicate can only be trusted against the full
// route set, so this file walks every declared operation, every route
// the extras specification describes, and every raw dispatch in
// setupGlobalMiddleware, and checks each against the gate's own tables.
// A new mutating route is gated by construction; the tests here exist for
// the cases construction does not cover: a GET handler that starts
// writing state, a raw dispatch added without a row, and an export-class
// read that goes unlisted.

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/api/restapi/handler"
	"gopkg.in/yaml.v3"
)

// stateWritingHooks are the calls that create or replace a session or a
// login state. A GET handler reaching any of them, directly or through one
// helper, must be on the gate's GET allowlist.
var stateWritingHooks = map[string]bool{
	"NetOauthUserTokenStore": true,
	"NetUserLogin":           true,
	"GenerateStateToken":     true,
}

func swaggerOperations(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for path, ops := range specPaths(t, SwaggerJSON) {
		for _, verb := range []string{"get", "post", "put", "patch", "delete", "head", "options"} {
			if _, ok := ops[verb]; ok {
				out[path] = append(out[path], strings.ToUpper(verb))
			}
		}
	}
	return out
}

// TestAuditGateCoversEveryMutatingOperation asserts the exclusion list is
// empty: every declared non-read operation is gated, whatever its path.
func TestAuditGateCoversEveryMutatingOperation(t *testing.T) {
	var mutating, gated int
	for path, verbs := range swaggerOperations(t) {
		for _, verb := range verbs {
			if verb == http.MethodGet || verb == http.MethodHead || verb == http.MethodOptions {
				continue
			}
			mutating++
			if ok, _ := handler.AuditGated(verb, path); ok {
				gated++
			} else {
				t.Errorf("%s %s is not gated", verb, path)
			}
		}
	}
	if mutating == 0 || gated != mutating {
		t.Fatalf("gated %d of %d mutating operations", gated, mutating)
	}
}

// TestAuditGateGETAllowlistMatchesStateWritingHandlers derives the set of
// GET operations whose handler reaches a state-writing hook from the
// source, and asserts it equals the gate's allowlist in both directions.
func TestAuditGateGETAllowlistMatchesStateWritingHandlers(t *testing.T) {
	writers := handlerFuncsReaching(t, "handler", stateWritingHooks)
	getOps := generatedRoutes(t, http.MethodGet)
	wired := wiredHandlers(t)

	want := map[string]bool{}
	for opName, fn := range wired {
		if !writers[fn] {
			continue
		}
		if route, ok := getOps[opName]; ok {
			want[route] = true
		}
	}
	got := map[string]bool{}
	for _, tpl := range handler.AuditGETAllowlist() {
		got[tpl] = true
	}
	for tpl := range want {
		if !got[tpl] {
			t.Errorf("GET %s reaches a state-writing hook but is not on the gate's allowlist", tpl)
		}
	}
	for tpl := range got {
		if !want[tpl] {
			t.Errorf("GET %s is on the allowlist but no handler of it writes state — remove it or list the hook", tpl)
		}
		if _, declared := getOps[routeName(http.MethodGet, tpl)]; !declared {
			if !declaredPath(t, tpl) {
				t.Errorf("allowlisted GET %s is not a declared route", tpl)
			}
		}
	}
	if len(want) == 0 {
		t.Fatal("no state-writing GET handler found; the hook list or the parser is stale")
	}
}

// TestAuditGateRawRoutesMatchDispatchSites asserts the gate's raw table is
// exactly the set of paths setupGlobalMiddleware dispatches itself, and
// that every route the extras specification describes is among them.
func TestAuditGateRawRoutesMatchDispatchSites(t *testing.T) {
	sites := rawDispatchPaths(t)
	table := map[string]bool{}
	for _, tpl := range handler.AuditRawRoutes() {
		table[tpl] = true
	}
	for p := range sites {
		if !table[p] {
			t.Errorf("setupGlobalMiddleware dispatches %s but the gate's raw table has no row for it", p)
		}
	}
	for p := range table {
		if !sites[p] {
			t.Errorf("gate raw table lists %s but setupGlobalMiddleware has no dispatch for it", p)
		}
	}
	raw, err := os.ReadFile(extrasSpecPath)
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Paths) == 0 {
		t.Fatal("extras specification declares no paths")
	}
	for p := range spec.Paths {
		if !table[p] {
			t.Errorf("extras route %s is not in the gate's raw table", p)
		}
	}
}

// listingHooks are the calls that read credential or account metadata. A
// GET handler reaching any of them, directly or through one helper, must
// be on the gate's listing-read table.
var listingHooks = map[string]bool{
	"NetUserGet":    true,
	"NetAPIKeyList": true,
	"NetAPIKeyGet":  true,
}

// TestAuditGateListReadsMatchListingHandlers derives the GET operations
// whose handler reaches a listing hook from the source and asserts they
// are exactly the gate's listing-read table, each a declared route gated
// as class read.
func TestAuditGateListReadsMatchListingHandlers(t *testing.T) {
	readers := handlerFuncsReaching(t, "handler", listingHooks)
	getOps := generatedRoutes(t, http.MethodGet)
	wired := wiredHandlers(t)

	want := map[string]bool{}
	for opName, fn := range wired {
		if !readers[fn] {
			continue
		}
		if route, ok := getOps[opName]; ok {
			want[route] = true
		}
	}
	got := map[string]bool{}
	for _, tpl := range handler.AuditListReads() {
		got[tpl] = true
	}
	for tpl := range want {
		if !got[tpl] {
			t.Errorf("GET %s reaches a listing hook but is not on the gate's listing-read table", tpl)
		}
	}
	for tpl := range got {
		if !want[tpl] {
			t.Errorf("GET %s is on the listing-read table but no handler of it reaches a listing hook", tpl)
		}
		if !declaredPath(t, tpl) {
			t.Errorf("listing read %s is not a declared route", tpl)
		}
		if gated, class := handler.AuditGated(http.MethodGet, tpl); !gated || class != "read" {
			t.Errorf("listing read %s is not gated as class read", tpl)
		}
	}
	if len(want) == 0 {
		t.Fatal("no listing GET handler found; the hook list or the parser is stale")
	}
}

// TestAuditGateExportReadsAreDeclared asserts every export-class read the
// gate lists is a declared GET, and that the list is exactly the routes
// that serve a configuration document or an archive.
func TestAuditGateExportReadsAreDeclared(t *testing.T) {
	want := []string{"/config/export", "/config/snapshot", "/log-archives/{filename}"}
	got := handler.AuditExportReads()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("export reads %v, want %v — a new export-class route needs a row", got, want)
	}
	for _, tpl := range got {
		if !declaredPath(t, tpl) {
			t.Errorf("export read %s is not a declared route", tpl)
		}
		if gated, class := handler.AuditGated(http.MethodGet, tpl); !gated || class != "read" {
			t.Errorf("export read %s is not gated as class read", tpl)
		}
	}
}

func declaredPath(t *testing.T, tpl string) bool {
	t.Helper()
	_, ok := specPaths(t, SwaggerJSON)[tpl]
	return ok
}

func routeName(method, tpl string) string { return method + " " + tpl }

// generatedRoutes maps the generated operation type name to its route for
// the given method, from the swagger:route line every generated operation
// carries.
func generatedRoutes(t *testing.T, method string) map[string]string {
	t.Helper()
	re := regexp.MustCompile(`^\s*(\w+) swagger:route (\w+) (\S+)`)
	out := map[string]string{}
	err := filepath.WalkDir("operations", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			m := re.FindStringSubmatch(line)
			if m == nil || m[2] != method {
				continue
			}
			out[m[1]] = m[3]
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatalf("no swagger:route lines found for %s", method)
	}
	return out
}

// wiredHandlers maps the generated operation type name to the handler
// function configureAPI assigns to it: api.<X>Handler = <pkg>.<X>HandlerFunc(handler.<F>).
func wiredHandlers(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "configure_loxilb_rest_api.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !strings.HasSuffix(sel.Sel.Name, "HandlerFunc") {
			return true
		}
		arg, ok := call.Args[0].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := arg.X.(*ast.Ident); !ok || pkg.Name != "handler" {
			return true
		}
		out[strings.TrimSuffix(sel.Sel.Name, "HandlerFunc")] = arg.Sel.Name
		return true
	})
	if len(out) == 0 {
		t.Fatal("no handler assignments found in configureAPI")
	}
	return out
}

// handlerFuncsReaching returns the functions of the package in dir that
// call one of the hooks directly, or call a package function that does.
func handlerFuncsReaching(t *testing.T, dir string, hooks map[string]bool) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				callees := map[string]bool{}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch fn := call.Fun.(type) {
					case *ast.Ident:
						callees[fn.Name] = true
					case *ast.SelectorExpr:
						callees[fn.Sel.Name] = true
					}
					return true
				})
				calls[fd.Name.Name] = callees
			}
		}
	}
	direct := map[string]bool{}
	for fn, callees := range calls {
		for c := range callees {
			if hooks[c] {
				direct[fn] = true
			}
		}
	}
	out := map[string]bool{}
	for fn, callees := range calls {
		if direct[fn] {
			out[fn] = true
			continue
		}
		for c := range callees {
			if direct[c] {
				out[fn] = true
			}
		}
	}
	return out
}

// rawDispatchPaths reads the paths setupGlobalMiddleware dispatches itself:
// the condition of every if statement whose body runs
// RequireManagementAuth, compared against r.URL.Path exactly or by prefix.
// A path comparison that only buffers a body is not a dispatch and is not
// collected.
func rawDispatchPaths(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "configure_loxilb_rest_api.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "setupGlobalMiddleware" {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatal("setupGlobalMiddleware not found")
	}
	const base = "/netlox/v1"
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || !callsRequireManagementAuth(ifs.Body) {
			return true
		}
		ast.Inspect(ifs.Cond, func(c ast.Node) bool {
			switch e := c.(type) {
			case *ast.BinaryExpr:
				if e.Op == token.EQL && isURLPath(e.X) {
					if lit, ok := e.Y.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						out[strings.TrimPrefix(strings.Trim(lit.Value, `"`), base)] = true
					}
				}
			case *ast.CallExpr:
				sel, ok := e.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "HasPrefix" || len(e.Args) != 2 || !isURLPath(e.Args[0]) {
					return true
				}
				if lit, ok := e.Args[1].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					// A prefix dispatch takes one trailing path parameter.
					prefix := strings.TrimPrefix(strings.Trim(lit.Value, `"`), base)
					out[prefix+"{"+prefixParamName(prefix)+"}"] = true
				}
			}
			return true
		})
		return true
	})
	if len(out) == 0 {
		t.Fatal("no raw dispatch found in setupGlobalMiddleware")
	}
	return out
}

func callsRequireManagementAuth(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "RequireManagementAuth" {
				found = true
			}
		}
		return !found
	})
	return found
}

// prefixParamName names the path parameter of a prefix dispatch the way
// the specification does.
func prefixParamName(prefix string) string {
	if prefix == "/config/ai/apikey/" {
		return "key_id"
	}
	return "id"
}

func isURLPath(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Path" {
		return false
	}
	inner, ok := sel.X.(*ast.SelectorExpr)
	if !ok || inner.Sel.Name != "URL" {
		return false
	}
	id, ok := inner.X.(*ast.Ident)
	return ok && id.Name == "r"
}

// keep json imported for specPaths' signature in this package
var _ = json.Marshal
var _ = sort.Strings
