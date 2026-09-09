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

// responder_binding_test.go — binds each operation's declared success codes
// to the responder its handler actually returns.
//
// declared_status_matrix_test.go pins the 204 set and requires some 2xx on
// mutating operations. Neither is enough: an operation served by the shared
// ResultResponse can declare 201, or both 200 and 204, and stay green — 201
// is a 2xx, and a 204 declared alongside a real 200 is invisible to a set
// that only polices 204. ResultResponse.WriteResponse never calls
// WriteHeader (api/restapi/handler/common.go), so every operation it serves
// answers exactly 200 with a {"result":...} body.
//
// The served set is derived, never listed here: handler functions that
// return &ResultResponse{} (directly or through a helper they return) are
// found by parsing the handler package, and bound to operations through the
// api.*Handler assignments in configure_loxilb_rest_api.go. A new handler
// joining the class therefore cannot join it silently.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	handlerDir    = "handler"
	operationsDir = "operations"
	wiringFile    = "configure_loxilb_rest_api.go"
)

// handlerBinding matches `api.XHandler = pkg.OpIDHandlerFunc(handler.Fn)` in
// the generated wiring file.
var handlerBinding = regexp.MustCompile(
	`api\.\w+Handler\s*=\s*\w+\.(\w+)HandlerFunc\(handler\.(\w+)\)`)

// urlBuilderType and urlBuilderPath read a generated *_urlbuilder.go, which
// carries the operation's raw spec path as a literal. This is an exact
// operation→path binding; deriving the path from the operation name instead
// would have to reimplement go-swagger's naming rules.
var (
	urlBuilderType = regexp.MustCompile(`type (\w+)URL struct`)
	urlBuilderPath = regexp.MustCompile(`var _path = "([^"]+)"`)
)

var opVerbs = []string{"Delete", "Options", "Patch", "Post", "Head", "Put", "Get"}

// resultResponseHandlers parses the handler package and returns the names of
// every function that answers with the shared success responder, following
// returns through helper functions to a fixed point.
func resultResponseHandlers(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, handlerDir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", handlerDir, err)
	}

	funcs := map[string]*ast.FuncDecl{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
					funcs[fn.Name.Name] = fn
				}
			}
		}
	}
	if len(funcs) == 0 {
		t.Fatalf("no functions parsed from %s", handlerDir)
	}

	// Seed: a return of a &ResultResponse{...} composite literal.
	served := map[string]bool{}
	for name, fn := range funcs {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			for _, r := range ret.Results {
				unary, ok := r.(*ast.UnaryExpr)
				if !ok || unary.Op != token.AND {
					continue
				}
				lit, ok := unary.X.(*ast.CompositeLit)
				if !ok {
					continue
				}
				if id, ok := lit.Type.(*ast.Ident); ok && id.Name == "ResultResponse" {
					served[name] = true
				}
			}
			return true
		})
	}
	if len(served) == 0 {
		t.Fatal("no handler returns &ResultResponse{} — the parse is not seeing the handler package")
	}

	// Closure: a return of a call to a function already in the set.
	for changed := true; changed; {
		changed = false
		for name, fn := range funcs {
			if served[name] {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ret, ok := n.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, r := range ret.Results {
					call, ok := r.(*ast.CallExpr)
					if !ok {
						continue
					}
					if id, ok := call.Fun.(*ast.Ident); ok && served[id.Name] {
						served[name] = true
						changed = true
					}
				}
				return true
			})
		}
	}
	return served
}

// boundOperations maps handler function name to the operation IDs it serves.
func boundOperations(t *testing.T) map[string][]string {
	t.Helper()
	src, err := os.ReadFile(wiringFile)
	if err != nil {
		t.Fatalf("read %s: %v", wiringFile, err)
	}
	bound := map[string][]string{}
	for _, m := range handlerBinding.FindAllStringSubmatch(string(src), -1) {
		bound[m[2]] = append(bound[m[2]], m[1])
	}
	if len(bound) == 0 {
		t.Fatalf("no handler bindings parsed from %s", wiringFile)
	}
	return bound
}

// operationPaths maps operation ID to its raw spec path.
func operationPaths(t *testing.T) map[string]string {
	t.Helper()
	paths := map[string]string{}
	err := filepath.Walk(operationsDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(p, "_urlbuilder.go") {
			return err
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		typ := urlBuilderType.FindSubmatch(src)
		route := urlBuilderPath.FindSubmatch(src)
		if typ != nil && route != nil {
			paths[string(typ[1])] = string(route[1])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", operationsDir, err)
	}
	if len(paths) == 0 {
		t.Fatalf("no url builders parsed from %s", operationsDir)
	}
	return paths
}

func verbOf(operationID string) string {
	for _, v := range opVerbs {
		if strings.HasPrefix(operationID, v) {
			return strings.ToUpper(v)
		}
	}
	return ""
}

// TestResultResponseOperationsDeclareOnly200 asserts that every operation
// served by the shared success responder declares exactly {200} as its 2xx
// set — the status that responder really writes.
func TestResultResponseOperationsDeclareOnly200(t *testing.T) {
	served := resultResponseHandlers(t)
	bound := boundOperations(t)
	routes := operationPaths(t)

	type opRef struct{ verb, path, fn string }
	var refs []opRef
	for fn, ops := range bound {
		if !served[fn] {
			continue
		}
		for _, op := range ops {
			verb := verbOf(op)
			if verb == "" {
				t.Errorf("cannot derive an HTTP method from operation %q", op)
				continue
			}
			route, ok := routes[op]
			if !ok {
				t.Errorf("no url builder found for operation %q (handler %s)", op, fn)
				continue
			}
			refs = append(refs, opRef{verb, route, fn})
		}
	}
	if len(refs) == 0 {
		t.Fatal("no operations resolved to the shared success responder")
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].path != refs[j].path {
			return refs[i].path < refs[j].path
		}
		return refs[i].verb < refs[j].verb
	})

	for name, raw := range specVariants() {
		t.Run(name, func(t *testing.T) {
			paths := specPaths(t, raw)
			for _, ref := range refs {
				op, ok := paths[ref.path][strings.ToLower(ref.verb)]
				if !ok {
					t.Errorf("%s %s is wired to handler %s but absent from the spec",
						ref.verb, ref.path, ref.fn)
					continue
				}
				var success []string
				for code := range opResponses(t, op) {
					if strings.HasPrefix(code, "2") {
						success = append(success, code)
					}
				}
				sort.Strings(success)
				if len(success) != 1 || success[0] != "200" {
					t.Errorf("%s %s (handler %s) declares 2xx %v — the shared success responder "+
						"never calls WriteHeader, so it answers 200 with a {\"result\":...} body. "+
						"Declare exactly 200, or return a generated responder that writes the "+
						"status being declared.",
						ref.verb, ref.path, ref.fn, success)
				}
			}
		})
	}
}

// operatorDeclaredCodes pins the response set of the four operator routes to
// what the middleware and handler chain can actually produce.
//
// 403 is reachable on every one of them, including the GETs: AuthorizeRole's
// default branch (pkg/authz/authz.go) denies any principal whose role falls
// outside the closed {admin, viewer} set, regardless of method — and a viewer
// is additionally denied the PUT.
//
// 503 is reachable on all four, but for two different reasons, and both have
// to be accounted for. The generated security chain answers 503 when the
// credential store cannot be reached (authFailure, api/restapi/handler/auth.go)
// -- that arm runs before any handler and does not care about the method, so
// it reaches the GETs too. Separately, SnapshotFreezeMiddleware
// (api/restapi/handler/snapshot.go) returns early for GET/HEAD/OPTIONS, so
// neither the boot-settle nor the restore-active freeze can reach a GET; PUT
// /maintenance is exempt from the maintenance gate by path suffix but not from
// those two, so it picks up a 503 from there as well. GET /status/ready
// carries a third 503, its own readiness verdict.
//
// Reasoning only about the freeze is what left the two GETs under-declared
// when the other codes on these routes were corrected: a store outage answers
// them with a status the specification did not list.
//
// 500 is reachable on none of them: ConfigGetMaintenance, ConfigPutMaintenance
// and ConfigGetDiagnostics return only OK and — for the PUT — BadRequest. No
// 500 responder exists on any of the three.
var operatorDeclaredCodes = map[string][]string{
	"GET /status/ready": {"200", "401", "403", "503"},
	"GET /maintenance":  {"200", "401", "403", "503"},
	"PUT /maintenance":  {"200", "400", "401", "403", "503"},
	"GET /diagnostics":  {"200", "401", "403", "503"},
}

// TestOperatorRoutesDeclareReachableCodes asserts the operator routes declare
// exactly the statuses their chain can emit — no missing 403, and no 500 that
// no responder can write.
func TestOperatorRoutesDeclareReachableCodes(t *testing.T) {
	for name, raw := range specVariants() {
		t.Run(name, func(t *testing.T) {
			paths := specPaths(t, raw)
			for op, want := range operatorDeclaredCodes {
				verb, route, ok := strings.Cut(op, " ")
				if !ok {
					t.Fatalf("malformed pin key %q", op)
				}
				spec, ok := paths[route][strings.ToLower(verb)]
				if !ok {
					t.Errorf("%s missing from spec", op)
					continue
				}
				var got []string
				for code := range opResponses(t, spec) {
					got = append(got, code)
				}
				sort.Strings(got)
				if strings.Join(got, ",") != strings.Join(want, ",") {
					t.Errorf("%s declares %v, want %v", op, got, want)
				}
			}
		})
	}
}
