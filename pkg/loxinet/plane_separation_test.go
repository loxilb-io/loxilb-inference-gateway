/*
 * Copyright (c) 2025 LoxiLB Authors
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
package loxinet

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The management plane and the data plane share no object, no store and no
// enable switch. That is a property of the source, not of a running system,
// and it grew back once already because someone reached for the nearest
// available service object. These legs are the mechanical version of the rule:
// they fail the build of this package, so the coupling cannot be reintroduced
// without the reintroduction being read.

// repoRoot is the module root, two levels above this package.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve the repository root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("%s is not the module root: %v", root, err)
	}
	return root
}

// parseGo parses one file, failing the test rather than skipping it: a gate
// that quietly passes over a file it could not read is not a gate.
func parseGo(t *testing.T, path string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return fset, f
}

// importPaths returns the file's import paths with their quotes stripped.
func importPaths(f *ast.File) []string {
	out := make([]string, 0, len(f.Imports))
	for _, imp := range f.Imports {
		out = append(out, strings.Trim(imp.Path.Value, `"`))
	}
	return out
}

// U-10, first half. The AI Gateway bridge is the file the coupling lived in:
// it validated data-plane credentials against the management plane's service
// object, which is how a management token and an API key ended up in one
// cache. It must not be able to see that package or that object at all.
func TestDataPathHasNoManagementPlaneEdge(t *testing.T) {
	path := filepath.Join(repoRoot(t), "pkg", "loxinet", "ai_gateway_dp.go")
	_, f := parseGo(t, path)

	for _, p := range importPaths(f) {
		if strings.HasSuffix(p, "/pkg/user") {
			t.Errorf("ai_gateway_dp.go imports %s: the data plane must not reach the management-plane package", p)
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if ok && ident.Name == "UserService" {
			t.Errorf("ai_gateway_dp.go references UserService: the data plane validates against the key store, not the management plane")
		}
		return true
	})
}

// U-10, second half. The edge must not grow back the other way either: the
// management-plane package has no business reaching into the data-plane key
// store, and an import there would put both planes' caches back in one
// dependency graph.
func TestManagementPlaneHasNoKeyStoreEdge(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "pkg", "user")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	seen := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		seen++
		_, f := parseGo(t, filepath.Join(dir, e.Name()))
		for _, p := range importPaths(f) {
			if strings.HasSuffix(p, "/pkg/aikey") {
				t.Errorf("pkg/user/%s imports %s: the management plane must not reach the data-plane key store", e.Name(), p)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no Go files found in pkg/user — the gate examined nothing")
	}
}

// keyStoreOptionPrefixes name the data-plane key store's connection options.
// Every one of them is read only where the key store is constructed.
var keyStoreOptionPrefixes = []string{"AIKeyDB", "AIKeySSL"}

func isKeyStoreOption(name string) bool {
	for _, p := range keyStoreOptionPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// identsIn collects every identifier appearing under a node.
func identsIn(n ast.Node) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(n, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok {
			out[id.Name] = true
		}
		return true
	})
	return out
}

// goFilesUnder walks the tree collecting Go sources, skipping the directories
// that are not this module's own code.
func goFilesUnder(t *testing.T, root string) []string {
	t.Helper()
	skip := map[string]bool{
		".git": true, "loxilb-ebpf": true, "3rdparty": true,
		"vendor": true, "docs": true, "node_modules": true,
	}
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// U-11. The two subsystems are configured independently, and the way that
// stops being true is a conditional: an `if UserServiceEnable` that also
// decides something about the key store, or the reverse. Reading both options
// in the same function is fine — loxiNetInit constructs both subsystems — but
// neither may be read under the other's condition, because that is precisely
// the dependency this change removes.
func TestOptionCallSitesAreDisjoint(t *testing.T) {
	root := repoRoot(t)
	files := goFilesUnder(t, root)
	if len(files) == 0 {
		t.Fatal("no Go files found — the gate examined nothing")
	}

	checked := 0
	for _, path := range files {
		fset, f := parseGo(t, path)
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			ifStmt, ok := n.(*ast.IfStmt)
			if !ok || ifStmt.Cond == nil {
				return true
			}
			cond := identsIn(ifStmt.Cond)
			body := identsIn(ifStmt.Body)

			condHasUserService := cond["UserServiceEnable"]
			condHasKeyStore := false
			for name := range cond {
				if isKeyStoreOption(name) {
					condHasKeyStore = true
				}
			}
			if !condHasUserService && !condHasKeyStore {
				return true
			}
			checked++

			if condHasUserService {
				for name := range body {
					if isKeyStoreOption(name) {
						t.Errorf("%s:%d: %s is read under `if ... UserServiceEnable`: the key store's availability must not follow from the management plane's enable switch",
							rel, fset.Position(ifStmt.Pos()).Line, name)
					}
				}
			}
			if condHasKeyStore && body["UserServiceEnable"] {
				t.Errorf("%s:%d: UserServiceEnable is read under the key store's condition: the two subsystems are configured independently",
					rel, fset.Position(ifStmt.Pos()).Line)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no conditional read either option — the gate examined nothing")
	}
}

// keyLifecycleHandlers are the seven key-lifecycle registrations. Six are
// swagger-generated; the PATCH arm is dispatched by path.
var keyLifecycleHandlers = []string{
	"AiPostConfigAiApikeyHandler",
	"AiGetConfigAiApikeyHandler",
	"AiGetConfigAiApikeyKeyIDHandler",
	"AiDeleteConfigAiApikeyKeyIDHandler",
	"AiPostConfigAiTenantRatelimitHandler",
	"AiGetConfigAiTenantRatelimitTenantIDHandler",
	"apiKeyPatchHandler",
}

// U-11, applied to the surface the coupling was actually observed on. Whether
// the key lifecycle routes are registered must not depend on --userservice:
// gating them there is what made a gateway with a key store but no user
// service answer 501 on its own keys, as though the feature did not exist.
//
// Who may call them still does depend on management authentication. That is
// the global BearerAuth requirement on the listener, not this.
func TestKeyLifecycleRoutesAreNotGatedOnUserService(t *testing.T) {
	path := filepath.Join(repoRoot(t), "api", "restapi", "configure_loxilb_rest_api.go")
	fset, f := parseGo(t, path)

	present := identsIn(f)
	for _, h := range keyLifecycleHandlers {
		if !present[h] {
			t.Errorf("%s is not registered anywhere in configure_loxilb_rest_api.go", h)
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Cond == nil || !identsIn(ifStmt.Cond)["UserServiceEnable"] {
			return true
		}
		body := identsIn(ifStmt.Body)
		for _, h := range keyLifecycleHandlers {
			if body[h] {
				t.Errorf("%s:%d: %s is registered under `if ... UserServiceEnable`: the key lifecycle API is not a function of the management plane's enable switch",
					filepath.Base(path), fset.Position(ifStmt.Pos()).Line, h)
			}
		}
		return true
	})
}

// The key store is published before it is dialled.
//
// aikey.Connect retries with a doubling backoff and takes tens of seconds
// against a store that is down. For the whole of that window every reader of
// mh.AIKeyService — the key lifecycle API and the data plane alike — sees
// whatever the pointer holds, and nil carries a specific and different
// meaning: that no store was configured. Assigning the pointer only after the
// dial returns therefore reports a configured-but-unreachable store as an
// unconfigured one, which is the distinction the store-status ladder draws.
//
// This is a property of the order of two statements, so it is checked as one.
func TestKeyStoreIsPublishedBeforeItIsDialled(t *testing.T) {
	path := filepath.Join(repoRoot(t), "pkg", "loxinet", "loxinet.go")
	fset, f := parseGo(t, path)

	var checked bool
	ast.Inspect(f, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Cond == nil || !identsIn(ifStmt.Cond)["AIKeyDBHost"] {
			return true
		}
		checked = true

		assignLine, connectLine := -1, -1
		ast.Inspect(ifStmt.Body, func(m ast.Node) bool {
			switch node := m.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if ok && sel.Sel != nil && sel.Sel.Name == "AIKeyService" && assignLine < 0 {
						assignLine = fset.Position(node.Pos()).Line
					}
				}
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if ok && sel.Sel != nil && sel.Sel.Name == "Connect" && connectLine < 0 {
					connectLine = fset.Position(node.Pos()).Line
				}
			}
			return true
		})

		if assignLine < 0 {
			t.Errorf("%s: nothing in the AIKeyDBHost block assigns mh.AIKeyService", filepath.Base(path))
			return true
		}
		if connectLine < 0 {
			t.Errorf("%s:%d: the AIKeyDBHost block never calls Connect, so the store is never dialled",
				filepath.Base(path), assignLine)
			return true
		}
		if assignLine > connectLine {
			t.Errorf("%s: mh.AIKeyService is assigned at line %d but the store is dialled at line %d — for the length of the dial every reader sees nil, which means \"no store configured\"",
				filepath.Base(path), assignLine, connectLine)
		}
		return true
	})

	if !checked {
		t.Fatalf("%s: found no `if ... AIKeyDBHost ...` block to check — the gate matched nothing", filepath.Base(path))
	}
}
