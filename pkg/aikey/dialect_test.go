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
package aikey

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// sqlVerbs identifies a string literal as SQL. Deliberately broad: the gate
// should catch a statement added anywhere in the package, not only one added
// to the var block it knows about.
var sqlVerbs = []string{"SELECT ", "INSERT ", "UPDATE ", "DELETE ", "CREATE ", "ALTER ", "REPLACE "}

// packageSQLLiterals returns every SQL-looking string literal in the
// package's non-test sources, keyed by position.
func packageSQLLiterals(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	found := map[string]string{}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			upper := strings.ToUpper(s)
			for _, verb := range sqlVerbs {
				if strings.Contains(upper, verb) {
					found[fset.Position(lit.Pos()).String()] = s
					return true
				}
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("scanned no source files — the gate would pass vacuously")
	}
	if len(found) == 0 {
		t.Fatal("found no SQL literals — the gate would pass vacuously")
	}
	return found
}

// U-16 — no MySQL placeholder and no REPLACE INTO survives anywhere in this
// package.
//
// Both failure modes are silent in the wrong way. A '?' placeholder is not a
// placeholder to PostgreSQL, so the statement fails at execution rather than
// at build, on whichever request first reaches it. REPLACE INTO is not
// PostgreSQL syntax at all, and its MySQL semantics — delete then insert —
// reset every column the statement does not name, so translating it to an
// upsert that names every column would preserve a data-loss behaviour rather
// than port it.
func TestNoMySQLDialectSurvives(t *testing.T) {
	for pos, stmt := range packageSQLLiterals(t) {
		if strings.Contains(strings.ToUpper(stmt), "REPLACE INTO") {
			t.Errorf("%s: REPLACE INTO in a PostgreSQL statement: %s", pos, stmt)
		}
		if strings.Contains(stmt, "?") {
			t.Errorf("%s: MySQL '?' placeholder in a PostgreSQL statement: %s", pos, stmt)
		}
	}
}

// Every statement that takes arguments must use $n placeholders, and the ones
// that name a table must name its schema. An unqualified table resolves
// through search_path, a role attribute the gateway cannot verify it still
// has; a table created in the wrong schema shows up much later as keys that
// have gone missing.
func TestStatementsAreSchemaQualified(t *testing.T) {
	for pos, stmt := range packageSQLLiterals(t) {
		upper := strings.ToUpper(stmt)
		// Catalogue queries address PostgreSQL's own schemas by design.
		if strings.Contains(upper, "PG_NAMESPACE") || strings.Contains(upper, "HAS_SCHEMA_PRIVILEGE") ||
			strings.Contains(upper, "CURRENT_USER") {
			continue
		}
		for _, table := range []string{"api_keys", "tenant_rate_limits", "tenant_model_rate_limits"} {
			// The literals build their table names through a %s format verb
			// for the schema, so a qualified reference reads "%s.api_keys".
			if strings.Contains(stmt, " "+table) || strings.Contains(stmt, "."+table) {
				if !strings.Contains(stmt, "%s."+table) {
					t.Errorf("%s: table %q is not schema-qualified: %s", pos, table, stmt)
				}
			}
		}
	}
}

// The upserts must name the columns they set. ON CONFLICT DO UPDATE with an
// explicit SET list is what makes the port a fix rather than a translation:
// it leaves columns the caller does not own untouched, where REPLACE INTO
// reset them.
func TestUpsertsNameTheColumnsTheySet(t *testing.T) {
	for _, tc := range []struct {
		name string
		stmt string
		want []string
	}{
		{"tenant rate limit", sqlUpsertTenantRateLimit,
			[]string{"ON CONFLICT (tenant_id) DO UPDATE SET", "rps = EXCLUDED.rps",
				"tokens_per_min = EXCLUDED.tokens_per_min", "burst_pct = EXCLUDED.burst_pct"}},
		{"tenant model rate limit", sqlUpsertTenantModelRateLimit,
			[]string{"ON CONFLICT (tenant_id, model) DO UPDATE SET",
				"tokens_per_min = EXCLUDED.tokens_per_min"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.want {
				if !strings.Contains(tc.stmt, want) {
					t.Errorf("upsert is missing %q:\n%s", want, tc.stmt)
				}
			}
		})
	}
}

// The authentication lookup must keep filtering on enabled. It is the
// statement that decides whether a revoked key still opens the gate, and the
// dialect port is exactly the kind of change that could drop a predicate
// while looking correct.
func TestAuthLookupStillFiltersDisabledKeys(t *testing.T) {
	if !strings.Contains(sqlSelectAPIKeyByHash, "enabled = TRUE") {
		t.Errorf("the authentication lookup no longer filters on enabled:\n%s", sqlSelectAPIKeyByHash)
	}
	// The management read paths must not filter, or a disabled key vanishes
	// from the listing an operator uses to re-enable it.
	for name, stmt := range map[string]string{
		"by tenant": sqlSelectAPIKeysByTenant,
		"by id":     sqlSelectAPIKeyByID,
		"all":       sqlSelectAllAPIKeys,
	} {
		if strings.Contains(stmt, "enabled = TRUE") {
			t.Errorf("management read path %q filters on enabled, hiding disabled keys:\n%s", name, stmt)
		}
	}
}
