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

// kv_status_vocabulary_test.go — the vocabulary-sync gate. The KV-exact
// status contract publishes its state and reason vocabularies in
// api/swagger.yml (x-kv-status-states / x-kv-status-reason-codes on
// KvExactStatusEntry); this package's constants are the single source of
// truth those blocks transcribe. This test fails the build when the two
// drift in either direction: a constant added without publishing it, or a
// published value no constant backs. Reason strings must therefore be
// declared as constants with the recognized prefixes, never as inline
// literals — a literal is invisible here.

package loxinet

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// constant-name prefixes that carry vocabulary values.
var kvStatusStatePrefixes = []string{"KvExactState"}
var kvStatusReasonPrefixes = []string{"KvAttestReason", "KvTrtllmFault"}

// collectVocabularyConstants AST-scans every non-test Go file of this package
// and returns the string values of constants whose names carry one of the
// given prefixes.
func collectVocabularyConstants(t *testing.T, prefixes []string) map[string]string {
	t.Helper()
	found := map[string]string{} // value -> declaring constant name
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, id := range vs.Names {
					matched := false
					for _, p := range prefixes {
						if strings.HasPrefix(id.Name, p) {
							matched = true
							break
						}
					}
					if !matched || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					val, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("%s: unquote %s: %v", name, lit.Value, err)
					}
					found[val] = id.Name
				}
			}
		}
	}
	return found
}

// publishedVocabulary reads the x-kv-status-* extension blocks off the
// KvExactStatusEntry definition in api/swagger.yml.
func publishedVocabulary(t *testing.T) (version int, states, reasons map[string]bool) {
	t.Helper()
	raw, err := os.ReadFile("../../api/swagger.yml")
	if err != nil {
		t.Fatalf("read swagger: %v", err)
	}
	var doc struct {
		Definitions map[string]struct {
			VocabularyVersion int                    `yaml:"x-kv-status-vocabulary-version"`
			States            map[string]interface{} `yaml:"x-kv-status-states"`
			Reasons           map[string]interface{} `yaml:"x-kv-status-reason-codes"`
		} `yaml:"definitions"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse swagger: %v", err)
	}
	entry, ok := doc.Definitions["KvExactStatusEntry"]
	if !ok {
		t.Fatal("KvExactStatusEntry definition missing from swagger")
	}
	states, reasons = map[string]bool{}, map[string]bool{}
	for k := range entry.States {
		states[k] = true
	}
	for k := range entry.Reasons {
		reasons[k] = true
	}
	return entry.VocabularyVersion, states, reasons
}

func diffVocabulary(t *testing.T, kind string, code map[string]string, published map[string]bool) {
	t.Helper()
	for val, constName := range code {
		if !published[val] {
			t.Errorf("%s %q (constant %s) exists in code but is NOT in the published vocabulary — add it to api/swagger.yml and bump x-kv-status-vocabulary-version", kind, val, constName)
		}
	}
	for val := range published {
		if _, ok := code[val]; !ok {
			t.Errorf("published %s %q has no backing constant — published values are never removed or renamed, so a missing constant means a code-side regression", kind, val)
		}
	}
}

// TestKvStatusVocabularySync: bidirectional code-constants ↔ published
// vocabulary equality for both states and reasons, plus a sane version.
func TestKvStatusVocabularySync(t *testing.T) {
	version, states, reasons := publishedVocabulary(t)
	if version < 1 {
		t.Fatalf("x-kv-status-vocabulary-version = %d, want >= 1", version)
	}
	if len(states) == 0 || len(reasons) == 0 {
		t.Fatalf("published vocabulary empty (states=%d reasons=%d) — extension blocks missing", len(states), len(reasons))
	}
	diffVocabulary(t, "state", collectVocabularyConstants(t, kvStatusStatePrefixes), states)
	diffVocabulary(t, "reason code", collectVocabularyConstants(t, kvStatusReasonPrefixes), reasons)
}
