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
package handler

// error_classification_test.go — the two properties that keep an input
// rejection from surfacing as an internal error.
//
// ResultErrorResponseErrorMessage decides the HTTP status by searching the
// message for one of an open-ended list of phrases. That is positional
// (whoever writes the wording decides the status) and case-fragile (the
// haystack is lowercased before the search, so a mixed-case needle can never
// match). Both failure modes shipped: two adjacent branches of one validator
// classified 400 and 500, and three CORS needles were dead on arrival.

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// TestValidationErrorClassifiesAs400 asserts a typed input rejection is a 400
// carrying its own text, whatever its wording — the structural guarantee that
// replaces guessing from the message.
func TestValidationErrorClassifiesAs400(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{
			// The wording that used to match " must be " and land on 400.
			name: "wording that the phrase table happens to match",
			err:  cmn.NewValidationError("api_key", "supplied API key must be between 16 and 512 characters"),
		},
		{
			// The wording that matched nothing and landed on 500, with its
			// text replaced by a correlation reference.
			name: "wording that the phrase table does not match",
			err:  cmn.NewValidationError("api_key", "supplied API key must contain only printable non-space ASCII characters"),
		},
		{
			name: "wrapped rejection",
			err:  fmt.Errorf("create api key: %w", cmn.NewValidationError("api_key", "zzz unmatchable wording zzz")),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResultErrorResponseError(tc.err)
			if got.Code != 400 {
				t.Errorf("Code = %d, want 400", got.Code)
			}
			if !strings.Contains(got.Result, tc.err.Error()) {
				t.Errorf("Result = %q, does not carry the rejection %q — a caller "+
					"cannot tell what to fix", got.Result, tc.err.Error())
			}
			if strings.Contains(got.Result, "Internal service error") {
				t.Errorf("Result = %q — an input rejection was answered as an internal error",
					got.Result)
			}
		})
	}
}

// TestValidationErrorNamesTheField asserts an attributed rejection reports the
// input it refused, so a client can point at the field rather than parse prose.
func TestValidationErrorNamesTheField(t *testing.T) {
	got := ResultErrorResponseError(cmn.NewValidationError("api_key", "some rejection"))
	if len(got.Fields) != 1 || got.Fields[0] != "api_key" {
		t.Errorf("Fields = %v, want [api_key]", got.Fields)
	}
	// An unattributed rejection must still serialize an empty list rather
	// than a null.
	if got := ResultErrorResponseError(&cmn.ValidationError{Err: errors.New("x")}); got.Fields == nil {
		t.Error("Fields is nil for an unattributed rejection, want an empty list")
	}
}

// TestCorsRejectionIsNotAnInternalError covers the reported trigger through
// the message classifier: an empty CORS URL is a client mistake.
func TestCorsRejectionIsNotAnInternalError(t *testing.T) {
	for _, msg := range []string{
		"Cors URL cannot be empty",
		"Failed to add Cors URL: boom",
		"Failed to delete Cors URL: boom",
	} {
		got := ResultErrorResponseErrorMessage(msg)
		if got.Code != 400 {
			t.Errorf("%q classified %d, want 400", msg, got.Code)
		}
		if strings.Contains(got.Result, "Internal service error") {
			t.Errorf("%q was answered as an internal error: %q", msg, got.Result)
		}
	}
}

// TestClassifierNeedlesAreLowercase asserts the invariant the classifier
// itself assumes but never enforced: it lowercases the message before
// searching, so a needle carrying an uppercase letter can never match.
//
// The needles are read from the source rather than restated here — a
// hand-copied list would be exactly as capable of drifting as the table it is
// meant to police.
func TestClassifierNeedlesAreLowercase(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "common.go", nil, 0)
	if err != nil {
		t.Fatalf("parse common.go: %v", err)
	}

	seen := 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := call.Fun.(*ast.Ident)
		if !ok || fn.Name != "containsAny" {
			return true
		}
		// The first argument is the haystack; the rest are needles.
		for _, arg := range call.Args[1:] {
			lit, ok := arg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			needle, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}
			seen++
			if needle != strings.ToLower(needle) {
				t.Errorf("%s: needle %q is not lowercase — containsAny is called on a "+
					"lowercased message, so this can never match",
					fset.Position(lit.Pos()), needle)
			}
		}
		return true
	})

	if seen == 0 {
		t.Fatal("no containsAny needles found — the parse is not seeing the classifier")
	}
	t.Logf("checked %d classifier needles", seen)
}

// flatteningCeiling is the number of call sites that still discard an error
// value by classifying err.Error() instead of the error itself. It is a
// ratchet, not a target: it must never rise, and it drops as handlers are
// converted to ResultErrorResponseError. Lower it when you convert some.
//
// Flattening is what made the reported defect possible. Once the error is a
// string, the only signal left is its wording, so the status is decided by a
// substring search over an open-ended phrase table — which is why two
// branches of one validator classified 400 and 500.
const flatteningCeiling = 127

// TestErrorFlatteningDoesNotGrow pins that ratchet, and pins to zero the
// handler this change converted.
func TestErrorFlatteningDoesNotGrow(t *testing.T) {
	perFile, err := countFlatteningSites()
	if err != nil {
		t.Fatalf("scan handlers: %v", err)
	}

	total := 0
	for _, n := range perFile {
		total += n
	}
	if total == 0 {
		t.Fatal("no call sites found at all — the scan is not seeing the handler package")
	}
	if total > flatteningCeiling {
		t.Errorf("%d call sites classify err.Error() instead of the error, ceiling is %d. "+
			"New code must pass the error value to ResultErrorResponseError so a typed "+
			"rejection keeps its status; see %v", total, flatteningCeiling, perFile)
	}
	if total < flatteningCeiling {
		t.Errorf("only %d call sites remain but the ceiling is still %d — lower "+
			"flatteningCeiling to %d so the ratchet keeps holding", total, flatteningCeiling, total)
	}

	if n := perFile["ai_apikey.go"]; n != 0 {
		t.Errorf("ai_apikey.go has %d flattening call sites, want 0 — its rejections are "+
			"typed, and flattening them here throws that away again", n)
	}
}

// countFlatteningSites returns, per handler file, the number of
// ResultErrorResponseErrorMessage(x.Error()) calls.
func countFlatteningSites() (map[string]int, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, err
	}

	counts := map[string]int{}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				outer, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn, ok := outer.Fun.(*ast.Ident)
				if !ok || fn.Name != "ResultErrorResponseErrorMessage" || len(outer.Args) != 1 {
					return true
				}
				// The argument is an error only when it is an .Error() call;
				// a string literal carries no type to lose.
				inner, ok := outer.Args[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := inner.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Error" {
					return true
				}
				counts[filepath.Base(name)]++
				return true
			})
		}
	}
	return counts, nil
}
