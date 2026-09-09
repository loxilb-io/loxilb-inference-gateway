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
package aikey

import (
	"errors"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// TestValidateSuppliedKeyRejectionsAreTyped asserts both rejections carry the
// type that decides their HTTP status.
//
// They are two branches of one validator behind one call site, so they must
// classify alike. Left as plain errors, that was decided by whether the
// wording happened to match a phrase in the API layer's fallback classifier:
// the length message contains " must be " and landed on 400, the charset
// message matched nothing and landed on the 500 branch, where its text was
// replaced by a correlation reference — so the caller was told nothing about
// what to fix.
func TestValidateSuppliedKeyRejectionsAreTyped(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want string
	}{
		{"too short", strings.Repeat("k", minSuppliedKeyLen-1), "between"},
		{"too long", strings.Repeat("k", maxSuppliedKeyLen+1), "between"},
		{"control byte", strings.Repeat("k", minSuppliedKeyLen) + "\x01", "printable"},
		{"embedded space", strings.Repeat("k", minSuppliedKeyLen) + " x", "printable"},
		{"non-ascii", strings.Repeat("k", minSuppliedKeyLen) + "é", "printable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSuppliedKey(tc.key)
			if err == nil {
				t.Fatalf("validateSuppliedKey(%q) accepted the key", tc.key)
			}
			var invalid *cmn.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("rejection is %T, not *cmn.ValidationError — the API layer will "+
					"fall back to matching its message text: %v", err, err)
			}
			if invalid.Field != "api_key" {
				t.Errorf("Field = %q, want %q", invalid.Field, "api_key")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message %q does not name the rule (%q)", err.Error(), tc.want)
			}
		})
	}
}

// TestValidateSuppliedKeyAcceptsUsableKeys guards the other direction: the
// rejections above must not have widened into refusing valid key material.
func TestValidateSuppliedKeyAcceptsUsableKeys(t *testing.T) {
	for _, key := range []string{
		strings.Repeat("k", minSuppliedKeyLen),
		strings.Repeat("k", maxSuppliedKeyLen),
		"sk-" + strings.Repeat("A1b2_-.~", 4),
		strings.Repeat("!", minSuppliedKeyLen),
		strings.Repeat("~", minSuppliedKeyLen),
	} {
		if err := validateSuppliedKey(key); err != nil {
			t.Errorf("validateSuppliedKey(%d-char key) = %v, want accepted", len(key), err)
		}
	}
}
