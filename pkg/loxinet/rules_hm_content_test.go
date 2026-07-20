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
	"reflect"
	"testing"
)

// TestParseExpectedCodes verifies Octavia expected_codes parsing:
// single ("200"), list ("200,202"), range ("200-204"), mixed, and default ("").
func TestParseExpectedCodes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want [][2]uint16
	}{
		{"default-empty", "", [][2]uint16{{200, 200}}},
		{"single", "200", [][2]uint16{{200, 200}}},
		{"list", "200,202", [][2]uint16{{200, 200}, {202, 202}}},
		{"range", "200-204", [][2]uint16{{200, 204}}},
		{"mixed", "200,300-302", [][2]uint16{{200, 200}, {300, 302}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseExpectedCodes(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("parseExpectedCodes(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestExpectedCodesMatch verifies the "ok iff within ANY parsed pair" semantics
// the prober uses to replace the old "2xx || 405" literal — and that malformed
// input degrades safely (no panic; unparseable parts simply do not match).
func TestExpectedCodesMatch(t *testing.T) {
	cases := []struct {
		name  string
		codes string
		code  int
		want  bool
	}{
		{"single-hit", "200", 200, true},
		{"single-miss-404", "200", 404, false},
		{"list-hit-202", "200,202", 202, true},
		{"list-miss-201", "200,202", 201, false},
		{"range-hit-lo", "200-204", 200, true},
		{"range-hit-hi", "200-204", 204, true},
		{"range-hit-mid", "200-204", 202, true},
		{"range-miss-205", "200-204", 205, false},
		{"mixed-hit-301", "200,300-302", 301, true},
		{"mixed-miss-303", "200,300-302", 303, false},
		{"default-200-ok", "", 200, true},
		{"default-404-down", "", 404, false},
		// (d) gate assert: HEAD /healthz with expected 200 marks a 404 backend DOWN.
		{"healthz-404-down", "200", 404, false},
		// malformed input must not panic and must not match.
		{"malformed-no-panic", "abc", 200, false},
		{"malformed-partial", "200,xyz", 200, true},
		{"malformed-partial-miss", "200,xyz", 250, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := expectedCodeOK(parseExpectedCodes(c.codes), c.code)
			if got != c.want {
				t.Fatalf("expectedCodeOK(parse(%q), %d) = %v, want %v", c.codes, c.code, got, c.want)
			}
		})
	}
}
