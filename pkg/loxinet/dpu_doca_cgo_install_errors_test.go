//go:build doca

/*
 * Copyright (c) 2022 NetLOX Inc
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

// TestDocaErrorReason — A2.
// Table-driven test for docaErrorReason: for each known DOCA error
// substring (and nil + generic error), assert the helper returns one of the
// 6 closed-enum reason values used by docaOffloadInstallErrorsTotal.
//
// "null_return" is the catchall for nil + unrecognised; "paired_steer_failed"
// is reserved for the P2 atomic-rollback path, but the helper should still
// recognise it if the error string carries it.

import (
	"errors"
	"testing"
)

func TestDocaErrorReason_AllCodesMapped(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "null_return"},
		{"invalid value", errors.New("rc=DOCA_ERROR_INVALID_VALUE"), "invalid_input"},
		{"invalid input", errors.New("DOCA_ERROR_INVALID_INPUT: bad arg"), "invalid_input"},
		{"invalid input lowercase", errors.New("Invalid input"), "invalid_input"},
		{"insufficient resources", errors.New("rc=LLB_DOCA_INSUFFICIENT_RESOURCES"), "capacity_full"},
		{"full", errors.New("pipe FULL"), "capacity_full"},
		{"capacity word", errors.New("egress_steer at capacity"), "capacity_full"},
		{"timeout", errors.New("rc=DOCA_ERROR_TIME_OUT"), "timeout"},
		{"timeout lowercase", errors.New("op timeout"), "timeout"},
		{"hw busy", errors.New("DOCA_FLOW BUSY: retry later"), "hw_busy"},
		{"paired steer failed", errors.New("paired_steer_failed: reply add"), "paired_steer_failed"},
		{"egress steer", errors.New("egress_steer add failed"), "paired_steer_failed"},
		{"unknown defaults to null_return", errors.New("totally unknown error"), "null_return"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := docaErrorReason(tc.err)
			if got != tc.want {
				t.Errorf("docaErrorReason(%v) = %q, want %q", tc.err, got, tc.want)
			}
			// Belt-and-braces: the result must always be one of the 6 closed-enum values.
			var allowed = map[string]struct{}{
				"invalid_input": {}, "capacity_full": {}, "null_return": {},
				"timeout": {}, "hw_busy": {}, "paired_steer_failed": {},
			}
			if _, ok := allowed[got]; !ok {
				t.Errorf("docaErrorReason returned %q which is NOT in the closed-enum reason set", got)
			}
		})
	}
}
