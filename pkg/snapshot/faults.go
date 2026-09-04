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

package snapshot

import (
	"fmt"
	"os"
	"sync"
)

// Test-only deterministic fault injection for the persist/restore paths.
// The CI suites need to interrupt the pipeline at EXACT points (crash
// between the temp write and the rename, error while applying one named
// domain) rather than race kill -9 against a debounce timer -- timing
// races prove nothing when they pass and diagnose nothing when they
// fail. The hook is env-gated: without LOXI_TEST_FAULT in the process
// environment every fault point is a single string comparison against
// "" and production behavior is unchanged. The env var is read once at
// first use, so one gateway process has one deterministic fault plan.
//
// Recognized values:
//
//	persist-after-temp-write        crash (exit) right after the temp
//	                                file's content is written, before it
//	                                is fsynced/renamed
//	persist-before-rename           crash right before the rename would
//	                                publish the temp file
//	restore-mid-apply:<domain>      the forward APPLY of <domain> fails
//	                                with an injected error (rollback runs
//	                                and must succeed)
//	restore-mid-apply-double:<domain>  the APPLY of <domain> fails in the
//	                                forward pass AND again during the
//	                                rollback re-apply (the double-fault
//	                                that must surface ROLLBACK-FAILED,
//	                                never a silent ok)
//	capture-domain-error:<domain>   the capture-side Get of <domain>
//	                                fails with an injected error
const testFaultEnv = "LOXI_TEST_FAULT"

var (
	testFaultOnce sync.Once
	testFaultVal  string
	// faultExit is the crash primitive behind the persist-* fault points,
	// in a var so unit tests can observe the crash instead of dying.
	faultExit = func(point string) {
		fmt.Fprintf(os.Stderr, "LOXI_TEST_FAULT: crashing at %s\n", point)
		os.Exit(101)
	}
)

// readFaultPlan is the single source of the process fault plan: the env
// var, nothing else. Split out so the production-safety pin (the plan is
// EMPTY unless the operator set the env) is testable without fighting
// the once-latch.
func readFaultPlan() string {
	return os.Getenv(testFaultEnv)
}

func testFault() string {
	testFaultOnce.Do(func() { testFaultVal = readFaultPlan() })
	return testFaultVal
}

// faultCrashPoint kills the process iff the env-selected fault names
// this exact point. Inert (one string compare) otherwise.
func faultCrashPoint(point string) {
	if testFault() == point {
		faultExit(point)
	}
}

// faultApplyError reports whether the APPLY of domain must fail with an
// injected error: always for the -double variant, only on the forward
// pass (not the rollback re-apply) for the single variant.
func faultApplyError(domain string, rollback bool) error {
	switch testFault() {
	case "restore-mid-apply:" + domain:
		if rollback {
			return nil
		}
	case "restore-mid-apply-double:" + domain:
	default:
		return nil
	}
	return fmt.Errorf("injected fault: apply %s (%s)", domain, testFaultEnv)
}

// faultCaptureError reports whether the capture-side Get of domain must
// fail with an injected error.
func faultCaptureError(domain string) error {
	if testFault() == "capture-domain-error:"+domain {
		return fmt.Errorf("injected fault: capture %s (%s)", domain, testFaultEnv)
	}
	return nil
}

// setTestFaultForTest pins the fault plan (tests only) and returns a
// restore func; it also forces the once-latch so the env var is not
// consulted afterwards.
func setTestFaultForTest(v string) func() {
	testFaultOnce.Do(func() {})
	prev := testFaultVal
	testFaultVal = v
	return func() { testFaultVal = prev }
}

