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
package user

import (
	"os"
	"testing"

	tk "github.com/loxilb-io/loxilib"
)

// packageLogPath is where every test's tk.LogIt output lands. The logger is
// package-global state, and some tests deliberately leave background work
// running past their own return (the constructor's store dial, which logs its
// failures). Re-initializing the logger per test therefore races that work's
// log writes — the race detector fails the package on a scheduling
// coincidence, and in the product the logger is initialized exactly once,
// before any service exists, so per-test re-init also tests an ordering the
// product cannot reach. Initialize once, here, before any test runs.
var packageLogPath string

func TestMain(m *testing.M) {
	f, err := os.CreateTemp("", "loxilb-user-test-*.log")
	if err != nil {
		os.Exit(1)
	}
	packageLogPath = f.Name()
	f.Close()

	tk.LogItInit(packageLogPath, tk.LogDebug, false)

	code := m.Run()
	os.Remove(packageLogPath)
	os.Exit(code)
}
