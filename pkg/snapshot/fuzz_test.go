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

// Fuzz gate over the document intake path: arbitrary (and mutated-valid)
// bytes through Decode + a dry-run Restore must fail CLOSED -- reject with
// errors -- and must never panic and never reach a mutating hook. The
// committed seed corpus includes every golden schema fixture, so the
// mutation space starts from realistic documents rather than noise.

package snapshot

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzRestoreDryRunFailsClosed(f *testing.F) {
	seeds, _ := filepath.Glob(filepath.Join("testdata", "snapshot-v*.json"))
	for _, s := range seeds {
		raw, err := os.ReadFile(s)
		if err != nil {
			f.Fatalf("seed %s: %v", s, err)
		}
		f.Add(raw)
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema_version":"1.2","kind":"loxilb-snapshot"}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		hooks := newMockHooks()
		e := newTestEngine(hooks, t.TempDir())

		res, err := e.Restore(raw, RestoreOptions{Mode: ModeDryRun})
		if err != nil {
			t.Fatalf("engine-level error on document input (must be reported via Result.Errors): %v", err)
		}
		if res == nil {
			t.Fatalf("Restore returned nil result")
		}
		// A dry run must NEVER mutate, no matter what the document said.
		if call := firstMutatingCall(hooks.Calls); call != "" {
			t.Fatalf("dry-run reached mutating hook %q", call)
		}
		// Fail closed: anything not fully valid must carry errors, and a
		// pipeline that reports no errors must have been checksum-gated
		// (i.e. only a document whose checksum verifies can plan).
		if len(res.Errors) == 0 && res.Result != ResultOK {
			t.Fatalf("no errors reported but result is %q -- silent partial acceptance", res.Result)
		}
	})
}
