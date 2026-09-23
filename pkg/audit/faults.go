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

package audit

import "sync/atomic"

// Named fault points. In a fault-enabled build exactly one of them can be
// armed through the environment; the harness uses them to prove that the
// failure paths (restart record, retroactive write-failure record, kept
// plain segment) actually fire. Unit tests in this package arm them
// through an internal hook instead, so they run in every build.
const (
	FaultWriterPanic         = "writer.panic"
	FaultWriterWriteFailed   = "writer.write_failed"
	FaultWriterStall         = "writer.stall"
	FaultSegmentRotateFailed = "segment.rotation_failed"
	FaultSegmentGzipFailed   = "segment.compress_failed"
)

// faults is the per-writer fault selector: the compiled-in selector plus a
// test hook. The hook is a pointer load on the write path, which is the
// cheapest check that still lets tests run without the build tag.
type faults struct {
	test atomic.Pointer[string]
}

// oneShot points fire once and disarm themselves: a panic that stayed
// armed would defeat the restart it exists to prove.
func oneShot(point string) bool { return point == FaultWriterPanic }

func (f *faults) armed(point string) bool {
	if p := f.test.Load(); p != nil && *p == point {
		if oneShot(point) {
			f.test.Store(nil)
		}
		return true
	}
	if buildFaultArmed(point) {
		if oneShot(point) {
			buildFaultClear()
		}
		return true
	}
	return false
}

func (f *faults) arm(point string) {
	if point == "" {
		f.test.Store(nil)
		return
	}
	f.test.Store(&point)
}
