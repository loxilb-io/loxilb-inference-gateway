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

// The data path reaches the trail through this package-level handle rather
// than through the management gate's own accessor. The gate lives in the
// REST handler package, and the datapath bridge may not import it: the
// import runs the wrong way and would drag the whole API surface into the
// packet path. The writer is a process-wide singleton either way, so the
// package that defines it is the honest place to hold it.
//
// It is nil until the trail starts and nil again after it closes. Every
// caller must treat nil as "no trail right now" and carry on: the data path
// answers requests whether or not it can be recorded, and a record it could
// not write is counted by the caller, never waited on.
var global atomic.Pointer[Writer]

// SetGlobal installs the process-wide writer. A nil argument clears it,
// which is what shutdown does before the writer drains.
func SetGlobal(w *Writer) { global.Store(w) }

// Global returns the process-wide writer, or nil when no trail is running.
func Global() *Writer { return global.Load() }
