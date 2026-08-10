/*
 * Copyright (c) 2026 LoxiLB Authors
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

import "sync/atomic"

// The REST API server starts serving before the boot-time config replay
// (snapshot.json restore or legacy *.txt replay) has run. Without a gate, a
// client write landing in that window can race the boot restore -- the
// restore then sees state it did not create, fails on it, and rolls back
// config that was applied moments earlier; worse, the write's auto-persist
// can then capture the half-applied or rolled-back state over
// snapshot.json, making the loss durable. This was observed live: a plain
// container restart under concurrent client writes wiped every LB rule and
// overwrote the snapshot with the empty result.
//
// bootConfigSettled starts false and is set exactly once, when the boot
// config replay has fully settled (or when the deployment mode runs no
// replay at all). The mutation-freeze middleware rejects config writes
// (503 + Retry-After) until then, and the auto-persist debouncer refuses
// to write snapshot.json before it.
var bootConfigSettled atomic.Bool

// MarkBootConfigSettled opens the boot-config gate: the boot config replay
// has fully settled (successfully or not -- a failed boot restore also
// settles, after quarantining its snapshot) or this deployment mode never
// runs one. Called from the boot replay's exit paths and from the
// no-replay init paths (API-only / BGP-peer modes).
func MarkBootConfigSettled() {
	bootConfigSettled.Store(true)
}

// BootConfigSettled reports whether the boot config replay has settled.
// Mutating config API calls must be rejected while this is false.
func BootConfigSettled() bool {
	return bootConfigSettled.Load()
}
