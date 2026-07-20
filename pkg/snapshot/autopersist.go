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

import (
	"sync"
	"time"
)

// AutoPersistQuiet is the §6.1 default auto-persist debounce: a burst of
// mutating API calls produces one snapshot.json write this long after the
// last call in the burst.
const AutoPersistQuiet = 3 * time.Second

// AutoPersister is the §6.1 auto-persist debouncer: Kick it on every
// successful mutating config API call and it runs fn once per burst,
// trailing-edge, after `quiet` with no further kicks. fn runs on a timer
// goroutine; it is never invoked concurrently with itself for a single
// burst, but fn must itself guard against the restore gate (a kick can be
// pending when a restore starts). fn may call Kick to reschedule itself —
// the REST layer does exactly that when it finds the gate busy.
type AutoPersister struct {
	quiet time.Duration
	fn    func()

	mu      sync.Mutex
	timer   *time.Timer
	stopped bool
}

// NewAutoPersister returns a debouncer that runs fn `quiet` after the most
// recent Kick. Nothing is scheduled until the first Kick.
func NewAutoPersister(quiet time.Duration, fn func()) *AutoPersister {
	return &AutoPersister{quiet: quiet, fn: fn}
}

// Kick records a config mutation: (re)starts the quiet-period countdown.
func (a *AutoPersister) Kick() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopped {
		return
	}
	if a.timer == nil {
		a.timer = time.AfterFunc(a.quiet, a.fire)
		return
	}
	a.timer.Reset(a.quiet)
}

func (a *AutoPersister) fire() {
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()
	a.fn()
}

// Stop cancels any pending write and ignores further Kicks (tests; shutdown).
func (a *AutoPersister) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopped = true
	if a.timer != nil {
		a.timer.Stop()
	}
}
