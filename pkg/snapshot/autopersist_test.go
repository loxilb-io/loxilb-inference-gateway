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
	"sync/atomic"
	"testing"
	"time"
)

func waitForCount(t *testing.T, c *atomic.Int32, want int32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.Load() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("fire count = %d after %v, want %d", c.Load(), timeout, want)
}

func TestAutoPersisterDebouncesBurstToOneFire(t *testing.T) {
	var fires atomic.Int32
	a := NewAutoPersister(50*time.Millisecond, func() { fires.Add(1) })
	defer a.Stop()

	// A burst of kicks inside the quiet period must coalesce to ONE fire.
	for i := 0; i < 10; i++ {
		a.Kick()
		time.Sleep(5 * time.Millisecond)
	}
	waitForCount(t, &fires, 1, 2*time.Second)

	// Quiet period with no kicks: nothing further fires.
	time.Sleep(120 * time.Millisecond)
	if got := fires.Load(); got != 1 {
		t.Fatalf("fires = %d after idle, want still 1", got)
	}

	// A fresh kick after the burst schedules a second, separate fire.
	a.Kick()
	waitForCount(t, &fires, 2, 2*time.Second)
}

func TestAutoPersisterStopCancelsPendingAndIgnoresKicks(t *testing.T) {
	var fires atomic.Int32
	a := NewAutoPersister(30*time.Millisecond, func() { fires.Add(1) })
	a.Kick()
	a.Stop()
	a.Kick()
	time.Sleep(100 * time.Millisecond)
	if got := fires.Load(); got != 0 {
		t.Fatalf("fires = %d after Stop, want 0", got)
	}
}

func TestAutoPersisterFnMayRescheduleItself(t *testing.T) {
	// The REST layer's fn re-kicks when the snapshot gate is busy; make sure
	// a Kick from inside fn schedules another fire instead of deadlocking.
	var fires atomic.Int32
	var a *AutoPersister
	a = NewAutoPersister(20*time.Millisecond, func() {
		if fires.Add(1) == 1 {
			a.Kick()
		}
	})
	defer a.Stop()
	a.Kick()
	waitForCount(t, &fires, 2, 2*time.Second)
}
