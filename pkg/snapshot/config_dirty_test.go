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
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// resetDirtyState rewinds the package-global sequence pair so each test
// observes gauge transitions from a clean slate (the gauge itself is
// process-global; only the relative transitions are asserted).
func resetDirtyState() {
	dirtyMu.Lock()
	defer dirtyMu.Unlock()
	mutationSeq = 0
	persistedSeq = 0
	configDirty.Set(0)
}

func dirtyValue() float64 { return testutil.ToFloat64(configDirty) }

// A mutation sets the gauge; a persist that began after it clears it.
func TestConfigDirtyMutateThenPersistClears(t *testing.T) {
	resetDirtyState()

	if dirtyValue() != 0 {
		t.Fatalf("clean slate not 0")
	}
	MarkConfigMutated()
	if dirtyValue() != 1 {
		t.Fatalf("mutation did not set dirty")
	}
	seq := beginPersistSeq()
	completePersistSeq(seq)
	if dirtyValue() != 0 {
		t.Fatalf("persist covering the mutation did not clear dirty")
	}
}

// A mutation landing AFTER a persist's capture started must survive that
// persist's completion — this is the reason dirty is a sequence pair, not
// a boolean cleared on any successful write.
func TestConfigDirtyMutationDuringPersistStaysDirty(t *testing.T) {
	resetDirtyState()

	MarkConfigMutated()
	seq := beginPersistSeq() // persist begins, capture running
	MarkConfigMutated()      // races the capture: may not be in the doc
	completePersistSeq(seq)  // persist succeeds
	if dirtyValue() != 1 {
		t.Fatalf("mutation during persist was lost: dirty=0")
	}
	// The NEXT persist (whose capture starts after the racing mutation)
	// clears it.
	completePersistSeq(beginPersistSeq())
	if dirtyValue() != 0 {
		t.Fatalf("follow-up persist did not clear dirty")
	}
}

// A failed persist never claims its watermark: the caller simply does not
// call completePersistSeq, so dirty stays 1. Out-of-order completions
// (older persist finishing after a newer one) must not regress the
// watermark either.
func TestConfigDirtyOutOfOrderPersistCompletions(t *testing.T) {
	resetDirtyState()

	MarkConfigMutated()
	seqOld := beginPersistSeq()
	MarkConfigMutated()
	seqNew := beginPersistSeq()

	completePersistSeq(seqNew)
	if dirtyValue() != 0 {
		t.Fatalf("newer persist should have cleared dirty")
	}
	completePersistSeq(seqOld) // stale completion arrives late
	if dirtyValue() != 0 {
		t.Fatalf("stale persist completion regressed the dirty state")
	}
	MarkConfigMutated()
	completePersistSeq(seqOld) // stale watermark cannot clear a new mutation
	if dirtyValue() != 1 {
		t.Fatalf("stale watermark cleared a mutation it never covered")
	}
}

// The sequence pair is written from REST handler goroutines and the
// auto-persist timer concurrently; -race must stay clean and the final
// state must be consistent (all mutations covered by the final persist).
func TestConfigDirtyConcurrentMutationsAndPersists(t *testing.T) {
	resetDirtyState()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				MarkConfigMutated()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				completePersistSeq(beginPersistSeq())
			}
		}()
	}
	wg.Wait()

	completePersistSeq(beginPersistSeq())
	if dirtyValue() != 0 {
		t.Fatalf("final persist did not converge dirty to 0")
	}
}
