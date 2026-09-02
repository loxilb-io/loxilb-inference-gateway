/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

import (
	"sync"
	"testing"
	"time"
)

// gatedBackend counts LoadModel calls and can block them on a gate channel, so
// tests can hold a load in flight and observe what the rest of the loader does
// meanwhile.
type gatedBackend struct {
	mu         sync.Mutex
	loads      int64
	gate       chan struct{} // when non-nil, LoadModel blocks until it is closed
	tokenizers map[string]*mockTokenizer
}

func (b *gatedBackend) LoadModel(tokenizerPath string) KvTokenizer {
	b.mu.Lock()
	b.loads++
	g := b.gate
	tk := b.tokenizers[tokenizerPath]
	b.mu.Unlock()
	if g != nil {
		<-g
	}
	if tk == nil {
		return nil
	}
	return tk
}

func (b *gatedBackend) Name() string { return "gated" }

// gateCloser returns a close-once wrapper for a gate channel, safe to both
// defer and call explicitly. A test failing before its explicit close must not
// leave a wedged LoadModel carrying shared loader state into later tests.
func gateCloser(gate chan struct{}) func() {
	var once sync.Once
	return func() { once.Do(func() { close(gate) }) }
}

func (b *gatedBackend) loadCount() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.loads
}

func (b *gatedBackend) waitLoads(t *testing.T, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for b.loadCount() < want {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for LoadModel call #%d (saw %d)", want, b.loadCount())
		}
		time.Sleep(time.Millisecond)
	}
}

func stagedPath(model string) string {
	return kvTokenizerDir + "/" + kvModelSlug(model) + "/tokenizer.json"
}

// TestKvTokenizerSingleflightStormLoadsOnce: a concurrent request storm for one
// not-yet-loaded model results in exactly ONE filesystem load; every caller
// still receives the tokenizer.
func TestKvTokenizerSingleflightStormLoadsOnce(t *testing.T) {
	KvTokenizerPoolReset()
	defer KvTokenizerPoolReset()

	gate := make(chan struct{})
	closeGate := gateCloser(gate)
	defer closeGate()
	backend := &gatedBackend{
		gate: gate,
		tokenizers: map[string]*mockTokenizer{
			stagedPath("storm-model"): {ids: []uint32{7}},
		},
	}
	KvRegisterTokenizerBackend(backend)
	defer KvRegisterTokenizerBackend(nil)

	const callers = 64
	results := make([]KvTokenizer, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = kvLoadTokenizer("storm-model")
		}(i)
	}

	backend.waitLoads(t, 1)   // the single leader is inside LoadModel
	time.Sleep(20 * time.Millisecond) // let the remaining callers join the flight
	closeGate()
	wg.Wait()

	if got := backend.loadCount(); got != 1 {
		t.Fatalf("storm of %d callers performed %d LoadModel calls, want exactly 1", callers, got)
	}
	for i, r := range results {
		if r == nil {
			t.Fatalf("caller %d got nil tokenizer from the shared load", i)
		}
	}
}

// TestKvTokenizerNegativeCacheBoundsFilesystemProbes: a broken-model storm hits
// the filesystem once per TTL, a data-plane retry inside the TTL stays nil even
// after the file is repaired, and the admission path (fresh probe) bypasses the
// TTL immediately.
func TestKvTokenizerNegativeCacheBoundsFilesystemProbes(t *testing.T) {
	KvTokenizerPoolReset()
	defer KvTokenizerPoolReset()

	backend := &gatedBackend{tokenizers: map[string]*mockTokenizer{}}
	KvRegisterTokenizerBackend(backend)
	defer KvRegisterTokenizerBackend(nil)

	if tok := kvLoadTokenizer("neg-model"); tok != nil {
		t.Fatal("expected nil for missing tokenizer")
	}
	if got := backend.loadCount(); got != 1 {
		t.Fatalf("first miss performed %d LoadModel calls, want 1", got)
	}

	// Storm inside the TTL: concurrent and sequential retries must not probe.
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tok := kvLoadTokenizer("neg-model"); tok != nil {
				t.Error("negative-cached model unexpectedly loaded")
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 32; i++ {
		if tok := kvLoadTokenizer("neg-model"); tok != nil {
			t.Fatal("negative-cached model unexpectedly loaded")
		}
	}
	if got := backend.loadCount(); got != 1 {
		t.Fatalf("storm inside TTL performed %d LoadModel calls, want still 1", got)
	}

	// Repair the file. The data-plane path is still TTL-bound (the bound is
	// real, not decorative) …
	backend.mu.Lock()
	backend.tokenizers[stagedPath("neg-model")] = &mockTokenizer{ids: []uint32{1}}
	backend.mu.Unlock()
	if tok := kvLoadTokenizer("neg-model"); tok != nil {
		t.Fatal("data-plane retry inside the TTL must stay nil even after repair")
	}
	if got := backend.loadCount(); got != 1 {
		t.Fatalf("TTL-bound retry performed %d LoadModel calls, want still 1", got)
	}

	// … while the admission path probes immediately.
	if tok := kvLoadTokenizerFresh("neg-model"); tok == nil {
		t.Fatal("admission fresh probe must load the repaired tokenizer immediately")
	}
	if got := backend.loadCount(); got != 2 {
		t.Fatalf("fresh probe performed %d LoadModel calls total, want 2", got)
	}
	if tok := kvLoadTokenizer("neg-model"); tok == nil {
		t.Fatal("pooled tokenizer must now serve the data-plane path")
	}
	if got := backend.loadCount(); got != 2 {
		t.Fatalf("pool hit performed %d LoadModel calls total, want still 2", got)
	}
}

// TestKvTokenizerNegativeCacheExpires: after the TTL passes, the data-plane
// path re-probes on its own (no admission action required).
func TestKvTokenizerNegativeCacheExpires(t *testing.T) {
	KvTokenizerPoolReset()
	defer KvTokenizerPoolReset()

	origTTL := kvTokenizerNegTTL
	kvTokenizerNegTTL = 50 * time.Millisecond
	defer func() { kvTokenizerNegTTL = origTTL }()

	backend := &gatedBackend{tokenizers: map[string]*mockTokenizer{}}
	KvRegisterTokenizerBackend(backend)
	defer KvRegisterTokenizerBackend(nil)

	if tok := kvLoadTokenizer("expiry-model"); tok != nil {
		t.Fatal("expected nil for missing tokenizer")
	}
	backend.mu.Lock()
	backend.tokenizers[stagedPath("expiry-model")] = &mockTokenizer{ids: []uint32{2}}
	backend.mu.Unlock()

	time.Sleep(80 * time.Millisecond)
	if tok := kvLoadTokenizer("expiry-model"); tok == nil {
		t.Fatal("data-plane retry after TTL expiry must re-probe and load")
	}
	if got := backend.loadCount(); got != 2 {
		t.Fatalf("performed %d LoadModel calls, want 2 (one failure, one reload)", got)
	}
}

// TestKvTokenizerHealthyLookupsUnblockedDuringBrokenLoad: while a broken
// model's load is stuck in the filesystem, lookups of already-loaded
// tokenizers complete immediately. This is the healthy-slug latency bound: the
// load must run with no pool lock held.
func TestKvTokenizerHealthyLookupsUnblockedDuringBrokenLoad(t *testing.T) {
	KvTokenizerPoolReset()
	defer KvTokenizerPoolReset()

	backend := &gatedBackend{
		tokenizers: map[string]*mockTokenizer{
			stagedPath("healthy-model"): {ids: []uint32{3}},
		},
	}
	KvRegisterTokenizerBackend(backend)
	defer KvRegisterTokenizerBackend(nil)

	if tok := kvLoadTokenizer("healthy-model"); tok == nil {
		t.Fatal("healthy tokenizer failed to pre-load")
	}

	gate := make(chan struct{})
	closeGate := gateCloser(gate)
	defer closeGate()
	backend.mu.Lock()
	backend.gate = gate
	backend.mu.Unlock()

	brokenDone := make(chan struct{})
	go func() {
		defer close(brokenDone)
		_ = kvLoadTokenizer("broken-model")
	}()
	backend.waitLoads(t, 2) // the broken load is now stuck inside LoadModel

	healthyDone := make(chan KvTokenizer, 1)
	go func() { healthyDone <- kvLoadTokenizer("healthy-model") }()
	select {
	case tok := <-healthyDone:
		if tok == nil {
			t.Fatal("healthy lookup returned nil during broken-model load")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("healthy lookup blocked behind a broken-model filesystem load")
	}

	closeGate()
	<-brokenDone
}

// TestKvTokenizerStaleLoadDiscardedOnPoolReset: a pool reset during an
// in-flight load (a) returns promptly rather than waiting for the load, and
// (b) invalidates the load's result — the loader re-dispatches under the new
// generation instead of committing state from the previous pool lifetime.
func TestKvTokenizerStaleLoadDiscardedOnPoolReset(t *testing.T) {
	KvTokenizerPoolReset()
	defer KvTokenizerPoolReset()

	gate := make(chan struct{})
	closeGate := gateCloser(gate)
	defer closeGate()
	backend := &gatedBackend{
		gate: gate,
		tokenizers: map[string]*mockTokenizer{
			stagedPath("epoch-model"): {ids: []uint32{4}},
		},
	}
	KvRegisterTokenizerBackend(backend)
	defer KvRegisterTokenizerBackend(nil)

	loaderDone := make(chan KvTokenizer, 1)
	go func() { loaderDone <- kvLoadTokenizer("epoch-model") }()
	backend.waitLoads(t, 1) // leader is stuck inside LoadModel

	resetDone := make(chan struct{})
	go func() {
		KvTokenizerPoolReset()
		close(resetDone)
	}()
	select {
	case <-resetDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("pool reset blocked behind an in-flight load")
	}

	closeGate()
	var tok KvTokenizer
	select {
	case tok = <-loaderDone:
	case <-time.After(2 * time.Second):
		t.Fatal("loader did not finish after gate release")
	}

	// The stale result was discarded and the loader re-dispatched under the
	// new generation: two LoadModel calls, and the final result is valid.
	if got := backend.loadCount(); got != 2 {
		t.Fatalf("performed %d LoadModel calls, want 2 (stale discard + re-dispatch)", got)
	}
	if tok == nil {
		t.Fatal("re-dispatched load must return the tokenizer")
	}
}

// TestKvTokenizerWaiterAbandonsSlowLoad: a waiter on someone else's in-flight
// load gives up after kvTokenizerWaitTimeout while the shared load keeps
// running and commits on its own lifecycle.
func TestKvTokenizerWaiterAbandonsSlowLoad(t *testing.T) {
	KvTokenizerPoolReset()
	defer KvTokenizerPoolReset()

	origWait := kvTokenizerWaitTimeout
	kvTokenizerWaitTimeout = 50 * time.Millisecond
	defer func() { kvTokenizerWaitTimeout = origWait }()

	gate := make(chan struct{})
	closeGate := gateCloser(gate)
	defer closeGate()
	backend := &gatedBackend{
		gate: gate,
		tokenizers: map[string]*mockTokenizer{
			stagedPath("slow-model"): {ids: []uint32{5}},
		},
	}
	KvRegisterTokenizerBackend(backend)
	defer KvRegisterTokenizerBackend(nil)

	leaderDone := make(chan KvTokenizer, 1)
	go func() { leaderDone <- kvLoadTokenizer("slow-model") }()
	backend.waitLoads(t, 1)

	start := time.Now()
	if tok := kvLoadTokenizer("slow-model"); tok != nil {
		t.Fatal("waiter must abandon a still-running load with nil, not block for its result")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("waiter took %v to abandon, want ~kvTokenizerWaitTimeout", waited)
	}

	closeGate()
	select {
	case tok := <-leaderDone:
		if tok == nil {
			t.Fatal("abandoned load must still commit for the leader")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not finish after gate release")
	}
	if tok := kvLoadTokenizer("slow-model"); tok == nil {
		t.Fatal("committed load must serve later callers from the pool")
	}
	if got := backend.loadCount(); got != 1 {
		t.Fatalf("performed %d LoadModel calls, want 1 (waiter abandonment must not re-probe)", got)
	}
}

// TestKvTokenizerCloseDiscardsInFlightLoad: KvTokenizerClose advances the pool
// generation like a reset does, so an in-flight load's result is discarded and
// re-dispatched instead of being committed by the pre-Close generation. The
// stale-commit mutation (dropping the epoch bump in Close) shows up as a single
// LoadModel call; correct behavior is two.
func TestKvTokenizerCloseDiscardsInFlightLoad(t *testing.T) {
	KvTokenizerPoolReset()
	defer KvTokenizerPoolReset()

	origWait := kvTokenizerWaitTimeout
	kvTokenizerWaitTimeout = 50 * time.Millisecond
	defer func() { kvTokenizerWaitTimeout = origWait }()

	gate := make(chan struct{})
	closeGate := gateCloser(gate)
	defer closeGate()
	backend := &gatedBackend{
		gate: gate,
		tokenizers: map[string]*mockTokenizer{
			stagedPath("close-model"): {ids: []uint32{6}},
		},
	}
	KvRegisterTokenizerBackend(backend)
	defer KvRegisterTokenizerBackend(nil)

	loaderDone := make(chan KvTokenizer, 1)
	go func() { loaderDone <- kvLoadTokenizer("close-model") }()
	backend.waitLoads(t, 1)

	KvTokenizerClose()
	closeGate()
	select {
	case <-loaderDone:
	case <-time.After(2 * time.Second):
		t.Fatal("loader did not finish after gate release")
	}

	if got := backend.loadCount(); got != 2 {
		t.Fatalf("performed %d LoadModel calls, want 2 — a single call means the pre-Close load committed across the generation boundary", got)
	}
}
