//go:build doca

/*
 * Copyright (c) 2022 NetLOX Inc
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

// CR-01 race test (-01).
//
// Pre-fix: this test triggers Go runtime
//
//	`fatal error: concurrent map iteration and map write`
//
// because the stats functions (FlowStats, AllFlowStats, AllFdbStats,
// AllRouteStats, AllAclStats, ActiveMeters) acquire only statsRWMu.RLock
// while iterating maps that are written under ctMtx or fdbMtx — different
// sync primitives that do NOT cross-serialize.
//
// Post-fix : each stats function takes the appropriate writer
// mutex briefly to snapshot the map, releases it, then performs
// DocaEntryQuery outside the lock. statsRWMu.RLock remains the OUTER
// drain-on-Shutdown guard.
//
// Gate: this test is build-tag gated to `doca` because the production stats
// functions only iterate live maps in the DOCA build (the !doca stub returns
// nil immediately). Run on bf2-arm with:
//
//	go test -race -count=1 -tags doca -run TestStatsConcurrentMapRace ./pkg/loxinet/...
//
// macOS / non-DOCA developer machines cannot run this test — the build tag
// excludes it from the default `go test ./...` invocation, so it does not
// regress the macOS workspace.

package loxinet

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// newTestDpDocaBf2Race constructs a DpDocaBf2 instance shaped for race
// testing only — no DOCA bridge, no real CGO entries. The maps are
// initialized with the same keys the production code uses; each map entry's
// `entry` field is set to a non-nil dummy unsafe.Pointer so the production
// stats funcs do not skip the row at the `oe.entry == nil` guard.
//
// Crucially, this test is NOT exercising DOCA itself — DocaEntryQuery is
// the slow-path call the snapshot-then-release pattern moves OUT OF the
// domain mutex, but the race we are reproducing is the *map iteration*
// happening WITHOUT writer-mutex serialization. To trigger the Go runtime
// detector for "concurrent map iteration and map write" we don't need
// DocaEntryQuery to actually return real counters; we need the map walk
// itself to run while a writer is mutating it. Setting bridge=nil causes
// DocaEntryQuery to error out fast (returning ErrNotSupported), and the
// production code skips the row on error — but the iteration has already
// happened by then, which is the moment the race detector observes.
func newTestDpDocaBf2Race() *DpDocaBf2 {
	d := NewDpDocaBf2() // production constructor — sets up all maps
	if d == nil {
		// Defensive — should never happen when built with -tags doca.
		return nil
	}
	d.bridge = nil // ensures DocaEntryQuery returns fast on error
	return d
}

// dummyEntryPtr is a sentinel non-nil unsafe.Pointer that race-test entries
// store in their `entry` field so the production stats funcs do not skip
// the row at the `oe.entry == nil` guard. Reading the pointer is never
// dereferenced in this test path because DocaEntryQuery returns early on
// d.bridge == nil.
var dummyEntryPtr = unsafe.Pointer(&struct{ _ uint8 }{})

// TestStatsConcurrentMapRace exercises the 6 stats functions concurrently
// with their respective writer paths to verify the snapshot-then-release
// pattern eliminates the Go runtime "concurrent map iteration and map write"
// race introduced identified in 55-VERIFICATION.md CR-01.
//
// The test PRE-FIX expected behaviour: the process panics with
// "fatal error: concurrent map iteration and map write" within ~50ms of
// starting the goroutines. The Go runtime detects this regardless of the
// `-race` flag.
//
// The test POST-FIX expected behaviour: 500ms of run time with no panic,
// no `-race` report, and a clean t.Logf summary of iteration counts.
func TestStatsConcurrentMapRace(t *testing.T) {
	d := newTestDpDocaBf2Race()
	if d == nil {
		t.Skip("DpDocaBf2 constructor returned nil under -tags doca; skipping")
	}

	const writers = 4
	const readers = 4
	const runFor = 500 * time.Millisecond

	var (
		readerOps atomic.Int64
		writerOps atomic.Int64
		stop      = make(chan struct{})
		wg        sync.WaitGroup
	)

	// === ctMtx writers — d.entries ===
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			n := 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				key := fmt.Sprintf("ct-flow-%d-%d", id, n)
				d.ctMtx.Lock()
				d.entries[key] = &docaOffloadEntry{
					entry:   dummyEntryPtr,
					pipeKey: "ct",
				}
				if n%4 == 3 {
					// periodic delete to keep map size bounded
					prev := fmt.Sprintf("ct-flow-%d-%d", id, n-2)
					delete(d.entries, prev)
				}
				d.ctMtx.Unlock()
				writerOps.Add(1)
				n++
			}
		}(i)
	}

	// === ctMtx writers — d.meterMap ===
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			n := uint32(0)
			for {
				select {
				case <-stop:
					return
				default:
				}
				meterID := uint32(id*16) + (n % 8)
				d.ctMtx.Lock()
				d.meterMap[meterID] = &docaMeterEntry{
					mark:   int(meterID) + 1,
					name:   fmt.Sprintf("meter-%d", meterID),
					active: true,
				}
				if n%5 == 4 {
					delete(d.meterMap, meterID)
				}
				d.ctMtx.Unlock()
				writerOps.Add(1)
				n++
			}
		}(i)
	}

	// === fdbMtx writers — d.fdbEntries ===
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			n := 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				key := fmt.Sprintf("fdb:00:00:00:%02x:%02x:%02x", id, n&0xff, (n>>8)&0xff)
				d.fdbMtx.Lock()
				d.fdbEntries[key] = &docaFdbOffloadEntry{
					entry:     dummyEntryPtr,
					fwdPortID: uint16(id),
				}
				if n%4 == 3 {
					prev := fmt.Sprintf("fdb:00:00:00:%02x:%02x:%02x", id, (n-2)&0xff, ((n-2)>>8)&0xff)
					delete(d.fdbEntries, prev)
				}
				d.fdbMtx.Unlock()
				writerOps.Add(1)
				n++
			}
		}(i)
	}

	// === fdbMtx writers — d.aclEntries ===
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			n := 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				key := aclEntryKey{Pref: uint16(id*100 + n%50)}
				d.fdbMtx.Lock()
				d.aclEntries[key] = &docaACLEntry{
					entry: dummyEntryPtr,
					key:   key,
				}
				if n%4 == 3 {
					prev := aclEntryKey{Pref: uint16(id*100 + (n-2)%50)}
					delete(d.aclEntries, prev)
				}
				d.fdbMtx.Unlock()
				writerOps.Add(1)
				n++
			}
		}(i)
	}

	// === Readers — call each stats function in a tight loop ===
	statFns := []func(){
		func() { _ = d.AllFlowStats() },
		func() { _ = d.AllFdbStats() },
		func() { _ = d.AllRouteStats() },
		func() { _ = d.AllAclStats() },
		func() { _ = d.ActiveMeters() },
		// FlowStats takes a *DpCtInfo argument — provide a dummy and accept
		// not-found result; we only care that the read path doesn't race.
		func() {
			_, _, _ = d.FlowStats(&DpCtInfo{Sip: "1.1.1.1", Dip: "2.2.2.2", Sport: 1234, Dport: 80, Proto: "tcp"})
		},
	}
	for fnIdx := range statFns {
		fn := statFns[fnIdx]
		for i := 0; i < readers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					fn()
					readerOps.Add(1)
				}
			}()
		}
	}

	// Run all goroutines for runFor, then close the stop channel and wait.
	time.Sleep(runFor)
	close(stop)
	wg.Wait()

	t.Logf("TestStatsConcurrentMapRace: %d reader ops + %d writer ops in %s without panic",
		readerOps.Load(), writerOps.Load(), runFor)

	if readerOps.Load() == 0 || writerOps.Load() == 0 {
		t.Fatalf("expected both readers and writers to make progress; got readers=%d writers=%d",
			readerOps.Load(), writerOps.Load())
	}
}
