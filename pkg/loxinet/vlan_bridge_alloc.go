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

// Bridge VID allocator for Linux kernel bridges (v7.0 HW offload).
//
// Fixes Bug #1 CONTEXT §: VlanValid(0) previously rejected
// zero-digit bridge names (`br0`, `br-prod`, `bridge`) because the legacy
// regex `[0-9]+` parse in api/loxinlp/nlp.go returned vid=0 for any name
// containing no digits. Every FDB sync for such bridges then failed with a
// "BD mismatch" log line at layer2.go:420.
//
// This file owns a thread-safe name -> VID mapping for Linux bridges. The
// allocator draws from the reserved range [BridgeVidStart, BridgeVidStart +
// BridgeVidCount - 1] = [5000, 6143] -- collision-free against the port
// range (3800-4311), real VLAN IDs (1-4094), and legacy docker0/cni0
// hardcodes (4090/4091).
//
// Call-site migration (api/loxinlp/nlp.go: 4 regex sites) lives.
package loxinet

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"sync"

	tk "github.com/loxilb-io/loxilib"
)

// Bridge VID allocator range -- CONTEXT §.
// [5000, 6143] = 1144 slots.
const (
	BridgeVidStart = 5000
	BridgeVidCount = 1144 // ceiling = BridgeVidStart + BridgeVidCount - 1 = 6143
)

// bridgeNumRe is compiled once at package init (RESEARCH "Don't Hand-Roll"
// row 4). Shared by both the Get/Lookup/Release helpers; pure function so
// concurrent reads are safe without locking.
var bridgeNumRe = regexp.MustCompile("[0-9]+")

// bridgeVidMu serializes every mutation of bridgeByName and every call into
// tk.Counter (which has no internal synchronization -- RESEARCH).
// The helper is reachable from multiple goroutines (initial netlink link
// dump + async RTM_NEWNEIGH subscribe) BEFORE the hooks layer acquires
// mh.mtx, so we MUST carry our own lock.
var (
	bridgeVidMu      sync.Mutex
	bridgeVidCounter *tk.Counter
	bridgeByName     map[string]int
)

func init() {
	bridgeVidCounter = tk.NewCounter(BridgeVidStart, BridgeVidCount)
	bridgeByName = make(map[string]int)
}

// GetOrAllocBridgeVid returns a stable bridge-domain ID for the given
// Linux bridge link name. Order:
// 1. "docker0"/"cni0" hardcode (legacy preserve CONTEXT §).
//  2. Numeric-name preservation -- e.g., "br100" -> 100; never consumes a
//     pool slot. Pre-existing latent conflict with real VLAN 100 is out of
//
// scope (RESEARCH).
//  3. Pool allocation from [5000, 6143] via tk.Counter.
//
// Idempotent on repeated calls for the same name -- the first pool-backed
// alloc caches the VID in bridgeByName[] and subsequent calls return the
// cached value without consuming another slot (:
// site #2 may run before site #1 in netlink replay order, so the cache
// check must happen before GetCounter).
func GetOrAllocBridgeVid(name string) (int, error) {
	if name == "docker0" {
		return 4090, nil
	}
	if name == "cni0" {
		return 4091, nil
	}
	if m := bridgeNumRe.FindString(name); m != "" {
		if v, err := strconv.Atoi(m); err == nil && v > 0 {
			return v, nil
		}
	}
	bridgeVidMu.Lock()
	defer bridgeVidMu.Unlock()
	if v, ok := bridgeByName[name]; ok {
		return v, nil
	}
	rid, err := bridgeVidCounter.GetCounter()
	if err != nil {
		return 0, fmt.Errorf("bridge VID pool exhausted for %q: %w", name, err)
	}
	vid := int(rid)
	bridgeByName[name] = vid
	tk.LogIt(tk.LogInfo, "bridge alloc: %s -> vid %d\n", name, vid)
	return vid, nil
}

// LookupBridgeVid returns the VID if one was previously assigned, or
// (0, false) if never seen. It MUST NOT allocate -- used by the netlink
// DelNeigh / DelLink paths where allocating on a delete would leak slots
// (CONTEXT § del-path edge case).
//
// The docker0/cni0 hardcode and numeric-name preservation paths return
// (vid, true) without touching the pool, mirroring GetOrAllocBridgeVid's
// observable mapping so callers see a consistent view.
func LookupBridgeVid(name string) (int, bool) {
	if name == "docker0" {
		return 4090, true
	}
	if name == "cni0" {
		return 4091, true
	}
	if m := bridgeNumRe.FindString(name); m != "" {
		if v, err := strconv.Atoi(m); err == nil && v > 0 {
			return v, true
		}
	}
	bridgeVidMu.Lock()
	defer bridgeVidMu.Unlock()
	v, ok := bridgeByName[name]
	return v, ok
}

// ListBridges returns a sorted snapshot of all bridge names currently in the
// registry. Used bridge_bytes_sampler to iterate bridges
// when sampling /sys/class/net/<name>/statistics.
//
// Returned slice is a fresh copy — safe to iterate without holding bridgeVidMu.
// Sort order is deterministic so Prometheus label ordering stays stable across
// restarts (aid for dashboard review; Prometheus itself doesn't require it).
//
// NOTE: bridges registered only via the docker0/cni0 hardcode or numeric-name
// preservation paths do NOT appear here — they never touch bridgeByName.
// Sampler still covers them indirectly because the kernel exposes their
// /sys/class/net/<name> entries regardless; P49-R3 focus is pool-allocated
// named bridges which is the operator-facing case.
func ListBridges() []string {
	bridgeVidMu.Lock()
	defer bridgeVidMu.Unlock()
	names := make([]string, 0, len(bridgeByName))
	for k := range bridgeByName {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// ReleaseBridgeVid returns a previously-allocated slot to the pool. It is
// a no-op for docker0/cni0 and numeric-named bridges (they never consumed
// a pool slot) and idempotent for never-seen names (netlink may deliver
// DelLink for a bridge that never reached the allocator).
//
// Call after a successful hooks.NetVlanDel on the DELETE branch of
// api/loxinlp/nlp.go LUpdate (: without a release
// hook, rename churn leaks slots).
func ReleaseBridgeVid(name string) error {
	if name == "docker0" || name == "cni0" {
		return nil
	}
	if m := bridgeNumRe.FindString(name); m != "" {
		if v, err := strconv.Atoi(m); err == nil && v > 0 {
			return nil
		}
	}
	bridgeVidMu.Lock()
	defer bridgeVidMu.Unlock()
	vid, ok := bridgeByName[name]
	if !ok {
		return nil
	}
	delete(bridgeByName, name)
	if err := bridgeVidCounter.PutCounter(uint64(vid)); err != nil {
		return errors.New("bridge release failed: " + err.Error())
	}
	tk.LogIt(tk.LogInfo, "bridge release: %s (vid %d)\n", name, vid)
	return nil
}

// resetBridgeAllocator is a test-only helper. Unexported; only the
// in-package _test.go file can reach it. Restores the pristine allocator
// state so tests can run in any order under `go test -shuffle=on`.
func resetBridgeAllocator() {
	bridgeVidMu.Lock()
	defer bridgeVidMu.Unlock()
	bridgeVidCounter = tk.NewCounter(BridgeVidStart, BridgeVidCount)
	bridgeByName = make(map[string]int)
}
