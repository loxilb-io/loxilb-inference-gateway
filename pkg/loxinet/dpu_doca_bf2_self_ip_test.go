//go:build !doca

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

package loxinet

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"

	tk "github.com/loxilb-io/loxilib"
	"golang.org/x/sync/singleflight"
)

// withCleanSelfIPCache scrubs the SelfIPCache entries this test is going to
// stomp on, runs the test body, and removes them again on completion to
// avoid polluting other tests in the same process.
func withCleanSelfIPCache(t *testing.T, ips []string, body func()) {
	t.Helper()
	keys := make([]uint32, 0, len(ips))
	for _, s := range ips {
		k, ok := parseIPv4BEFromCIDR(s)
		if !ok {
			t.Fatalf("parseIPv4BEFromCIDR(%q) returned ok=false", s)
		}
		keys = append(keys, k)
		SelfIPCache.Del(k)
	}
	defer func() {
		for _, k := range keys {
			SelfIPCache.Del(k)
		}
	}()
	body()
}

// TestResolveFlowMACs_SelfIPFastPath — A4 / -05: when the
// SelfIPCache reports the target IP as loxilb-owned, resolveFlowMACs must
// return ok=true immediately with the proxy port MAC and skip the slow
// path entirely.
func TestResolveFlowMACs_SelfIPFastPath(t *testing.T) {
	withCleanSelfIPCache(t, []string{"31.31.31.254"}, func() {
		// Set proxy port MAC the stub returns for self-IP hits.
		origStubMAC := stubProxyPortMAC
		stubProxyPortMAC = [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
		defer func() { stubProxyPortMAC = origStubMAC }()

		// Seed the singleton with the EVIDENCE self-IP.
		ipBE, _ := parseIPv4BEFromCIDR("31.31.31.254")
		SelfIPCache.Add(ipBE)

		d := &DpDocaBf2{}
		port, dst, src, ok := d.resolveFlowMACs(net.ParseIP("31.31.31.254"))
		if !ok {
			t.Fatal("expected ok=true on self-IP fast path")
		}
		if port != 0 {
			t.Errorf("port=%d; want 0 (proxy port)", port)
		}
		if dst != stubProxyPortMAC {
			t.Errorf("dst=%v; want %v (proxy port MAC)", dst, stubProxyPortMAC)
		}
		if src != stubProxyPortMAC {
			t.Errorf("src=%v; want %v (proxy port MAC)", src, stubProxyPortMAC)
		}
	})
}

// TestResolveFlowMACs_NonSelfIPMissesFastPath — defensive contract: an IP
// NOT in the SelfIPCache must NOT trigger the fast path. The !doca stub's
// slow path returns ok=false (no DPDK port table); production reaches
// neighListFn. Either way, the fast path's "self-IP suppression" must not
// fire for non-self IPs — otherwise we'd silently mis-route.
func TestResolveFlowMACs_NonSelfIPMissesFastPath(t *testing.T) {
	d := &DpDocaBf2{}
	// 8.8.8.8 is a public IP — must NOT be in SelfIPCache.
	port, _, _, ok := d.resolveFlowMACs(net.ParseIP("8.8.8.8"))
	if ok {
		t.Errorf("non-self-IP returned ok=true; fast-path leak (port=%d)", port)
	}
}

// TestResolveFlowMACs_SingleflightCollapse asserts that N callers arriving on
// one key while a flight is open share that flight: the inner function runs
// exactly once.
//
// The overlap is established rather than raced for. DoChan registers the
// caller and returns immediately, so "the flight is open" and "this caller has
// joined it" are both observable facts, and the flight is held open until
// every caller has joined. The previous version started N goroutines and
// relied on a busy-spin to keep them overlapping, which made collapse a race
// the test hoped to win: with parallelism unavailable -- a loaded CI machine,
// or simply GOMAXPROCS=1, where it fails every single time -- the callers ran
// serially, each flight retired before the next caller arrived, and the inner
// function ran once per caller. That is a correct singleflight doing exactly
// what it promises, reported as a failure.
//
// The assertion tightens with the mechanism: the old bound (1 <= calls < N)
// accepted nine redundant resolutions out of ten, so it could only have caught
// a total failure to collapse. Exactly-one is the property the production hot
// path actually depends on.
func TestResolveFlowMACs_SingleflightCollapse(t *testing.T) {
	var sf singleflight.Group
	var calls atomic.Int64

	const (
		N   = 10
		key = "99.99.99.99"
	)

	release := make(chan struct{})
	entered := make(chan struct{})
	// A regression makes the inner function run more than once; closing
	// `entered` under a Once keeps that a clean assertion failure below
	// instead of a panic on a closed channel.
	var enteredOnce sync.Once

	fn := func() (interface{}, error) {
		calls.Add(1)
		enteredOnce.Do(func() { close(entered) })
		<-release
		return 0, nil
	}

	results := make([]<-chan singleflight.Result, 0, N)
	results = append(results, sf.DoChan(key, fn))
	<-entered // the flight is in progress -- not "probably in progress"

	for i := 1; i < N; i++ {
		// DoChan returns once this caller has joined, so the next one cannot
		// be issued into a window that has already closed.
		results = append(results, sf.DoChan(key, fn))
	}

	close(release)
	for i, ch := range results {
		if r := <-ch; r.Err != nil {
			t.Errorf("caller %d: %v", i, r.Err)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("singleflight did not collapse: inner-fn ran %d times for %d concurrent callers on one key; want exactly 1",
			got, N)
	}
}

// TestResolveFlowMACs_SymmetricKeyEncoding — meta-test guarding against
// regressions where production (tk.IPtonl) and test stub (also tk.IPtonl
// via dpu_doca_bf2_stub.go) drift apart. If this fails, the cache will
// silently miss in production despite the value being present.
func TestResolveFlowMACs_SymmetricKeyEncoding(t *testing.T) {
	const ipStr = "31.31.31.254"

	keyHook, ok := parseIPv4BEFromCIDR(ipStr)
	if !ok {
		t.Fatalf("parseIPv4BEFromCIDR(%q) ok=false", ipStr)
	}
	keyResolver := tk.IPtonl(net.ParseIP(ipStr).To4())
	if keyHook != keyResolver {
		t.Fatalf("key derivation drift: parseIPv4BEFromCIDR=%#x tk.IPtonl=%#x", keyHook, keyResolver)
	}
}
