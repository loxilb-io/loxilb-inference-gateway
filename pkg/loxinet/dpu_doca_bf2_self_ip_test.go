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

// TestResolveFlowMACs_SelfIPFastPath — A4 / REQ-55-05: when the
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

// TestResolveFlowMACs_SingleflightCollapse — A3: 10 concurrent
// callers with the same key must invoke the singleflight inner function
// AT MOST one extra time per unique inflight window. We can't directly
// instrument the !doca stub's inner-fn (its Do call is sealed inside
// resolveFlowMACs), so we exercise the Group object on a parallel
// resolveSF.Do call to validate semantics that match what the production
// hot-path relies on.
//
// (The integration check on bf2-arm uses strace per §5.)
func TestResolveFlowMACs_SingleflightCollapse(t *testing.T) {
	var sf singleflight.Group
	var calls atomic.Int64

	const N = 10
	var wg sync.WaitGroup
	wg.Add(N)
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, _, _ = sf.Do("99.99.99.99", func() (interface{}, error) {
				calls.Add(1)
				// Small busy-spin so callers actually overlap.
				for k := 0; k < 1_000_000; k++ {
					_ = k
				}
				return 0, nil
			})
		}()
	}
	close(start)
	wg.Wait()

	got := calls.Load()
	if got < 1 {
		t.Fatalf("singleflight inner-fn ran %d times; want >= 1", got)
	}
	if got >= N {
		t.Fatalf("singleflight failed to collapse: inner-fn ran %d times for %d callers; want < %d (collapse achieved)",
			got, N, N)
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
