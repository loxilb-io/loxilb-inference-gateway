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
	"time"

	tk "github.com/loxilb-io/loxilib"
	"github.com/vishvananda/netlink"
)

// newSelfIPCacheForTest returns a fresh selfIPCache for tests so concurrent
// test runs do not stomp on the package-level SelfIPCache singleton.
func newSelfIPCacheForTest() *selfIPCache {
	return &selfIPCache{ips: make(map[uint32]struct{})}
}

// TestSelfIPCache_HasAddDel — A4 contract: table-driven add/has/del
// cycle for 5 sample IPs (including 31.31.31.254 from EVIDENCE).
func TestSelfIPCache_HasAddDel(t *testing.T) {
	c := newSelfIPCacheForTest()

	cases := []string{
		"31.31.31.254", // EVIDENCE self-IP
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.5",
	}

	// All IPs absent before Add.
	for _, s := range cases {
		key, ok := parseIPv4BEFromCIDR(s)
		if !ok {
			t.Fatalf("parseIPv4BEFromCIDR(%q) returned ok=false", s)
		}
		if c.Has(key) {
			t.Errorf("Has(%s) before Add returned true; want false", s)
		}
	}

	// Add → Has must report true.
	for _, s := range cases {
		key, _ := parseIPv4BEFromCIDR(s)
		c.Add(key)
		if !c.Has(key) {
			t.Errorf("Has(%s) after Add returned false; want true", s)
		}
	}

	// Del → Has must report false.
	for _, s := range cases {
		key, _ := parseIPv4BEFromCIDR(s)
		c.Del(key)
		if c.Has(key) {
			t.Errorf("Has(%s) after Del returned true; want false", s)
		}
	}
}

// TestSelfIPCache_ParseIPv4BEFromCIDR_RejectsBadInput — defensive helper
// contract: non-IPv4 / unparseable / IPv6 inputs return (0, false).
func TestSelfIPCache_ParseIPv4BEFromCIDR_RejectsBadInput(t *testing.T) {
	cases := []struct {
		in     string
		wantOK bool
	}{
		{"", false},
		{"not-an-ip", false},
		{"::1", false},            // IPv6 — out-of-scope
		{"2001:db8::1/64", false}, // IPv6 CIDR — out-of-scope
		{"31.31.31.254", true},    // bare IPv4
		{"31.31.31.254/24", true}, // CIDR-stripped IPv4
		{"127.0.0.1/32", true},    // /32 host
		{"256.0.0.1", false},      // out-of-range octet
	}
	for _, tc := range cases {
		_, ok := parseIPv4BEFromCIDR(tc.in)
		if ok != tc.wantOK {
			t.Errorf("parseIPv4BEFromCIDR(%q) ok=%v; want %v", tc.in, ok, tc.wantOK)
		}
	}
}

// TestSelfIPCache_ConcurrentReadWrite — race-test gate. 10 goroutines do
// Has/Add/Del concurrently for ~200ms. PASS under -race means no map
// concurrent access, no deadlock, no panic.
func TestSelfIPCache_ConcurrentReadWrite(t *testing.T) {
	c := newSelfIPCacheForTest()

	// Pre-populate with 100 keys.
	for i := uint32(0); i < 100; i++ {
		c.Add(i)
	}

	const writers = 5
	const readers = 5
	const dur = 200 * time.Millisecond

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var ops atomic.Uint64

	wg.Add(writers + readers)
	for w := 0; w < writers; w++ {
		go func(seed uint32) {
			defer wg.Done()
			i := seed
			for {
				select {
				case <-stop:
					return
				default:
				}
				c.Add(i)
				c.Del(i + 1000)
				ops.Add(2)
				i++
			}
		}(uint32(w * 1000))
	}
	for r := 0; r < readers; r++ {
		go func(seed uint32) {
			defer wg.Done()
			i := seed
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = c.Has(i)
				ops.Add(1)
				i++
			}
		}(uint32(r * 100))
	}

	time.Sleep(dur)
	close(stop)
	wg.Wait()

	if ops.Load() == 0 {
		t.Fatal("no operations performed; goroutines did not run")
	}
}

// TestSelfIPCache_InitBulkLoad — Init must populate the cache from the
// addrListFn injection point. Covers REQ-55-05 boot-time bulk-load.
func TestSelfIPCache_InitBulkLoad(t *testing.T) {
	c := newSelfIPCacheForTest()

	canned := []netlink.Addr{
		{IPNet: &net.IPNet{IP: net.ParseIP("31.31.31.254"), Mask: net.CIDRMask(24, 32)}},
		{IPNet: &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)}},
		{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}},
	}
	c.addrListFn = func() ([]netlink.Addr, error) {
		return canned, nil
	}

	if err := c.Init(); err != nil {
		t.Fatalf("Init returned err=%v; want nil", err)
	}

	for _, a := range canned {
		ip4 := a.IP.To4()
		if ip4 == nil {
			t.Fatalf("canned addr %v: To4 returned nil", a)
		}
		key := tk.IPtonl(ip4)
		if !c.Has(key) {
			t.Errorf("Has(%s) after Init returned false; want true", a.IP)
		}
	}

	// An unrelated IP must NOT be present (cache is exact-membership).
	otherKey, _ := parseIPv4BEFromCIDR("8.8.8.8")
	if c.Has(otherKey) {
		t.Errorf("Has(8.8.8.8) returned true; want false (only canned IPs were loaded)")
	}
}

// TestSelfIPCache_AddDelRoundtrip — covers the hook contract used by the
// NetAddrAdd / NetAddrDel hooks in apiclient.go: parseIPv4BEFromCIDR + Add/Del
// round-trip on the package-level singleton (the production path).
//
// We use a deliberately uncommon IP (203.0.113.55, RFC 5737 TEST-NET-3) to
// avoid colliding with anything Init might bulk-load on a real host should
// other tests run earlier in the same process.
func TestSelfIPCache_AddDelRoundtrip(t *testing.T) {
	const sample = "203.0.113.55/24"

	ipBE, ok := parseIPv4BEFromCIDR(sample)
	if !ok {
		t.Fatalf("parseIPv4BEFromCIDR(%q) returned ok=false", sample)
	}

	// Defensive: ensure clean starting state on the singleton.
	SelfIPCache.Del(ipBE)
	if SelfIPCache.Has(ipBE) {
		t.Fatal("singleton: Has=true before Add (test pollution)")
	}

	SelfIPCache.Add(ipBE)
	if !SelfIPCache.Has(ipBE) {
		t.Fatal("singleton: Has=false after Add")
	}

	SelfIPCache.Del(ipBE)
	if SelfIPCache.Has(ipBE) {
		t.Fatal("singleton: Has=true after Del")
	}
}

// TestSelfIPCache_KeySymmetry — Init via tk.IPtonl, lookup via
// parseIPv4BEFromCIDR (the helper used by NetAddrAdd hooks): both must
// produce the same key for the same IP. Symmetry guarantee for the
// resolveFlowMACs.Has fast path.
func TestSelfIPCache_KeySymmetry(t *testing.T) {
	c := newSelfIPCacheForTest()
	c.addrListFn = func() ([]netlink.Addr, error) {
		return []netlink.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("31.31.31.254"), Mask: net.CIDRMask(24, 32)}}}, nil
	}
	if err := c.Init(); err != nil {
		t.Fatalf("Init err=%v", err)
	}

	// resolveFlowMACs path: tk.IPtonl directly on net.IP.
	keyResolver := tk.IPtonl(net.ParseIP("31.31.31.254").To4())
	if !c.Has(keyResolver) {
		t.Error("Has via tk.IPtonl(net.ParseIP) returned false after Init")
	}

	// NetAddrAdd path: parseIPv4BEFromCIDR("31.31.31.254/24").
	keyHook, ok := parseIPv4BEFromCIDR("31.31.31.254/24")
	if !ok {
		t.Fatal("parseIPv4BEFromCIDR returned ok=false")
	}
	if !c.Has(keyHook) {
		t.Error("Has via parseIPv4BEFromCIDR returned false after Init")
	}

	if keyResolver != keyHook {
		t.Errorf("key mismatch: tk.IPtonl=%#x parseIPv4BEFromCIDR=%#x — symmetry broken",
			keyResolver, keyHook)
	}
}
