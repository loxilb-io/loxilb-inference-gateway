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

// A4: self-IP membership cache.
//
// Why: resolveFlowMACs (dpu_doca_bf2.go) was probing netlink.NeighList for
// loxilb's OWN VIP-style IPs (e.g., 31.31.31.254), failing to find a neighbor
// entry, logging a warn line, and falling through to slow-path. The fix is a
// leading O(1) cache check before the neighbor probe — -05.
//
// Cache freshness:
// - Init bulk-loads via netlink.AddrList at startup (covers IPs added
//     before the NLP subsystem starts).
//   - NetAddrAdd / NetAddrDel REST/NLP hooks (apiclient.go) call Add/Del on
//     success to keep the cache fresh as addresses change.
//
// Lock discipline: the SelfIPCache RWMutex is INDEPENDENT — never acquired
// under any other loxilb mutex (mh.mtx, DpDocaBf2 ctMtx/fdbMtx/userCtxMu/
// statsRWMu, pairMu). RLock for Has (hot path), Lock for Add/Del/Init (rare).
//
// Key encoding: every put/get goes through tk.IPtonl so cache-producer (Init/
// NetAddrAdd) and cache-consumer (resolveFlowMACs) derive an identical
// uint32 from the same net.IP. tk.IPtonl is the canonical helper used
// across pkg/loxinet — symmetric key derivation between producer and
// consumer is mandatory; mismatched endianness = silent cache miss.

package loxinet

import (
	"net"
	"strings"
	"sync"

	tk "github.com/loxilb-io/loxilib"
	"github.com/vishvananda/netlink"
)

// selfIPCache is the type underlying the package-level SelfIPCache singleton.
type selfIPCache struct {
	mu  sync.RWMutex
	ips map[uint32]struct{}
	// addrListFn is a test injection point. nil in production; tests set
	// it before calling Init to feed canned []netlink.Addr without
	// touching the real netlink subsystem.
	addrListFn func() ([]netlink.Addr, error)
}

// SelfIPCache is the package-level singleton. Hot-path lookup is RLock-only.
var SelfIPCache = &selfIPCache{ips: make(map[uint32]struct{})}

// Has returns true if ip is loxilb-owned. ip is IPv4 in tk.IPtonl encoding.
func (c *selfIPCache) Has(ip uint32) bool {
	c.mu.RLock()
	_, ok := c.ips[ip]
	c.mu.RUnlock()
	return ok
}

// Add records ip as loxilb-owned. Caller must encode via tk.IPtonl.
func (c *selfIPCache) Add(ip uint32) {
	c.mu.Lock()
	c.ips[ip] = struct{}{}
	c.mu.Unlock()
}

// Del removes ip from the cache.
func (c *selfIPCache) Del(ip uint32) {
	c.mu.Lock()
	delete(c.ips, ip)
	c.mu.Unlock()
}

// Init bulk-loads loxilb-owned IPv4 addresses via netlink.AddrList(nil, FAMILY_V4).
// Called once at startup AFTER the NLP subsystem is ready (loxinet.go bootstrap).
// Subsequent additions/deletions flow via NetAddrAdd / NetAddrDel hooks
// (apiclient.go).
//
// Returns the netlink error (if any). Callers treat the error as non-fatal:
// the cache will still populate via NetAddrAdd/Del hooks during runtime.
func (c *selfIPCache) Init() error {
	listFn := c.addrListFn
	if listFn == nil {
		listFn = func() ([]netlink.Addr, error) {
			return netlink.AddrList(nil, netlink.FAMILY_V4)
		}
	}
	addrs, err := listFn()
	if err != nil {
		return err
	}
	c.mu.Lock()
	for _, a := range addrs {
		ip4 := a.IP.To4()
		if ip4 == nil {
			continue
		}
		c.ips[tk.IPtonl(ip4)] = struct{}{}
	}
	c.mu.Unlock()
	return nil
}

// parseIPv4BEFromCIDR strips an optional /N suffix from s, parses as IPv4,
// returns tk.IPtonl-encoded uint32 + true. Returns (0, false) on parse
// failure or non-IPv4 address. Used by the NetAddrAdd/Del hooks in
// apiclient.go where am.IP is a string (potentially CIDR-formatted).
//
// Naming: "BE" reflects the original plan terminology; the actual encoding
// is whatever tk.IPtonl produces (matches the rest of pkg/loxinet, which
// is what matters for cache symmetry).
func parseIPv4BEFromCIDR(s string) (uint32, bool) {
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return tk.IPtonl(ip4), true
}
