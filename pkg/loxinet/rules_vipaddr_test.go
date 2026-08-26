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

// rules_vipaddr_test.go — unit tests for rule-VIP host-address ownership.
// Rule create only puts a VIP on a kernel interface in the MASTER cluster
// state and only when the address is missing; rule delete used to take it
// down whatever its origin, so a delete+re-create left a pre-configured VIP
// deaf below TCP. These pin the bookkeeping that makes the two sides
// symmetric without touching netlink.

package loxinet

import (
	"net"
	"testing"
)

// localHostAddr returns a non-loopback address this host really carries, i.e.
// one utils.IsIPHostAddr answers true for.
func localHostAddr(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("no interface addresses to test against: %v", err)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP
		}
	}
	t.Skip("host carries no non-loopback IPv4 address")
	return nil
}

// TestVIPHostAddrNotOwnedWhenPreconfigured: a VIP that was already on the host
// when the rule was created is NOT ours to remove. Fullproxy VIPs must be
// locally bindable before the sockproxy listener can bind them, so the address
// exists before the rule does.
func TestVIPHostAddrNotOwnedWhenPreconfigured(t *testing.T) {
	ip := localHostAddr(t)
	vipEnt := &vipElem{ref: 1}
	if vipEnt.ownsHostAddr(ip) {
		t.Fatalf("a pre-configured host address %s must not be removable by rule delete", ip)
	}
}

// TestVIPHostAddrOwnedAfterSelfAdd: an address this path added is ours, and the
// last rule reference takes it back down.
func TestVIPHostAddrOwnedAfterSelfAdd(t *testing.T) {
	ip := localHostAddr(t)
	R := &RuleH{vipMap: make(map[string]*vipElem)}
	R.vipMap[ip.String()] = &vipElem{ref: 1}

	R.markRuleVIPAddr(ip, true)
	if !R.vipMap[ip.String()].ownsHostAddr(ip) {
		t.Fatalf("a self-added host address %s must be removable by rule delete", ip)
	}

	// A cluster-state demotion takes the address down on our behalf; the entry
	// must stop claiming it so a later rule delete does not delete twice.
	R.markRuleVIPAddr(ip, false)
	if R.vipMap[ip.String()].ownsHostAddr(ip) {
		t.Fatalf("ownership must be dropped once the address is taken down")
	}
}

// TestVIPHostAddrOwnershipNeedsPresence: ownership alone is not enough — an
// address that is no longer on the host is not deleted again.
func TestVIPHostAddrOwnershipNeedsPresence(t *testing.T) {
	vipEnt := &vipElem{ref: 1, selfAddr: true}
	absent := net.ParseIP("203.0.113.77")
	if vipEnt.ownsHostAddr(absent) {
		t.Fatalf("an address absent from the host must not be deleted again")
	}
}

// TestMarkRuleVIPAddrIsTotal: the marker never panics and never invents a
// vipMap entry — AdvRuleVIP runs on the cluster-state sweep too, where a VIP
// may already have been reaped.
func TestMarkRuleVIPAddrIsTotal(t *testing.T) {
	R := &RuleH{vipMap: make(map[string]*vipElem)}

	R.markRuleVIPAddr(nil, true)
	R.markRuleVIPAddr(net.ParseIP("20.20.20.3"), true)

	if len(R.vipMap) != 0 {
		t.Fatalf("marking must not create vipMap entries, got %d", len(R.vipMap))
	}
}

// TestVIPRefCountKeepsOwnership: ownership is decided at the add that really
// put the address there, and must survive further rules landing on the same
// VIP — two rules on one VIP, one delete, the address stays.
func TestVIPRefCountKeepsOwnership(t *testing.T) {
	ip := localHostAddr(t)
	R := &RuleH{vipMap: make(map[string]*vipElem)}
	R.vipMap[ip.String()] = &vipElem{ref: 1}
	R.markRuleVIPAddr(ip, true)

	R.vipMap[ip.String()].ref++ // second rule on the same VIP

	if !R.vipMap[ip.String()].ownsHostAddr(ip) {
		t.Fatalf("ownership must survive a second rule referencing the VIP")
	}
}
