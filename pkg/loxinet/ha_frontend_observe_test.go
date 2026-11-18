// Copyright (c) 2026 LoxiLB Authors
// SPDX-License-Identifier: Apache-2.0

package loxinet

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestHAFrontendObserverLatchAndRecover(t *testing.T) {
	const vip = "192.0.2.253"
	o := newHAFrontendObserver()
	o.track(vip)
	healthy := func(name string, index int) *netlink.Veth {
		return &netlink.Veth{LinkAttrs: netlink.LinkAttrs{
			Name: name, Index: index, Flags: net.FlagUp, RawFlags: unix.IFF_LOWER_UP,
		}}
	}
	frontend := healthy("eth7", 7)
	duplicate := healthy("eth8", 8)
	_, prefix, err := net.ParseCIDR("192.0.2.10/24")
	if err != nil {
		t.Fatal(err)
	}
	address := netlink.Addr{IPNet: prefix, LinkIndex: 7}
	o.reconcile([]netlink.Link{frontend, duplicate}, []netlink.Addr{
		address, {IPNet: prefix, LinkIndex: 8},
	})
	if got := o.targets[vip]; got.state != "unresolved" {
		t.Fatalf("ambiguous frontend latched: %+v", got)
	}
	o.reconcile([]netlink.Link{frontend}, []netlink.Addr{address})
	expect := func(name string, index int, state string) {
		t.Helper()
		want := haFrontendObservation{name: name, index: index, state: state}
		if got := o.targets[vip]; got != want {
			t.Fatalf("observation %+v, want %+v", got, want)
		}
	}
	expect("eth7", 7, "up")

	// A lost carrier event and missing connected subnet do not clear the latch.
	frontend.RawFlags = 0
	o.reconcile([]netlink.Link{frontend}, nil)
	expect("eth7", 7, "carrier-down")
	frontend.Flags = 0
	o.event(netlink.LinkUpdate{Link: frontend, Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK}})
	expect("eth7", 7, "admin-down")
	o.event(netlink.LinkUpdate{Link: frontend, Header: unix.NlMsghdr{Type: unix.RTM_DELLINK}})
	expect("eth7", 7, "deleted")

	replacement := healthy("eth7", 17)
	o.reconcile([]netlink.Link{replacement}, nil)
	expect("eth7", 7, "deleted")
	address.LinkIndex = 17
	o.reconcile([]netlink.Link{replacement}, []netlink.Addr{address})
	expect("eth7", 17, "up")
	o.event(netlink.LinkUpdate{Link: frontend, Header: unix.NlMsghdr{Type: unix.RTM_DELLINK}})
	expect("eth7", 17, "up")
	o.untrack(vip)
	if _, exists := o.targets[vip]; exists {
		t.Fatal("removed VIP still tracked")
	}
}
