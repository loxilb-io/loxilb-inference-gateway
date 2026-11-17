// Copyright (c) 2026 LoxiLB Authors
// SPDX-License-Identifier: Apache-2.0

package loxinet

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type haVIPNetlinkTest struct {
	attempts []string
	links    []netlink.Link
	addrs    []netlink.Addr
	fail     bool
}

func (*haVIPNetlinkTest) SetSocketTimeout(time.Duration) error { return nil }
func (h *haVIPNetlinkTest) LinkList() ([]netlink.Link, error)  { return h.links, nil }
func (h *haVIPNetlinkTest) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return h.addrs, nil
}
func (h *haVIPNetlinkTest) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	h.attempts = append(h.attempts, link.Attrs().Name)
	if h.fail {
		return unix.EBUSY
	}
	return unix.EADDRNOTAVAIL
}

func TestHAFrontendWithdrawalRetainsFailedVIPs(t *testing.T) {
	const vip = "192.0.2.253"
	h := &haVIPNetlinkTest{
		fail: true,
		links: []netlink.Link{
			&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "lo"}},
			&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "eth1"}},
		},
		addrs: []netlink.Addr{
			{IPNet: &net.IPNet{IP: net.ParseIP(vip).To4(), Mask: net.CIDRMask(32, 32)}, LinkIndex: 1},
			{IPNet: &net.IPNet{IP: net.ParseIP(vip).To4(), Mask: net.CIDRMask(32, 32)}, LinkIndex: 2},
		},
	}
	pending := map[string]struct{}{vip: {}}
	deadline := time.Now().Add(time.Second)
	if err := clearWithdrawnVIPs(h, pending, deadline); !errors.Is(err, unix.EBUSY) || len(pending) != 1 {
		t.Fatalf("failed address was lost: pending=%v error=%v", pending, err)
	}
	h.fail = false
	if err := clearWithdrawnVIPs(h, pending, deadline); err != nil || len(pending) != 0 {
		t.Fatalf("already absent address did not clear: pending=%v error=%v", pending, err)
	}
	if len(h.attempts) != 2 || h.attempts[0] != "lo" || h.attempts[1] != "lo" {
		t.Fatalf("unexpected deletion targets: %v", h.attempts)
	}
}
