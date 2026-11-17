// Copyright (c) 2026 LoxiLB Authors
// SPDX-License-Identifier: Apache-2.0

package loxinet

import (
	"errors"
	"net"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"
	bfd "github.com/loxilb-io/loxilb/pkg/proto"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const haWithdrawalBudget = 300 * time.Millisecond

func (ch *CIStateH) announcePair() {
	if ch.Bs != nil {
		if err := ch.Bs.AnnouncePair(ch.l2PairPeer); err != nil {
			tk.LogIt(tk.LogWarning, "HA BFD rank transmission peer=%s state=%d error=%v\n",
				ch.l2PairPeer, ch.pairState(), err)
		}
	}
}

func (ch *CIStateH) withdrawPair(reason string) {
	ch.haTransitionMu.Lock()
	defer ch.haTransitionMu.Unlock()
	if ch.pairState() == bfd.PairWithdrawn && reason != "shutdown_withdrawal" {
		return
	}
	if ch.pairState() != bfd.PairWithdrawn {
		ch.haPairState.Store(uint32(bfd.PairHolding))
	}
	haElectionEvents.WithLabelValues(reason).Inc()
	tk.LogIt(tk.LogInfo, "HA reason=%s instance=%s peer=%s\n", reason, cmn.CIDefault, ch.l2PairPeer)
	ch.haWithdrawPending.Store(true)
	ch.sweepWithdrawnVIPs()
	ch.haPairState.Store(uint32(bfd.PairWithdrawn))
	// Send rank 1 even after a failed address removal. The sweep keeps this
	// node out of the election until it can verify the remaining addresses.
	ch.announcePair()
}

func (ch *CIStateH) sweepWithdrawnVIPs() {
	deadline := time.Now().Add(haWithdrawalBudget)
	for !mh.mtx.TryLock() {
		if time.Until(deadline) <= 0 {
			haElectionEvents.WithLabelValues("vip_withdrawal_failed").Inc()
			tk.LogIt(tk.LogWarning, "HA reason=vip_withdrawal_failed error=rule lock timed out\n")
			return
		}
		time.Sleep(time.Millisecond)
	}
	defer mh.mtx.Unlock()
	if !ch.haWithdrawPending.Load() || ch.pairState() == bfd.PairEligible {
		return
	}
	if mh.zr != nil && mh.zr.Rules != nil {
		for vip, ruleVIP := range mh.zr.Rules.vipMap {
			ip := ruleVIP.pVIP
			if ip == nil {
				ip = net.ParseIP(vip)
			}
			if ch.protectsL2VIP(ruleVIP.inst) && !ruleVIP.egr && ip.To4() != nil && !ip.IsUnspecified() {
				ch.rememberWithdrawVIP(ip.String())
			}
		}
	}
	ch.CIStateUpdate(cmn.HASMod{Instance: cmn.CIDefault, State: cmn.CIBackupStateString, Vip: net.IPv4zero})
	pending := ch.haWithdrawVIPs
	attempts := 0
	if len(pending) != 0 {
		handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
		if err == nil {
			defer handle.Close()
			for attempts < 3 && time.Now().Before(deadline) && len(pending) != 0 {
				attempts++
				err = clearWithdrawnVIPs(handle, pending, deadline)
			}
		}
		if len(pending) != 0 {
			haElectionEvents.WithLabelValues("vip_withdrawal_failed").Inc()
			tk.LogIt(tk.LogWarning, "HA reason=vip_withdrawal_failed attempts=%d remaining=%v error=%v\n",
				attempts, pending, err)
			return
		}
	}
	ch.haWithdrawPending.Store(false)
	tk.LogIt(tk.LogInfo, "HA VIP withdrawal complete attempts=%d\n", attempts)
}

func (ch *CIStateH) rememberWithdrawVIP(vip string) {
	if ch.haWithdrawVIPs == nil {
		ch.haWithdrawVIPs = make(map[string]struct{})
	}
	ch.haWithdrawVIPs[vip] = struct{}{}
}

// clearWithdrawnVIPs removes host addresses from the existing L2 VIP devices
// and retains failed entries for the next attempt. Physical interface
// addresses belong to the operator and are excluded.
type haVIPNetlink interface {
	SetSocketTimeout(time.Duration) error
	LinkList() ([]netlink.Link, error)
	AddrList(netlink.Link, int) ([]netlink.Addr, error)
	AddrDel(netlink.Link, *netlink.Addr) error
}

func clearWithdrawnVIPs(h haVIPNetlink, pending map[string]struct{}, deadline time.Time) error {
	timeout := func() error {
		remaining := time.Until(deadline)
		if remaining < time.Millisecond {
			return errors.New("VIP withdrawal budget exhausted")
		}
		return h.SetSocketTimeout(remaining)
	}
	if err := timeout(); err != nil {
		return err
	}
	links, err := h.LinkList()
	if err != nil {
		return err
	}
	byIndex := make(map[int]netlink.Link, len(links))
	for _, link := range links {
		byIndex[link.Attrs().Index] = link
	}
	if err := timeout(); err != nil {
		return err
	}
	addresses, err := h.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	failed := make(map[string]struct{})
	var lastErr error
	for _, addr := range addresses {
		ip := addr.IP.String()
		link := byIndex[addr.LinkIndex]
		if _, tracked := pending[ip]; !tracked || addr.IPNet == nil {
			continue
		}
		if link == nil {
			failed[ip] = struct{}{}
			lastErr = errors.New("link changed during VIP withdrawal")
			continue
		}
		ones, bits := addr.Mask.Size()
		if bits != 32 || ones != 32 || (link.Attrs().Name != "lo" && link.Attrs().Name != "llb-rule-"+ip) {
			continue
		}
		if err := timeout(); err != nil {
			return err
		}
		if err := h.AddrDel(link, &addr); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			lastErr = err
			failed[ip] = struct{}{}
		}
	}
	for ip := range pending {
		if _, keep := failed[ip]; !keep {
			delete(pending, ip)
		}
	}
	return lastErr
}
