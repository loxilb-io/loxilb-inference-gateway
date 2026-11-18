// Copyright (c) 2026 LoxiLB Authors
// SPDX-License-Identifier: Apache-2.0

package loxinet

import (
	"context"
	"fmt"
	"maps"
	"net"
	"sync/atomic"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"
	"github.com/loxilb-io/loxilb/options"
	bfd "github.com/loxilb-io/loxilb/pkg/proto"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	haFrontendDownHold = 300 * time.Millisecond
	haFrontendUpHold   = 5 * time.Second
)

type haFrontendSample struct {
	index int
	up    bool
	vips  map[string]struct{}
}

type haFrontendHold struct {
	index     int
	upSince   time.Time
	downSince time.Time
}

func (h *haFrontendHold) observe(now time.Time, sample haFrontendSample, eligible bool) (down, up bool) {
	if !sample.up || (eligible && sample.index != h.index) {
		h.upSince = time.Time{}
		if h.downSince.IsZero() {
			h.downSince = now
		}
		return now.Sub(h.downSince) >= haFrontendDownHold, false
	}
	h.downSince = time.Time{}
	if sample.index != h.index || h.upSince.IsZero() {
		h.index = sample.index
		h.upSince = now
	}
	return false, now.Sub(h.upSince) >= haFrontendUpHold
}

type haFrontendGate struct {
	name     string
	cluster  *CIStateH
	observer *haFrontendObserver
	allowed  atomic.Pointer[map[string]struct{}]
}

func newHAFrontendGate(name string, ch *CIStateH) (*haFrontendGate, error) {
	if !ch.protectsL2VIP(cmn.CIDefault) || options.Opts.NoNlp || options.Opts.ProxyModeOnly {
		return nil, fmt.Errorf("requires on-premises IPv4 L2 --ka with the datapath enabled")
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("frontend interface %q: %w", name, err)
	}
	routes, err := netlink.RouteGet(ch.RemoteIP)
	if err != nil {
		return nil, fmt.Errorf("lookup BFD egress to %s: %w", ch.RemoteIP, err)
	}
	if len(routes) != 1 || routes[0].LinkIndex == 0 {
		return nil, fmt.Errorf("BFD egress to %s cannot be identified", ch.RemoteIP)
	}
	if routes[0].LinkIndex == link.Attrs().Index {
		return nil, fmt.Errorf("frontend interface %q is also the BFD egress to %s", name, ch.RemoteIP)
	}
	ch.haPairState.Store(uint32(bfd.PairWithdrawn))
	return &haFrontendGate{name: name, cluster: ch}, nil
}

func (g *haFrontendGate) allows(vip string) bool {
	allowed := g.allowed.Load()
	if allowed == nil {
		return false
	}
	_, ok := (*allowed)[vip]
	return ok
}

func (g *haFrontendGate) snapshot(h *netlink.Handle) haFrontendSample {
	links, err := h.LinkList()
	if err != nil {
		return haFrontendSample{}
	}
	addrs, err := h.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return haFrontendSample{}
	}
	byIndex := make(map[int]netlink.Link, len(links))
	var frontend int
	for _, link := range links {
		attrs := link.Attrs()
		byIndex[attrs.Index] = link
		if attrs.Name == g.name && haFrontendLinkState(attrs) == "up" {
			frontend = attrs.Index
		}
	}
	if frontend == 0 {
		return haFrontendSample{}
	}
	g.observer.mu.Lock()
	vips := make(map[string]struct{}, len(g.observer.targets))
	for vip := range g.observer.targets {
		vips[vip] = struct{}{}
	}
	g.observer.mu.Unlock()
	if len(vips) == 0 {
		return haFrontendSample{}
	}
	for vip := range vips {
		selected := haFrontendPrefixLink(net.ParseIP(vip), byIndex, addrs)
		if selected == nil || selected.Index != frontend {
			return haFrontendSample{}
		}
	}
	return haFrontendSample{index: frontend, up: true, vips: vips}
}

func (g *haFrontendGate) run(ctx context.Context) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		tk.LogIt(tk.LogWarning, "HA reason=frontend_down interface=%s error=%v\n", g.name, err)
		haElectionEvents.WithLabelValues("frontend_down").Inc()
		return
	}
	defer h.Close()
	if err := h.SetSocketTimeout(100 * time.Millisecond); err != nil {
		tk.LogIt(tk.LogWarning, "HA reason=frontend_down interface=%s error=%v\n", g.name, err)
		haElectionEvents.WithLabelValues("frontend_down").Inc()
		return
	}
	updates := make(chan netlink.LinkUpdate, 64)
	if err := netlink.LinkSubscribeWithOptions(updates, ctx.Done(), netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			if ctx.Err() == nil {
				tk.LogIt(tk.LogWarning, "HA frontend link subscription interface=%s error=%v\n", g.name, err)
			}
		},
	}); err != nil {
		tk.LogIt(tk.LogWarning, "HA frontend link subscription interface=%s error=%v; polling\n", g.name, err)
		updates = nil
	}
	snapshots := time.NewTicker(250 * time.Millisecond)
	defer snapshots.Stop()
	ticks := time.NewTicker(25 * time.Millisecond)
	defer ticks.Stop()
	var hold haFrontendHold
	reportedDown := false
	sample := g.snapshot(h)
	for {
		select {
		case <-ctx.Done():
			return
		case update, ok := <-updates:
			if !ok {
				updates = nil
				continue
			}
			attrs := update.Attrs()
			if attrs.Index != hold.index && attrs.Name != g.name {
				continue
			}
			if attrs.Index == hold.index && (update.Header.Type == unix.RTM_DELLINK ||
				attrs.Name != g.name || haFrontendLinkState(attrs) != "up") {
				sample = haFrontendSample{}
			} else {
				sample = g.snapshot(h)
			}
		case <-snapshots.C:
			sample = g.snapshot(h)
		case <-ticks.C:
		}
		now := time.Now()
		eligible := g.cluster.pairState() == bfd.PairEligible
		down, up := hold.observe(now, sample, eligible)
		if down && !reportedDown {
			reportedDown = true
			if eligible {
				g.cluster.withdrawPair("frontend_down")
			} else {
				haElectionEvents.WithLabelValues("frontend_down").Inc()
				tk.LogIt(tk.LogInfo, "HA reason=frontend_down interface=%s\n", g.name)
			}
		}
		if sample.up && (up || eligible) && sample.index == hold.index {
			g.updateAllowed(sample.vips, eligible)
		}
		if up && !eligible && !g.cluster.haWithdrawPending.Load() {
			sample = g.snapshot(h)
			if _, stillUp := hold.observe(time.Now(), sample, false); !stillUp {
				continue
			}
			g.cluster.haTransitionMu.Lock()
			if !mh.shutdownInProgress.Load() && !g.cluster.haWithdrawPending.Load() {
				g.allowed.Store(&sample.vips)
				g.cluster.haPairState.Store(uint32(bfd.PairEligible))
				g.cluster.announcePair()
				reportedDown = false
				tk.LogIt(tk.LogInfo, "HA frontend eligible interface=%s ifindex=%d\n", g.name, sample.index)
			}
			g.cluster.haTransitionMu.Unlock()
		}
	}
}

func (g *haFrontendGate) updateAllowed(vips map[string]struct{}, eligible bool) {
	previous := g.allowed.Load()
	if previous != nil && maps.Equal(*previous, vips) {
		return
	}
	g.allowed.Store(&vips)
	if eligible {
		go func() {
			mh.mtx.Lock()
			defer mh.mtx.Unlock()
			role, _ := g.cluster.CIStateGetInst(cmn.CIDefault)
			if role == cmn.CIMasterStateString && !g.cluster.l2VIPBlocked(cmn.CIDefault) {
				mh.zr.Rules.RulesSyncToClusterState(cmn.CIDefault, role)
			}
		}()
	}
}
