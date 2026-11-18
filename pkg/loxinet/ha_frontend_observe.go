// Copyright (c) 2026 LoxiLB Authors
// SPDX-License-Identifier: Apache-2.0

package loxinet

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	tk "github.com/loxilb-io/loxilb/internal/tk"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type haFrontendObservation struct {
	name  string
	index int
	state string
}

type haFrontendObserver struct {
	mu      sync.Mutex
	targets map[string]haFrontendObservation
}

func newHAFrontendObserver() *haFrontendObserver {
	return &haFrontendObserver{targets: make(map[string]haFrontendObservation)}
}

func (o *haFrontendObserver) track(vip string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, exists := o.targets[vip]; !exists {
		o.targets[vip] = haFrontendObservation{}
	}
}

func (o *haFrontendObserver) untrack(vip string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.targets, vip)
}

func haFrontendLinkState(attrs *netlink.LinkAttrs) string {
	if attrs.Flags&net.FlagUp == 0 {
		return "admin-down"
	}
	if attrs.RawFlags&unix.IFF_LOWER_UP == 0 {
		return "carrier-down"
	}
	return "up"
}

func (o *haFrontendObserver) record(vip string, next haFrontendObservation, reason string) {
	old := o.targets[vip]
	if old == next {
		return
	}
	o.targets[vip] = next
	tk.LogIt(tk.LogInfo, "ha frontend observe vip=%s interface=%s ifindex=%d state=%s previous=%s previous_ifindex=%d reason=%s\n",
		vip, next.name, next.index, next.state, old.state, old.index, reason)
}

func (o *haFrontendObserver) event(event netlink.LinkUpdate) {
	attrs := event.Attrs()
	o.mu.Lock()
	defer o.mu.Unlock()
	for vip, old := range o.targets {
		if old.index != attrs.Index || old.name != attrs.Name || old.state == "deleted" {
			continue
		}
		next := old
		next.state = haFrontendLinkState(attrs)
		if event.Header.Type == unix.RTM_DELLINK {
			next.state = "deleted"
		}
		o.record(vip, next, "link-event")
	}
}

// Only a unique, healthy directly connected interface may establish a latch.
// Use the address prefix because the kernel can withdraw its connected route
// during a fault. Host addresses, including loxilb's VIPs, are not candidates.
func haFrontendCandidate(vip net.IP, links map[int]netlink.Link, addrs []netlink.Addr) *netlink.LinkAttrs {
	selected := haFrontendPrefixLink(vip, links, addrs)
	if selected != nil && haFrontendLinkState(selected) == "up" {
		return selected
	}
	return nil
}

func haFrontendPrefixLink(vip net.IP, links map[int]netlink.Link, addrs []netlink.Addr) *netlink.LinkAttrs {
	var selected *netlink.LinkAttrs
	for _, addr := range addrs {
		link := links[addr.LinkIndex]
		if link == nil || addr.IPNet == nil || addr.Flags&unix.IFA_F_SECONDARY != 0 {
			continue
		}
		ones, bits := addr.Mask.Size()
		attrs := link.Attrs()
		if bits != 32 || ones == 32 || !addr.Contains(vip) ||
			attrs.Flags&net.FlagLoopback != 0 || link.Type() == "dummy" || strings.HasPrefix(attrs.Name, "llb-rule-") {
			continue
		}
		if selected != nil && selected.Index != attrs.Index {
			return nil
		}
		selected = attrs
	}
	return selected
}

func (o *haFrontendObserver) reconcile(links []netlink.Link, addrs []netlink.Addr) {
	byIndex := make(map[int]netlink.Link, len(links))
	for _, link := range links {
		byIndex[link.Attrs().Index] = link
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for vip, old := range o.targets {
		if old.index != 0 && old.state != "deleted" {
			next := old
			link := byIndex[old.index]
			if link == nil || link.Attrs().Name != old.name {
				next.state = "deleted"
			} else {
				next.state = haFrontendLinkState(link.Attrs())
			}
			o.record(vip, next, "snapshot-repair")
			continue
		}
		candidate := haFrontendCandidate(net.ParseIP(vip), byIndex, addrs)
		if candidate == nil || (old.name != "" && old.name != candidate.Name) {
			if old.index == 0 {
				o.record(vip, haFrontendObservation{state: "unresolved"}, "no-unique-healthy-frontend")
			}
			continue
		}
		reason := "latched"
		if old.index != 0 {
			reason = "recreated"
		}
		o.record(vip, haFrontendObservation{name: candidate.Name, index: candidate.Index, state: "up"}, reason)
	}
}

func (o *haFrontendObserver) run(ctx context.Context) {
	subscribeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	updates := make(chan netlink.LinkUpdate, 64)
	err := netlink.LinkSubscribeWithOptions(updates, subscribeCtx.Done(), netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			if ctx.Err() == nil {
				tk.LogIt(tk.LogWarning, "ha frontend observe reason=link-subscription-error error=%v\n", err)
			}
		},
	})
	if err != nil {
		tk.LogIt(tk.LogWarning, "ha frontend observe reason=link-subscription-unavailable error=%v\n", err)
		updates = nil
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	snapshotFailed := false
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-updates:
			if !ok {
				tk.LogIt(tk.LogWarning, "ha frontend observe reason=link-subscription-closed fallback=snapshot\n")
				updates = nil
				cancel()
				continue
			}
			o.event(event)
		case <-ticker.C:
			o.mu.Lock()
			idle := len(o.targets) == 0
			o.mu.Unlock()
			if idle {
				continue
			}
			links, err := netlink.LinkList()
			if err == nil {
				var addrs []netlink.Addr
				addrs, err = netlink.AddrList(nil, netlink.FAMILY_V4)
				if err == nil {
					o.reconcile(links, addrs)
				}
			}
			if err != nil && !snapshotFailed {
				tk.LogIt(tk.LogWarning, "ha frontend observe reason=snapshot-unavailable error=%v\n", err)
			}
			snapshotFailed = err != nil
		}
	}
}
