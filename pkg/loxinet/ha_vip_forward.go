// Copyright (c) 2026 NetLOX Inc
// SPDX-License-Identifier: Apache-2.0

package loxinet

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// The local table (priority 0) delivers owned VIPs to their listeners.
// This rule drops traffic to an unowned VIP before the ordinary route
// lookup can relay it to the peer. It remains installed during handoff,
// so adding or removing the VIP address switches both paths atomically.
const haVIPForwardGuardPriority = 1

func setHAVIPForwardGuard(vip net.IP, add bool) error {
	message, flags := unix.RTM_DELRULE, unix.NLM_F_ACK
	if add {
		message = unix.RTM_NEWRULE
		flags |= unix.NLM_F_CREATE | unix.NLM_F_EXCL
	}
	req := nl.NewNetlinkRequest(message, flags)
	header := &nl.RtMsg{RtMsg: unix.RtMsg{Family: unix.AF_INET, Dst_len: 32, Type: unix.FR_ACT_BLACKHOLE}}
	req.AddData(header)
	req.AddData(nl.NewRtAttr(unix.FRA_DST, vip.To4()))
	req.AddData(nl.NewRtAttr(unix.FRA_PRIORITY, nl.Uint32Attr(haVIPForwardGuardPriority)))
	req.AddData(nl.NewRtAttr(unix.FRA_PROTOCOL, []byte{unix.RTPROT_STATIC}))
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	if (add && errors.Is(err, unix.EEXIST)) || (!add && errors.Is(err, unix.ENOENT)) {
		return nil
	}
	return err
}
