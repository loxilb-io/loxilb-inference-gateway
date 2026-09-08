/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package loxinet

import (
	"strings"

	cmn "github.com/loxilb-io/loxilb/common"
	nlp "github.com/vishvananda/netlink"
)

// tcAttachVerified reports whether the loxilb TC program is actually
// present on the interface's ingress hook right now. This is the same
// kernel-side check loadEbpfPgm performs after an attach (a BPF filter
// whose name carries tc_packet_func on the clsact ingress hook) -- the
// netlink answer, not the control plane's bookkeeping.
func tcAttachVerified(link nlp.Link) bool {
	filters, err := nlp.FilterList(link, nlp.HANDLE_MIN_INGRESS)
	if err != nil {
		return false
	}
	for _, f := range filters {
		if t, ok := f.(*nlp.BpfFilter); ok {
			if strings.Contains(t.Name, "tc_packet_func") {
				return true
			}
		}
	}
	return false
}

// NetEbpfAttachmentGet - live per-interface eBPF attachment status.
//
// A "tc" entry is emitted for every port the control plane dispatched a
// program load for (SInfo.BpfLoaded intent), with Attached carrying the
// kernel-verified truth; intent-true/attached-false is precisely the
// divergence an operator readiness probe needs to see. An "xdp" entry
// is emitted only where the kernel reports an XDP program attached --
// XDP expectation depends on compile-time datapath flags this layer
// cannot see, so absence is not reported as divergence.
//
// In proxy-only mode (--proxyonlymode) no eBPF program is expected on
// any interface and the dump is empty rather than a wall of
// attached=false false alarms.
func (*NetAPIStruct) NetEbpfAttachmentGet() ([]cmn.EbpfAttachmentDump, error) {
	if mh.disBPF {
		return []cmn.EbpfAttachmentDump{}, nil
	}
	ports, err := mh.zr.Ports.PortsToGet()
	if err != nil {
		return nil, err
	}
	dumps := []cmn.EbpfAttachmentDump{}
	for _, p := range ports {
		if !p.SInfo.BpfLoaded {
			continue
		}
		link, lerr := nlp.LinkByName(p.Name)
		if lerr != nil {
			// The port table knows an interface the kernel no longer
			// has -- nothing can be attached to it.
			dumps = append(dumps, cmn.EbpfAttachmentDump{Name: p.Name, Mode: "tc", Attached: false})
			continue
		}
		dumps = append(dumps, cmn.EbpfAttachmentDump{Name: p.Name, Mode: "tc", Attached: tcAttachVerified(link)})
		if xdp := link.Attrs().Xdp; xdp != nil && xdp.Attached {
			dumps = append(dumps, cmn.EbpfAttachmentDump{Name: p.Name, Mode: "xdp", Attached: true})
		}
	}
	return dumps, nil
}
