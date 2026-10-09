/*
 * Copyright (c) 2026 NetLOX Inc
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

/*
#include <stdint.h>
// The service key as dpebpf_betls_linux.go declares it: the listener lookup
// reads xip, xport and protocol only.
struct proxy_ent;
int proxy_get_fe_conn_stats(struct proxy_ent *key, uint32_t *conns, uint32_t *limit,
                            uint64_t *refused);
*/
import "C"

import (
	"net"
	"unsafe"

	tk "github.com/loxilb-io/loxilib"
)

// feConnStats - what a fullproxy listener reports about its client
// connections: the live count, the connectionLimit it enforces at accept
// (0 = unlimited) and how many connections it has reset at that limit.
type feConnStats struct {
	conns   uint32
	limit   uint32
	refused uint64
}

// DpFeConnStatsGet - the client-connection gauge of the listener of a
// fullproxy service. ok is false when the service has no listener in the data
// plane (a rule that has not been pushed, or an IPv6 service). A fullproxy
// rule never enters nat_map, so this gauge — not nat_ep_map.conc_conns — is
// its activeConns and the count its connectionLimit is enforced against.
func (e *DpEbpfH) DpFeConnStatsGet(svcIP net.IP, svcPort uint16, proto uint8) (feConnStats, bool) {
	var key struct {
		xip      uint32
		xport    uint16
		inv      uint8
		protocol uint8
	}
	var st feConnStats

	if svcIP.To4() == nil {
		return st, false
	}
	key.xip = uint32(tk.IPtonl(svcIP))
	key.xport = uint16(tk.Htons(svcPort))
	key.protocol = proto
	if C.proxy_get_fe_conn_stats((*C.struct_proxy_ent)(unsafe.Pointer(&key)),
		(*C.uint32_t)(&st.conns), (*C.uint32_t)(&st.limit), (*C.uint64_t)(&st.refused)) != 0 {
		return feConnStats{}, false
	}
	return st, true
}
