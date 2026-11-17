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
// The service key as the health updates declare it in dpebpf_linux.go: one
// cgo package shares one definition.
struct proxy_ent {
  uint32_t xip;
  uint16_t xport;
  uint8_t inv;
  uint8_t protocol;
};
// The report of loxilb-ebpf/common/sockproxy.h, which this preamble cannot
// include. The two declarations must stay member for member the same.
struct proxy_betls_state {
  uint8_t have_epssl;
  uint8_t verify;
  uint8_t client_cert_loaded;
  uint32_t generation;
  char ca_id[64];
  char client_id[64];
  char server_name[256];
};
int proxy_get_backend_tls_state(struct proxy_ent *key, struct proxy_betls_state *out);
*/
import "C"

import (
	"net"

	tk "github.com/loxilb-io/loxilb/internal/tk"
)

// DpBackendTLSStateGet - the backend TLS policy the listener of a service has
// installed. ok is false when the service has no listener in the data plane
// (a rule that has not been pushed, or an IPv6 service).
func (e *DpEbpfH) DpBackendTLSStateGet(svcIP net.IP, svcPort uint16, proto uint8) (backendTLSInstalled, bool) {
	var key C.struct_proxy_ent
	var st C.struct_proxy_betls_state

	if svcIP.To4() == nil {
		return backendTLSInstalled{}, false
	}
	key.xip = C.uint(tk.IPtonl(svcIP))
	key.xport = C.ushort(tk.Htons(svcPort))
	key.protocol = C.uchar(proto)
	if C.proxy_get_backend_tls_state(&key, &st) != 0 {
		return backendTLSInstalled{}, false
	}
	return backendTLSInstalled{
		tls:          st.have_epssl != 0,
		verify:       st.verify != 0,
		clientCert:   st.client_cert_loaded != 0,
		generation:   uint32(st.generation),
		caCertID:     C.GoString(&st.ca_id[0]),
		clientCertID: C.GoString(&st.client_id[0]),
		serverName:   C.GoString(&st.server_name[0]),
	}, true
}
