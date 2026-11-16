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

package loxinet

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// ai_gw_netid_t comes from the datapath header (see ai_gw_exports.h).
#include "ai_gw_exports.h"
*/
import "C"

import "unsafe"

// llb_ai_netid_resolve finds the network-identity binding of a request's
// source on a service. The admission gate calls it at most once per
// request, and only for a service the bound set names.
//
// Parameters:
//
//	clientIP  – the socket peer, dotted IPv4 ("" when unknown)
//	inIfindex – the interface the connection arrived on; 0 when not read
//	svcIdent  – the service identity, "VIP:port"
//	model     – the model the request names, for model_ok ("" when none)
//	out       – the answer; zeroed here before anything is written
//
// Returns 0 when it answered (out.matched says whether a binding matches)
// and -1 when it could not: no snapshot, or a failure inside. It reads an
// immutable snapshot and takes no lock.
//
//export llb_ai_netid_resolve
func llb_ai_netid_resolve(clientIP *C.char, inIfindex C.int, svcIdent *C.char, model *C.char, out *C.ai_gw_netid_t) C.int {
	if out == nil {
		return -1
	}
	*out = C.ai_gw_netid_t{}
	// netidAnswerFor recovers a failure of the resolver itself; the copies
	// below run on bounded strings into zeroed fields of known size.
	ans, rc := netidAnswerFor(netidActive.Load(), C.GoString(clientIP), int(inIfindex),
		C.GoString(svcIdent), C.GoString(model))
	if rc != 0 {
		return -1
	}
	if !ans.matched {
		return 0
	}
	out.matched = 1
	if ans.strict {
		out.enforce = 1
	}
	if ans.credNetwork {
		out.credential_network = 1
	}
	if ans.modelOK {
		out.model_ok = 1
	}
	if ans.forward {
		out.forward_identity = 1
	}
	cCopyStr((*C.char)(unsafe.Pointer(&out.tenant_id[0])), ans.tenant, 128)
	cCopyStr((*C.char)(unsafe.Pointer(&out.binding[0])), ans.binding, 64)
	return 0
}
