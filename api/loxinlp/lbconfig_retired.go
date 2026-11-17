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

package loxinlp

import (
	"strings"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"
)

// dropRetiredLbKeys brings a rule of an lbconfig.txt written by an earlier
// release to what this release carries: the retired mtls_backend keys are
// discarded and a verify_server_cert request is reset to false, each with a
// warning that names the rule and the keys (never a value). It returns lb.
// None of this reached the data plane, so the rule is replayed as it behaved
// before.
func dropRetiredLbKeys(lb *cmn.LbRuleMod) *cmn.LbRuleMod {
	if names := lb.Serv.MTLSBackend.DropRetired(); len(names) > 0 {
		tk.LogIt(tk.LogWarning, "nlp: LB %s:%d/%s: mtls_backend keys no longer supported and ignored: %s\n",
			lb.Serv.ServIP, lb.Serv.ServPort, lb.Serv.Proto, strings.Join(names, ", "))
	}
	if lb.Serv.MTLSBackend.ResetUnverifiable(lb.Serv.BackendCaCertId) {
		tk.LogIt(tk.LogWarning, "nlp: LB %s:%d/%s: mtls_backend.verify_server_cert names no backend_ca_cert_id and was reset to false; it had no effect\n",
			lb.Serv.ServIP, lb.Serv.ServPort, lb.Serv.Proto)
	}
	return lb
}
