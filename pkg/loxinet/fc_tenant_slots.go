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

import (
	"context"
	"fmt"
	"os"
	"strconv"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// fcTenantSlotsFromEnv is the tenant-table size a model pool is created
// with: LLB_FC_TENANT_SLOTS held to its range, the default when unset or not
// a number. It mirrors fc_tenant_slots_from_env in the data plane, which is
// the value pools actually get; this copy only feeds the warning below.
func fcTenantSlotsFromEnv() int {
	n, err := strconv.Atoi(os.Getenv("LLB_FC_TENANT_SLOTS"))
	if err != nil || n < 0 || n > 100000000 {
		return cmn.FcTenantSlotsDefault
	}
	if n < cmn.FcTenantSlotsMin {
		return cmn.FcTenantSlotsMin
	}
	if n > cmn.FcTenantSlotsMax {
		return cmn.FcTenantSlotsMax
	}
	return n
}

// fcTenantShareWanted is the tenant share a rule asks for: its own value,
// else the environment's. 0 and 100 are no share.
func fcTenantShareWanted(serv *cmn.LbServiceArg) uint32 {
	pct := serv.FcTenantMaxSharePct
	if pct == 0 {
		// Parsed at 32 bits: a value that does not fit is an error and reads
		// as no share, like any other value of 100 or more, never as its low
		// bits.
		if n, err := strconv.ParseUint(os.Getenv("LLB_FC_TENANT_MAX_SHARE_PCT"), 10, 32); err == nil && n > 0 {
			if n > cmn.FcTenantMaxSharePctMax {
				n = cmn.FcTenantMaxSharePctMax
			}
			pct = uint32(n)
		}
	}
	if pct >= cmn.FcTenantMaxSharePctMax {
		return 0
	}
	return pct
}

// fcTenantSlotsWarning is the text for a rule that holds tenants to a share
// on a node that knows more tenants than a pool tracks by name: the ones
// past the table would share one budget. It is advice, never a refusal, and
// it can be early, because the table only has to hold the tenants active at
// the same moment. Empty when there is nothing to say.
func fcTenantSlotsWarning(serv *cmn.LbServiceArg, known, slots int) string {
	if fcTenantShareWanted(serv) == 0 || known <= slots {
		return ""
	}
	return fmt.Sprintf("fc_tenant_max_share_pct: %d tenants are known to this node and a model pool tracks %d at once "+
		"(LLB_FC_TENANT_SLOTS, at most %d); tenants active past that share one budget",
		known, slots, cmn.FcTenantSlotsMax)
}

// NetFcTenantSlotsWarning returns the tenant-table warning for a rule that
// was just applied, and logs it. The count comes from the key store; with
// no store, or one that cannot be read now, there is no warning.
func (na *NetAPIStruct) NetFcTenantSlotsWarning(lm *cmn.LbRuleMod) string {
	if lm == nil || fcTenantShareWanted(&lm.Serv) == 0 {
		return ""
	}
	store := mh.AIKeyService.Load()
	if store == nil {
		return ""
	}
	// No request to inherit from here: the rule apply runs on its own, so
	// the operation budget alone bounds the count.
	known, err := store.KnownTenantCount(context.Background())
	if err != nil {
		return ""
	}
	msg := fcTenantSlotsWarning(&lm.Serv, known, fcTenantSlotsFromEnv())
	if msg != "" {
		tk.LogIt(tk.LogWarning, "[FC] rule %s:%d: %s\n", lm.Serv.ServIP, lm.Serv.ServPort, msg)
	}
	return msg
}
