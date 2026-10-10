/*
 * Copyright (c) 2026 NetLOX Inc
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

package loxinet

import (
	"fmt"
	"net"
	"sort"

	cmn "github.com/loxilb-io/loxilb/common"
)

// A TC fence protects packets before host, path or model can be selected.
// Such pools therefore share one source policy, including an empty policy.
func normalizeListenerSources(srcs []cmn.LbAllowedSrcIPArg) ([]cmn.LbAllowedSrcIPArg, error) {
	set := make(map[string]bool, len(srcs))
	for _, src := range srcs {
		_, pref, err := net.ParseCIDR(src.Prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid allowedSources prefix: %w", err)
		}
		set[pref.String()] = true
	}
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]cmn.LbAllowedSrcIPArg, 0, len(keys))
	for _, key := range keys {
		out = append(out, cmn.LbAllowedSrcIPArg{Prefix: key})
	}
	return out, nil
}

func listenerSourcePoliciesEqual(have []*allowedSrcElem, want []cmn.LbAllowedSrcIPArg) bool {
	set := make(map[string]bool, len(have))
	for _, src := range have {
		set[src.srcPref.String()] = true
	}
	if len(set) != len(want) {
		return false
	}
	for _, src := range want {
		if !set[src.Prefix] {
			return false
		}
	}
	return true
}

// Overlapping port ranges must also agree: their packet fences overlap even
// if their logical listener keys differ. Protocol and address remain separate.
func (R *RuleH) lbListenerSourcesConflict(self *ruleEnt, rt *ruleTuples, want []cmn.LbAllowedSrcIPArg) *ruleEnt {
	var found *ruleEnt
	var foundKey string
	for key, r := range R.tables[RtLB].eMap {
		if r == self || !lbRuleIsFullProxy(r) {
			continue
		}
		if !r.tuples.l3Dst.addr.IP.Equal(rt.l3Dst.addr.IP) || r.tuples.l4Prot.val != rt.l4Prot.val {
			continue
		}
		if r.tuples.l4Dst.valMax < rt.l4Dst.valMin || rt.l4Dst.valMax < r.tuples.l4Dst.valMin {
			continue
		}
		if !listenerSourcePoliciesEqual(r.srcList, want) && (found == nil || key < foundKey) {
			found, foundKey = r, key
		}
	}
	return found
}

// Each pool records its interest in the shared firewall entries. Removing
// one interest must not remove an entry still required by another live pool.
func (R *RuleH) proxySrcFenceNeededByPeer(self *ruleEnt, fw cmn.FwRuleArg) bool {
	for _, r := range R.tables[RtLB].eMap {
		if r == self {
			continue
		}
		for _, needed := range lbProxySrcFenceWanted(r) {
			if needed == fw {
				return true
			}
		}
	}
	return false
}
