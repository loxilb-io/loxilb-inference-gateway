/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
	"net"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

func qosTestRules(entries ...*ruleEnt) *RuleH {
	rules := &RuleH{}
	rules.tables[RtLB].eMap = make(map[string]*ruleEnt)
	for idx, entry := range entries {
		rules.tables[RtLB].eMap[string(rune('a'+idx))] = entry
	}
	return rules
}

func qosTestRule(ip string, port uint16, proto uint8, actType ruleTActType) *ruleEnt {
	parsedIP := net.ParseIP(ip)
	maskBits := 128
	if parsedIP.To4() != nil {
		maskBits = 32
		parsedIP = parsedIP.To4()
	}
	return &ruleEnt{
		tuples: ruleTuples{
			l3Dst:  ruleIPTuple{addr: net.IPNet{IP: parsedIP, Mask: net.CIDRMask(maskBits, maskBits)}},
			l4Dst:  rule16RTuple{valMin: port},
			l4Prot: rule8Tuple{val: proto},
		},
		act: ruleAct{actType: actType},
	}
}

func TestGetLBRuleByKeyMatchesIPv4AndIPv6WithSharedParser(t *testing.T) {
	ipv4 := qosTestRule("20.20.20.1", 443, 6, RtActFullNat)
	ipv6 := qosTestRule("2001:db8::20", 8443, 17, RtActFullNat)
	rules := qosTestRules(ipv4, ipv6)

	if got := rules.getLBRuleByKey("20.20.20.1:443:tcp"); got != ipv4 {
		t.Fatalf("legacy IPv4 key resolved %p, want %p", got, ipv4)
	}
	if got := rules.getLBRuleByKey("[2001:db8::20]:8443:udp"); got != ipv6 {
		t.Fatalf("bracketed IPv6 key resolved %p, want %p", got, ipv6)
	}
	if got := rules.getLBRuleByKey("2001:db8::20:8443:udp"); got != nil {
		t.Fatalf("ambiguous bracketless IPv6 key resolved %p", got)
	}
}

func TestPolAddPropagatesAttachmentProgrammingFailure(t *testing.T) {
	savedDP, savedDPEbpf := mh.dp, mh.dpEbpf
	mh.dp = &DpH{ToDpCh: make(chan interface{}, 4)}
	mh.dpEbpf = nil
	t.Cleanup(func() {
		mh.dp = savedDP
		mh.dpEbpf = savedDPEbpf
	})

	rule := qosTestRule("2001:db8::20", 443, 6, RtActFullProxy)
	rules := qosTestRules(rule)
	zone := &Zone{Rules: rules}
	pols := &PolH{
		PolMap: make(map[PolKey]*PolEntry),
		Zone:   zone,
		Mark:   tk.NewCounter(1, MaxPols),
	}
	zone.Pols = pols

	rc, err := pols.PolAdd("ipv6-fullproxy", cmn.PolInfo{CommittedInfoRate: MinPolRate}, cmn.PolObj{
		PolObjName: "[2001:db8::20]:443:tcp",
		AttachMent: cmn.PolAttachLbRule,
	})
	if err == nil || rc != PolAttachErr || !strings.Contains(err.Error(), "fullproxy shaper config failed") {
		t.Fatalf("PolAdd must surface attachment failure, got rc=%d err=%v", rc, err)
	}
	if len(pols.PolMap) != 0 {
		t.Fatalf("failed policy must be rolled back, found %d policy entries", len(pols.PolMap))
	}
}

func TestPolAddRejectsBracketlessIPv6BeforeProgramming(t *testing.T) {
	pols := &PolH{PolMap: make(map[PolKey]*PolEntry)}
	rc, err := pols.PolAdd("ambiguous", cmn.PolInfo{CommittedInfoRate: MinPolRate}, cmn.PolObj{
		PolObjName: "2001:db8::20:443:tcp",
		AttachMent: cmn.PolAttachLbRule,
	})
	if err == nil || rc != PolAttachErr || !strings.Contains(err.Error(), "bracketed") {
		t.Fatalf("bracketless IPv6 must be rejected explicitly, got rc=%d err=%v", rc, err)
	}
}
