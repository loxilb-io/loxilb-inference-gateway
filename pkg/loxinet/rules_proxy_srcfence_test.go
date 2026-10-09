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

import (
	"errors"
	"net"
	"reflect"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// fenceRule builds the minimum of a load-balancer rule the fence reads: the
// VIP tuple, the mode and the allowed sources.
func fenceRule(t *testing.T, vip string, port uint16, mode cmn.LBMode, srcs ...string) *ruleEnt {
	t.Helper()
	ip := net.ParseIP(vip)
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	r := &ruleEnt{}
	r.tuples.l3Dst = ruleIPTuple{net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}}
	r.tuples.l4Dst = rule16RTuple{port, port, true}
	r.tuples.l4Prot = rule8Tuple{6, 0xff}
	r.act.action = &ruleLBActs{mode: mode}
	for _, s := range srcs {
		_, pref, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("bad cidr %s: %v", s, err)
		}
		r.srcList = append(r.srcList, &allowedSrcElem{srcPref: pref})
	}
	return r
}

func fenceAllow(src string) cmn.FwRuleArg {
	return cmn.FwRuleArg{SrcIP: src, DstIP: "10.10.10.254/32", DstPortMin: 8080, DstPortMax: 8080, Proto: 6, Pref: lbProxySrcFenceAllowPref}
}

var fenceDrop = cmn.FwRuleArg{SrcIP: "0.0.0.0/0", DstIP: "10.10.10.254/32", DstPortMin: 8080, DstPortMax: 8080, Proto: 6, Pref: lbProxySrcFenceDropPref}

// A fullproxy rule with allowed sources wants one allow per source, scoped to
// its own VIP and port, and one catch-all drop one preference below.
func TestProxySrcFenceWanted(t *testing.T) {
	r := fenceRule(t, "10.10.10.254", 8080, cmn.LBModeFullProxy, "192.0.2.0/24", "198.51.100.7/32")
	want := []cmn.FwRuleArg{fenceAllow("192.0.2.0/24"), fenceAllow("198.51.100.7/32"), fenceDrop}
	if got := lbProxySrcFenceWanted(r); !reflect.DeepEqual(got, want) {
		t.Fatalf("fence:\n got %+v\nwant %+v", got, want)
	}
	if lbProxySrcFenceAllowPref <= lbProxySrcFenceDropPref {
		t.Fatalf("allow pref %d must sort before drop pref %d", lbProxySrcFenceAllowPref, lbProxySrcFenceDropPref)
	}
}

// The fence exists only where the NAT-side source check cannot reach: a NAT
// rule keeps the mark + CHKSRC path, a rule without sources has nothing to
// fence, and the data plane proxies IPv4 only.
func TestProxySrcFenceWantedOnlyForFullProxyV4WithSources(t *testing.T) {
	for name, r := range map[string]*ruleEnt{
		"nat rule":      fenceRule(t, "10.10.10.254", 8080, cmn.LBModeDefault, "192.0.2.0/24"),
		"fullnat rule":  fenceRule(t, "10.10.10.254", 8080, cmn.LBModeFullNAT, "192.0.2.0/24"),
		"no sources":    fenceRule(t, "10.10.10.254", 8080, cmn.LBModeFullProxy),
		"v6 fullproxy":  fenceRule(t, "2001:db8::1", 8080, cmn.LBModeFullProxy, "2001:db8:1::/48"),
		"no action set": {tuples: fenceRule(t, "10.10.10.254", 8080, cmn.LBModeFullProxy, "192.0.2.0/24").tuples},
	} {
		if got := lbProxySrcFenceWanted(r); got != nil {
			t.Fatalf("%s: wanted no fence, got %+v", name, got)
		}
	}
}

// A port range rule fences the whole range.
func TestProxySrcFenceWantedPortRange(t *testing.T) {
	r := fenceRule(t, "10.10.10.254", 8080, cmn.LBModeFullProxy, "192.0.2.0/24")
	r.tuples.l4Dst = rule16RTuple{8080, 8090, true}
	got := lbProxySrcFenceWanted(r)
	for _, fw := range got {
		if fw.DstPortMin != 8080 || fw.DstPortMax != 8090 {
			t.Fatalf("port range not carried: %+v", fw)
		}
	}
}

// Installing: allows before the drop. Removing: the drop before the allows.
// Replacing one source for another keeps the drop in place and never removes
// an allow that stays wanted.
func TestProxySrcFencePlanOrder(t *testing.T) {
	a, b, c := fenceAllow("192.0.2.0/24"), fenceAllow("198.51.100.0/24"), fenceAllow("203.0.113.9/32")

	adds, dels := lbProxySrcFencePlan(nil, []cmn.FwRuleArg{a, b, fenceDrop})
	if !reflect.DeepEqual(adds, []cmn.FwRuleArg{a, b, fenceDrop}) || dels != nil {
		t.Fatalf("fresh install: adds %+v dels %+v", adds, dels)
	}

	adds, dels = lbProxySrcFencePlan([]cmn.FwRuleArg{a, b, fenceDrop}, nil)
	if adds != nil || !reflect.DeepEqual(dels, []cmn.FwRuleArg{fenceDrop, a, b}) {
		t.Fatalf("teardown: adds %+v dels %+v", adds, dels)
	}

	adds, dels = lbProxySrcFencePlan([]cmn.FwRuleArg{a, b, fenceDrop}, []cmn.FwRuleArg{a, c, fenceDrop})
	if !reflect.DeepEqual(adds, []cmn.FwRuleArg{c}) || !reflect.DeepEqual(dels, []cmn.FwRuleArg{b}) {
		t.Fatalf("replace b->c: adds %+v dels %+v", adds, dels)
	}

	// A fence that was only half installed (drop missing) is completed, not
	// rebuilt.
	adds, dels = lbProxySrcFencePlan([]cmn.FwRuleArg{a}, []cmn.FwRuleArg{a, fenceDrop})
	if !reflect.DeepEqual(adds, []cmn.FwRuleArg{fenceDrop}) || dels != nil {
		t.Fatalf("complete half fence: adds %+v dels %+v", adds, dels)
	}
}

// Every fence rule carries the auto-generated source-check mark, which is what
// keeps it out of configuration snapshots alongside the NAT-side allow rules.
func TestProxySrcFenceOptsCarrySrcChkMark(t *testing.T) {
	for _, fw := range []cmn.FwRuleArg{fenceAllow("192.0.2.0/24"), fenceDrop} {
		isDrop := fw.Pref == lbProxySrcFenceDropPref
		opts := cmn.FwOptArg{Allow: !isDrop, Drop: isDrop, Mark: SrcChkFwMark}
		if opts.Mark&SrcChkFwMark == 0 || opts.Allow == opts.Drop {
			t.Fatalf("fence opts for %+v: %+v", fw, opts)
		}
	}
}

// allowedSources on any rule is refused in proxy-only mode: neither the NAT
// mark path nor the fullproxy fence has a datapath to run in there.
func TestAddLbRuleAllowedSourcesRefusedInProxyOnly(t *testing.T) {
	saved := mh.disBPF
	mh.disBPF = true
	t.Cleanup(func() { mh.disBPF = saved })
	R := &RuleH{}
	serv := cmn.LbServiceArg{ServIP: "10.10.10.254", ServPort: 8080, Proto: "tcp", Mode: cmn.LBModeFullProxy}
	_, err := R.AddLbRule(serv, nil, nil, []cmn.LbAllowedSrcIPArg{{Prefix: "192.0.2.0/24"}}, nil)
	if err == nil {
		t.Fatalf("proxy-only accepted allowedSources")
	}
	var ruleArg *cmn.RuleArgumentError
	if !errors.As(err, &ruleArg) {
		t.Fatalf("want RuleArgumentError (HTTP 400), got %T: %v", err, err)
	}
}
