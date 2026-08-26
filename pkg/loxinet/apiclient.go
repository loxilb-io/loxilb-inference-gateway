/*
 * Copyright (c) 2022 NetLOX Inc
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
	"fmt"
	"net"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// This file implements interface defined in cmn.NetHookInterface
// The implementation is thread-safe and can be called by multiple-clients at once

// NetAPIStruct - empty struct for anchoring client routines
type NetAPIStruct struct {
	BgpPeerMode bool
}

// NetAPIInit - Initialize a new instance of NetAPI
func NetAPIInit(bgpPeerMode bool) *NetAPIStruct {
	na := new(NetAPIStruct)
	na.BgpPeerMode = bgpPeerMode
	return na
}

// NetMirrorGet - Get a mirror in loxinet
func (*NetAPIStruct) NetMirrorGet() ([]cmn.MirrGetMod, error) {
	// There is no locking requirement for this operation
	ret, _ := mh.zr.Mirrs.MirrGet()
	return ret, nil
}

// NetMirrorAdd - Add a mirror in loxinet
func (*NetAPIStruct) NetMirrorAdd(mm *cmn.MirrMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Mirrs.MirrAdd(mm.Ident, mm.Info, mm.Target)
	return ret, err
}

// NetMirrorDel - Delete a mirror in loxinet
func (*NetAPIStruct) NetMirrorDel(mm *cmn.MirrMod) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Mirrs.MirrDelete(mm.Ident)
	return ret, err
}

// NetPortGet - Get Port Information of loxinet
func (*NetAPIStruct) NetPortGet() ([]cmn.PortDump, error) {
	ret, err := mh.zr.Ports.PortsToGet()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// NetPortAdd - Add a port in loxinet
func (na *NetAPIStruct) NetPortAdd(pm *cmn.PortMod) (int, error) {
	if na.BgpPeerMode {
		return PortBaseErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Ports.PortAdd(pm.Dev, pm.LinkIndex, pm.Ptype, RootZone,
		PortHwInfo{pm.MacAddr, pm.Link, pm.State, pm.Mtu, pm.Master, pm.Real,
			uint32(pm.TunID), pm.TunSrc, pm.TunDst}, PortLayer2Info{false, 0})

	return ret, err
}

// NetPortDel - Delete port from loxinet
func (na *NetAPIStruct) NetPortDel(pm *cmn.PortMod) (int, error) {
	if na.BgpPeerMode {
		return PortBaseErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Ports.PortDel(pm.Dev, pm.Ptype)
	return ret, err
}

// NetVlanGet - Get Vlan Information of loxinet
func (na *NetAPIStruct) NetVlanGet() ([]cmn.VlanGet, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	ret, err := mh.zr.Vlans.VlanGet()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// NetVlanAdd - Add vlan info to loxinet
func (na *NetAPIStruct) NetVlanAdd(vm *cmn.VlanMod) (int, error) {
	if na.BgpPeerMode {
		return VlanBaseErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Vlans.VlanAdd(vm.Vid, vm.Dev, RootZone, vm.LinkIndex,
		PortHwInfo{vm.MacAddr, vm.Link, vm.State, vm.Mtu, "", "", vm.TunID, nil, nil})
	if ret == VlanExistsErr {
		ret = 0
		err = nil
	}

	return ret, err
}

// NetVlanDel - Delete vlan info from loxinet
func (na *NetAPIStruct) NetVlanDel(vm *cmn.VlanMod) (int, error) {
	if na.BgpPeerMode {
		return VlanBaseErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Vlans.VlanDelete(vm.Vid)
	return ret, err
}

// NetVlanPortAdd - Add a port to vlan in loxinet
func (na *NetAPIStruct) NetVlanPortAdd(vm *cmn.VlanPortMod) (int, error) {
	if na.BgpPeerMode {
		return VlanPortCreateErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Vlans.VlanPortAdd(vm.Vid, vm.Dev, vm.Tagged)
	return ret, err
}

// NetVlanPortDel - Delete a port from vlan in loxinet
func (na *NetAPIStruct) NetVlanPortDel(vm *cmn.VlanPortMod) (int, error) {
	if na.BgpPeerMode {
		return VlanPortExistErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Vlans.VlanPortDelete(vm.Vid, vm.Dev, vm.Tagged)
	return ret, err
}

// NetAddrGet - Get an IPv4 Address info from loxinet
func (na *NetAPIStruct) NetAddrGet() ([]cmn.IPAddrGet, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	// There is no locking requirement for this operation
	ret := mh.zr.L3.IfaGet()
	return ret, nil
}

// NetAddrAdd - Add an ipv4 address in loxinet
func (na *NetAPIStruct) NetAddrAdd(am *cmn.IPAddrMod) (int, error) {
	if na.BgpPeerMode {
		return L3AddrErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.L3.IfaAdd(am.Dev, am.IP)
	// A4: keep SelfIPCache fresh on successful add. Both NLP
	// (api/loxinlp/nlp.go calls hooks.NetAddrAdd) and REST flows reach
	// here, so this single hook covers both event sources.
	if err == nil {
		if ipBE, ok := parseIPv4BEFromCIDR(am.IP); ok {
			SelfIPCache.Add(ipBE)
		}
	}
	return ret, err
}

// NetAddrDel - Delete an ipv4 address in loxinet
func (na *NetAPIStruct) NetAddrDel(am *cmn.IPAddrMod) (int, error) {
	if na.BgpPeerMode {
		return L3AddrErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.L3.IfaDelete(am.Dev, am.IP)
	// A4: keep SelfIPCache fresh on successful delete (mirror
	// of NetAddrAdd). Stale cache entries would cause resolveFlowMACs
	// to return wrong MAC for an IP that has been removed.
	if err == nil {
		if ipBE, ok := parseIPv4BEFromCIDR(am.IP); ok {
			SelfIPCache.Del(ipBE)
		}
	}
	return ret, err
}

// NetNeighGet - Get a neighbor in loxinet
func (na *NetAPIStruct) NetNeighGet() ([]cmn.NeighMod, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	ret, err := mh.zr.Nh.NeighGet()
	return ret, err
}

// NetNeighAdd - Add a neighbor in loxinet
func (na *NetAPIStruct) NetNeighAdd(nm *cmn.NeighMod) (int, error) {
	if na.BgpPeerMode {
		return NeighErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Nh.NeighAdd(nm.IP, RootZone, NeighAttr{nm.LinkIndex, nm.State, nm.HardwareAddr})
	if err != nil {
		if ret != NeighExistsErr {
			return ret, err
		}
	}

	return 0, nil
}

// NetNeighDel - Delete a neighbor in loxinet
func (na *NetAPIStruct) NetNeighDel(nm *cmn.NeighMod) (int, error) {
	if na.BgpPeerMode {
		return NeighErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Nh.NeighDelete(nm.IP, RootZone, nm.LinkIndex)
	return ret, err
}

// NetFdbAdd - Add a forwarding database entry in loxinet
func (na *NetAPIStruct) NetFdbAdd(fm *cmn.FdbMod) (int, error) {
	if na.BgpPeerMode {
		return L2ErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()
	fdbKey := FdbKey{fm.MacAddr, fm.BridgeID}
	fdbAttr := FdbAttr{fm.Dev, fm.Dst, fm.Type}
	ret, err := mh.zr.L2.L2FdbAdd(fdbKey, fdbAttr)
	return ret, err
}

// NetFdbDel - Delete a forwarding database entry in loxinet
func (na *NetAPIStruct) NetFdbDel(fm *cmn.FdbMod) (int, error) {
	if na.BgpPeerMode {
		return L2ErrBase, errors.New("running in bgp only mode")
	}

	fdbKey := FdbKey{fm.MacAddr, fm.BridgeID}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.L2.L2FdbDel(fdbKey)
	return ret, err
}

// NetRouteGet - Get Route info from loxinet
func (na *NetAPIStruct) NetRouteGet() ([]cmn.RouteGet, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	// There is no locking requirement for this operation
	ret, _ := mh.zr.Rt.RouteGet()
	return ret, nil
}

// NetRouteAdd - Add a route in loxinet
func (na *NetAPIStruct) NetRouteAdd(rm *cmn.RouteMod) (int, error) {
	var ret int
	var err error
	var cloudPrivateInterfaceID int

	if len(rm.GWs) <= 0 {
		return RtNhErr, errors.New("invalid gws")
	}
	if na.BgpPeerMode {
		return RtNhErr, errors.New("running in bgp only mode")
	}
	if mh.cloudHook != nil {
		cloudPrivateInterfaceID, _ = mh.cloudHook.CloudGetPrivateInterfaceID()
	}
	intfRt := false
	mlen, _ := rm.Dst.Mask.Size()
	if rm.GWs[0].Gw == nil {
		// This is an interface route
		if (tk.IsNetIPv4(rm.Dst.IP.String()) && mlen == 32) || (tk.IsNetIPv6(rm.Dst.IP.String()) && mlen == 128) {
			intfRt = true
			rm.GWs[0].Gw = rm.Dst.IP
		}
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ra := RtAttr{Protocol: rm.Protocol, OSFlags: rm.Flags, HostRoute: false, Ifi: rm.GWs[0].LinkIndex, IfRoute: intfRt}
	if rm.GWs[0].Gw != nil {
		var na []RtNhAttr
		for _, gw := range rm.GWs {
			linkIndex := gw.LinkIndex
			cloudGwIp := gw.Gw
			if rm.Dst.String() == "0.0.0.0/0" && cloudPrivateInterfaceID > 0 {
				linkIndex = cloudPrivateInterfaceID
				cloudGwIp = awsCIDRnet.IP.Mask(awsCIDRnet.Mask)
				cloudGwIp[3]++
			}
			na = append(na, RtNhAttr{cloudGwIp, linkIndex})
		}
		ret, err = mh.zr.Rt.RtAdd(rm.Dst, RootZone, ra, na)

	} else {
		ret, err = mh.zr.Rt.RtAdd(rm.Dst, RootZone, ra, nil)
	}
	return ret, err
}

// NetRouteDel - Delete a route in loxinet
func (na *NetAPIStruct) NetRouteDel(rm *cmn.RouteMod) (int, error) {
	if na.BgpPeerMode {
		return RtNhErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Rt.RtDelete(rm.Dst, RootZone)
	return ret, err
}

// NetLbRuleAdd - Add a load-balancer rule in loxinet
func (na *NetAPIStruct) NetLbRuleAdd(lm *cmn.LbRuleMod) (int, error) {
	if na.BgpPeerMode {
		return RuleErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()
	var ips []string
	ret, err := mh.zr.Rules.AddLbRule(lm.Serv, lm.SecIPs[:], lm.SecVIPs[:], lm.SrcIPs[:], lm.Eps[:])
	if err == nil && lm.Serv.Bgp {
		if mh.bgp != nil {
			ips = append(ips, lm.Serv.ServIP)
			for _, ip := range lm.SecIPs {
				ips = append(ips, ip.SecIP)
			}
			mh.bgp.AddBGPRule(cmn.CIDefault, ips)
		} else {
			tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
		}
	}
	return ret, err
}

// NetLbRuleDel - Delete a load-balancer rule in loxinet
func (na *NetAPIStruct) NetLbRuleDel(lm *cmn.LbRuleMod) (int, error) {
	if na.BgpPeerMode {
		return RuleErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ips := mh.zr.Rules.GetLBRuleSecIPs(lm.Serv)
	ret, err := mh.zr.Rules.DeleteLbRule(lm.Serv)
	if lm.Serv.Bgp {
		if mh.bgp != nil {
			ips = append(ips, lm.Serv.ServIP)
			mh.bgp.DelBGPRule(cmn.CIDefault, ips)
		} else {
			tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
		}
	}
	return ret, err
}

// NetLbRuleGet - Get a load-balancer rule from loxinet
func (na *NetAPIStruct) NetLbRuleGet() ([]cmn.LbRuleMod, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	ret, err := mh.zr.Rules.GetLBRule()
	return ret, err
}

// l7ProtoToNum maps a service protocol string to its IP protocol number
// (matching the rest of the rules layer: tcp=6, udp=17, sctp=132). L7 content
// routing is meaningful only over the stream protocols; unknown values default to
// tcp (the only protocol the fullproxy L7 path serves today).
func l7ProtoToNum(proto string) uint8 {
	switch proto {
	case "udp":
		return 17
	case "sctp":
		return 132
	default:
		return 6 // tcp
	}
}

// NetL7PolicyApply - attach an ordered L7 content-routing route array to the
// running sockproxy rule fronting vip:port:proto. The route IR
// reaches the eBPF userspace proxy via the SEPARATE DpProxyAttachL7Policy CGO call
// (never inline on the 4096-byte proxy_arg). An empty route set detaches.
func (na *NetAPIStruct) NetL7PolicyApply(vip string, port uint16, proto string, routes []cmn.L7RuleArg) (int, error) {
	if na.BgpPeerMode {
		return RuleErrBase, errors.New("running in bgp only mode")
	}
	ip := net.ParseIP(vip)
	if ip == nil {
		return RuleErrBase, fmt.Errorf("l7policy: invalid VIP %q", vip)
	}
	if mh.dpEbpf == nil {
		return RuleErrBase, errors.New("l7policy: ebpf datapath not initialized")
	}
	if ret := DpProxyAttachL7Policy(ip, port, l7ProtoToNum(proto), routes); ret != 0 {
		return RuleErrBase, fmt.Errorf("l7policy: attach failed for %s:%d (bad regex or no such service)", vip, port)
	}
	return 0, nil
}

// NetL7PolicyRemove - detach any L7 policy from the vip:port:proto sockproxy rule
// (regfrees every compiled REGEX program on the C side).
func (na *NetAPIStruct) NetL7PolicyRemove(vip string, port uint16, proto string) (int, error) {
	if na.BgpPeerMode {
		return RuleErrBase, errors.New("running in bgp only mode")
	}
	ip := net.ParseIP(vip)
	if ip == nil {
		return RuleErrBase, fmt.Errorf("l7policy: invalid VIP %q", vip)
	}
	if mh.dpEbpf == nil {
		return RuleErrBase, errors.New("l7policy: ebpf datapath not initialized")
	}
	if ret := DpProxyDetachL7Policy(ip, port, l7ProtoToNum(proto)); ret != 0 {
		return RuleErrBase, fmt.Errorf("l7policy: detach failed for %s:%d", vip, port)
	}
	return 0, nil
}

// NetCtInfoGet - Get connection track info from loxinet
func (na *NetAPIStruct) NetCtInfoGet() ([]cmn.CtInfo, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	// There is no locking requirement for this operation
	ret := mh.dp.DpMapGetCt4()
	return ret, nil
}

// NetSessionAdd - Add a 3gpp user-session info in loxinet
func (na *NetAPIStruct) NetSessionAdd(sm *cmn.SessionMod) (int, error) {
	if na.BgpPeerMode {
		return SessErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Sess.SessAdd(sm.Ident, sm.IP, sm.AnTun, sm.CnTun)
	return ret, err
}

// NetSessionDel - Delete a 3gpp user-session info in loxinet
func (na *NetAPIStruct) NetSessionDel(sm *cmn.SessionMod) (int, error) {
	if na.BgpPeerMode {
		return SessErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Sess.SessDelete(sm.Ident)
	return ret, err
}

// NetSessionUlClAdd - Add a 3gpp ulcl-filter info in loxinet
func (na *NetAPIStruct) NetSessionUlClAdd(sr *cmn.SessionUlClMod) (int, error) {
	if na.BgpPeerMode {
		return SessErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Sess.UlClAddCls(sr.Ident, sr.Args)
	return ret, err
}

// NetSessionUlClDel - Delete a 3gpp ulcl-filter info in loxinet
func (na *NetAPIStruct) NetSessionUlClDel(sr *cmn.SessionUlClMod) (int, error) {
	if na.BgpPeerMode {
		return SessErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Sess.UlClDeleteCls(sr.Ident, sr.Args)
	return ret, err
}

// NetSessionGet - Get 3gpp user-session info in loxinet
func (na *NetAPIStruct) NetSessionGet() ([]cmn.SessionMod, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	// There is no locking requirement for this operation
	ret, err := mh.zr.Sess.SessGet()
	return ret, err
}

// NetSessionUlClGet - Get 3gpp ulcl filter info from loxinet
func (na *NetAPIStruct) NetSessionUlClGet() ([]cmn.SessionUlClMod, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	// There is no locking requirement for this operation
	ret, err := mh.zr.Sess.SessUlclGet()
	return ret, err
}

// NetPolicerGet - Get a policer in loxinet
func (na *NetAPIStruct) NetPolicerGet() ([]cmn.PolMod, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	// There is no locking requirement for this operation
	ret, err := mh.zr.Pols.PolGetAll()
	return ret, err
}

// NetPolicerAdd - Add a policer in loxinet
func (na *NetAPIStruct) NetPolicerAdd(pm *cmn.PolMod) (int, error) {
	if na.BgpPeerMode {
		return PolInfoErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Pols.PolAdd(pm.Ident, pm.Info, pm.Target)
	return ret, err
}

// NetPolicerDel - Delete a policer in loxinet
func (na *NetAPIStruct) NetPolicerDel(pm *cmn.PolMod) (int, error) {
	if na.BgpPeerMode {
		return PolInfoErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Pols.PolDelete(pm.Ident)
	return ret, err
}

// NetCIStateGet - Get current node cluster state
func (na *NetAPIStruct) NetCIStateGet() ([]cmn.HASMod, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	// There is no locking requirement for this operation
	ret, err := mh.has.CIStateGet()
	return ret, err
}

// NetCIStateMod - Modify cluster state
func (na *NetAPIStruct) NetCIStateMod(hm *cmn.HASMod) (int, error) {
	if na.BgpPeerMode {
		return CIErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	_, err := mh.has.CIStateUpdate(*hm)
	if err != nil {
		return -1, err
	}

	return 0, nil
}

// NetCIStateMod - Modify cluster state
func (na *NetAPIStruct) NetBFDGet() ([]cmn.BFDMod, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	if !mh.has.SpawnKa || mh.has.Bs == nil {
		mh.mtx.Unlock()
		tk.LogIt(tk.LogError, "[CLUSTER] BFD sessions not running\n")
		return nil, errors.New("bfd session not running")
	}
	bp := mh.has.Bs
	mh.mtx.Unlock()
	return bp.BFDGet()
}

// NetBFDAdd - Add BFD Session
func (na *NetAPIStruct) NetBFDAdd(bm *cmn.BFDMod) (int, error) {
	if na.BgpPeerMode {
		return CIErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	_, err := mh.has.CIBFDSessionAdd(*bm)
	if err != nil {
		return -1, err
	}

	return 0, nil
}

// NetBFDDel - Delete BFD Session
func (na *NetAPIStruct) NetBFDDel(bm *cmn.BFDMod) (int, error) {
	if na.BgpPeerMode {
		return CIErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	_, err := mh.has.CIBFDSessionDel(*bm)
	if err != nil {
		return -1, err
	}

	return 0, nil
}

// NetFwRuleAdd - Add a firewall rule in loxinet
func (na *NetAPIStruct) NetFwRuleAdd(fm *cmn.FwRuleMod) (int, error) {
	if na.BgpPeerMode {
		return RuleTupleErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Rules.AddFwRule(fm.Rule, fm.Opts)
	return ret, err
}

// NetFwRuleDel - Delete a firewall rule in loxinet
func (na *NetAPIStruct) NetFwRuleDel(fm *cmn.FwRuleMod) (int, error) {
	if na.BgpPeerMode {
		return RuleTupleErr, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Rules.DeleteFwRule(fm.Rule)
	return ret, err
}

// NetIPFilterAdd - Add an IP filter rule (whitelist/blacklist) in loxinet
func (na *NetAPIStruct) NetIPFilterAdd(fm *cmn.IPFilterMod) (int, error) {
	if na.BgpPeerMode {
		return -1, errors.New("running in bgp only mode")
	}

	// Validate filter type
	var filterType IPFilterType
	if fm.FilterType == "whitelist" {
		filterType = IPFilterWhitelist
	} else if fm.FilterType == "blacklist" {
		filterType = IPFilterBlacklist
	} else {
		return -1, errors.New("invalid filter_type: must be 'whitelist' or 'blacklist'")
	}

	// Parse CIDR
	_, ipNet, err := net.ParseCIDR(fm.CIDR)
	if err != nil {
		return -1, fmt.Errorf("invalid CIDR: %v", err)
	}

	// Validate action
	var action uint8
	if fm.Action == "allow" {
		action = 0
	} else if fm.Action == "drop" {
		action = 1
	} else {
		return -1, errors.New("invalid action: must be 'allow' or 'drop'")
	}

	// Create work queue entry
	var status DpStatusT
	wq := IPFilterDpWorkQ{
		Work:       DpCreate,
		Status:     &status,
		FilterType: filterType,
		IPNet:      *ipNet,
		Zone:       fm.Zone,
		Priority:   fm.Priority,
		Action:     action,
	}

	// Submit to datapath
	ret := mh.dp.DpHooks.DpIPFilterAdd(&wq)
	if ret != 0 {
		return ret, errors.New("failed to add IP filter rule to datapath")
	}

	return 0, nil
}

// NetIPFilterDel - Delete an IP filter rule from loxinet
func (na *NetAPIStruct) NetIPFilterDel(fm *cmn.IPFilterMod) (int, error) {
	if na.BgpPeerMode {
		return -1, errors.New("running in bgp only mode")
	}

	// Validate filter type
	var filterType IPFilterType
	if fm.FilterType == "whitelist" {
		filterType = IPFilterWhitelist
	} else if fm.FilterType == "blacklist" {
		filterType = IPFilterBlacklist
	} else {
		return -1, errors.New("invalid filter_type: must be 'whitelist' or 'blacklist'")
	}

	// Parse CIDR
	_, ipNet, err := net.ParseCIDR(fm.CIDR)
	if err != nil {
		return -1, fmt.Errorf("invalid CIDR: %v", err)
	}

	// Create work queue entry
	var status DpStatusT
	wq := IPFilterDpWorkQ{
		Work:       DpRemove,
		Status:     &status,
		FilterType: filterType,
		IPNet:      *ipNet,
		Zone:       fm.Zone,
		Priority:   fm.Priority,
		Action:     0, // Don't care for delete
	}

	// Submit to datapath
	ret := mh.dp.DpHooks.DpIPFilterDel(&wq)
	if ret != 0 {
		return ret, errors.New("no such ipfilter rule (datapath delete failed)")
	}

	return 0, nil
}

// NetIPFilterGet - Get IP filter rules from loxinet
func (na *NetAPIStruct) NetIPFilterGet() ([]cmn.IPFilterEntry, error) {
	var ret []cmn.IPFilterEntry

	// Get whitelist entries
	whitelistEntries, err := mh.dp.DpHooks.DpIPFilterGet(IPFilterWhitelist)
	if err != nil {
		return ret, fmt.Errorf("failed to get whitelist: %v", err)
	}
	ret = append(ret, whitelistEntries...)

	// Get blacklist entries
	blacklistEntries, err := mh.dp.DpHooks.DpIPFilterGet(IPFilterBlacklist)
	if err != nil {
		return ret, fmt.Errorf("failed to get blacklist: %v", err)
	}
	ret = append(ret, blacklistEntries...)

	return ret, nil
}

// NetSecurityRateSet - Set unified security rate limiting configuration (P0-5 + P0-6)
func (na *NetAPIStruct) NetSecurityRateSet(config *cmn.SecurityRateConfig) (int, error) {
	if na.BgpPeerMode {
		return RuleErrBase, errors.New("running in bgp only mode")
	}

	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	tk.LogIt(tk.LogInfo, "[API] Security rate limiting: SYN=%v (threshold=%d, cookie=%d), ConnRate=%v (rate=%d), UDP=%v (pkt=%d, bw=%dMB)\n",
		config.SYNEnabled, config.SYNThreshold, config.CookieThreshold,
		config.ConnRateEnabled, config.RatePerSec,
		config.UDPEnabled, config.UDPPktThreshold, config.UDPBandwidthMB)

	// Apply configuration to eBPF datapath
	if mh.dpEbpf != nil {
		dpConfig := SecurityRateConfig{
			SYNEnabled:      config.SYNEnabled,
			SYNThreshold:    config.SYNThreshold,
			CookieThreshold: config.CookieThreshold,
			ConnRateEnabled: config.ConnRateEnabled,
			RatePerSec:      config.RatePerSec,
			UDPEnabled:      config.UDPEnabled,
			UDPPktThreshold: config.UDPPktThreshold,
			UDPBandwidthMB:  config.UDPBandwidthMB,
			WhitelistIPs:    config.WhitelistIPs,
		}

		err := mh.dpEbpf.DpSecurityRateConfigSet(dpConfig)
		if err != nil {
			tk.LogIt(tk.LogError, "[API] Failed to set security rate config in eBPF: %v\n", err)
			// Fail closed: a security control that could not be programmed into the
			// datapath must report failure, not a false success. mh.securityRateConfig
			// is deliberately NOT updated here so GET keeps reporting the config that
			// is actually enforced.
			return RuleErrBase, err
		}
	}

	// Store configuration only after the datapath accepted it, so the reported
	// state never diverges from the enforced state.
	mh.securityRateConfig = *config

	return 0, nil
}

// NetSecurityRateGet - Get unified security rate limiting configuration and statistics
func (na *NetAPIStruct) NetSecurityRateGet() (*cmn.SecurityRateState, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}

	// Snapshot the config under the lock, then release it BEFORE the stats
	// fetch: DpSecurityRateGetStats iterates the (up to 100K-entry) per-IP
	// tracking maps one syscall per key and must not starve config writers.
	mh.mtx.RLock()
	cfgSnapshot := mh.securityRateConfig
	mh.mtx.RUnlock()

	// Start with stored configuration
	state := &cmn.SecurityRateState{
		Config: cfgSnapshot,
		Stats: cmn.SecurityRateStats{
			SYNBlocked:      0,
			SYNPassed:       0,
			SYNCookies:      0,
			ConnBlocked:     0,
			ConnPassed:      0,
			UDPBlocked:      0,
			UDPPassed:       0,
			UDPBytesBlocked: 0,
			UDPBytesPassed:  0,
			UniqueIPs:       0,
		},
	}

	// Retrieve statistics from eBPF maps
	if mh.dpEbpf != nil {
		dpStats, err := mh.dpEbpf.DpSecurityRateGetStats()
		if err == nil {
			// Convert eBPF stats to common stats
			state.Stats.SYNBlocked = dpStats.SYNBlocked
			state.Stats.SYNPassed = dpStats.SYNPassed
			state.Stats.SYNCookies = dpStats.SYNCookies
			state.Stats.ConnBlocked = dpStats.ConnBlocked
			state.Stats.ConnPassed = dpStats.ConnPassed
			state.Stats.UDPBlocked = dpStats.UDPBlocked
			state.Stats.UDPPassed = dpStats.UDPPassed
			state.Stats.UDPBytesBlocked = dpStats.UDPBytesBlocked
			state.Stats.UDPBytesPassed = dpStats.UDPBytesPassed
			state.Stats.UniqueIPs = dpStats.UniqueIPs
		} else {
			tk.LogIt(tk.LogDebug, "[API] Failed to get security rate stats from eBPF: %v\n", err)
		}
	}

	return state, nil
}

// NetSecurityRateStatsGet - Get only security rate limiting statistics (for Prometheus)
// Pattern: Lightweight stats-only version of NetSecurityRateGet for metrics collection
func (na *NetAPIStruct) NetSecurityRateStatsGet() (cmn.SecurityRateStats, error) {
	stats := cmn.SecurityRateStats{}

	if na.BgpPeerMode {
		return stats, errors.New("running in bgp only mode")
	}

	// Retrieve statistics directly from eBPF maps (no lock needed for read-only)
	if mh.dpEbpf != nil {
		dpStats, err := mh.dpEbpf.DpSecurityRateGetStats()
		if err == nil {
			// Direct assignment from eBPF stats
			stats = cmn.SecurityRateStats{
				SYNBlocked:      dpStats.SYNBlocked,
				SYNPassed:       dpStats.SYNPassed,
				SYNCookies:      dpStats.SYNCookies,
				ConnBlocked:     dpStats.ConnBlocked,
				ConnPassed:      dpStats.ConnPassed,
				UDPBlocked:      dpStats.UDPBlocked,
				UDPPassed:       dpStats.UDPPassed,
				UDPBytesBlocked: dpStats.UDPBytesBlocked,
				UDPBytesPassed:  dpStats.UDPBytesPassed,
				UniqueIPs:       dpStats.UniqueIPs,
			}
		} else {
			tk.LogIt(tk.LogDebug, "[API] Failed to get security rate stats from eBPF: %v\n", err)
			return stats, err
		}
	}

	return stats, nil
}

// NetCtErrorStatsGet - Get always-on L4 connection-error counters (for Prometheus).
// Trace-independent: reads the ct_err_stats eBPF map populated by the CT state
// machine, so the loxilb_l4_error_events_total metric is exact and present in
// every build regardless of L4 trace. Mirrors NetSecurityRateStatsGet.
func (na *NetAPIStruct) NetCtErrorStatsGet() (cmn.CtErrorStats, error) {
	stats := cmn.CtErrorStats{}

	if na.BgpPeerMode {
		return stats, errors.New("running in bgp only mode")
	}

	if mh.dpEbpf != nil {
		dpStats, err := mh.dpEbpf.DpCtErrorGetStats()
		if err == nil {
			stats = cmn.CtErrorStats{
				TCPRstClient: dpStats.TCPRstClient,
				TCPRstServer: dpStats.TCPRstServer,
				TCPErr:       dpStats.TCPErr,
				SCTPAbort:    dpStats.SCTPAbort,
				SCTPErr:      dpStats.SCTPErr,
			}
		} else {
			tk.LogIt(tk.LogDebug, "[API] Failed to get ct error stats from eBPF: %v\n", err)
			return stats, err
		}
	}

	return stats, nil
}

// NetSecurityRateResetStats - Reset security rate limiting statistics
func (na *NetAPIStruct) NetSecurityRateResetStats() (int, error) {
	if na.BgpPeerMode {
		return -1, errors.New("running in bgp only mode")
	}

	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	// Reset statistics in eBPF maps
	if mh.dpEbpf != nil {
		err := mh.dpEbpf.DpSecurityRateResetStats()
		if err != nil {
			tk.LogIt(tk.LogError, "[API] Failed to reset security rate stats: %v\n", err)
			return -1, err
		}
		tk.LogIt(tk.LogInfo, "[API] Security rate statistics reset successfully\n")
		return 0, nil
	}

	return -1, errors.New("eBPF not initialized")
}

// NetFwRuleGet - Get a firewall rule from loxinet
func (na *NetAPIStruct) NetFwRuleGet() ([]cmn.FwRuleMod, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	// GetFwRule iterates the fw rule map; hold the lock to avoid a concurrent
	// map iteration/write fatal panic against NetFwRuleAdd/NetFwRuleDel.
	mh.mtx.RLock()
	defer mh.mtx.RUnlock()

	ret, err := mh.zr.Rules.GetFwRule()
	return ret, err
}

// NetEpHostAdd - Add a LB end-point in loxinet
func (na *NetAPIStruct) NetEpHostAdd(em *cmn.EndPointMod) (int, error) {
	if na.BgpPeerMode {
		return RuleErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	// resolve probe_verify. A nil/absent pointer ⇒ verification ON
	// (the default); only an explicit false sets InsecureSkipVerify.
	probeVerify := true
	if em.ProbeVerify != nil {
		probeVerify = *em.ProbeVerify
	}
	epArgs := epHostOpts{inActTryThr: em.InActTries, probeType: em.ProbeType,
		probeReq: em.ProbeReq, probeResp: em.ProbeResp,
		probeDuration: em.ProbeDuration, probePort: em.ProbePort,
		// structured Octavia HM-content fields, additive/default-off.
		probeMethod: em.HttpMethod, probePath: em.UrlPath,
		expectedCodes: em.ExpectedCodes, httpVersion: em.HttpVersion,
		domainName: em.DomainName,
		// per-probe CA override + resolved verify toggle.
		probeCAPath: em.ProbeCaPath, probeVerify: probeVerify,
		// residual: per-probe static CRL on the same health/verify surface.
		probeCRLPath: em.ProbeCrlPath,
	}
	ret, err := mh.zr.Rules.AddEPHost(true, em.HostName, em.Name, epArgs)
	return ret, err
}

// NetEpHostDel - Delete a LB end-point in loxinet
func (na *NetAPIStruct) NetEpHostDel(em *cmn.EndPointMod) (int, error) {
	if na.BgpPeerMode {
		return RuleErrBase, errors.New("running in bgp only mode")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Rules.DeleteEPHost(true, em.Name, em.HostName, em.ProbeType, em.ProbePort)
	return ret, err
}

// NetEpHostGet - Get LB end-points from loxinet
func (na *NetAPIStruct) NetEpHostGet() ([]cmn.EndPointMod, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	ret, err := mh.zr.Rules.GetEpHosts()
	return ret, err
}

// NetEpHostStateSet - Set a host state (which can internally have multiple end-points)
func (na *NetAPIStruct) NetEpHostStateSet(em *cmn.EndPointHostMod) (int, error) {
	if na.BgpPeerMode {
		return RuleUnknownEpErr, errors.New("running in bgp only mode")
	}

	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	ret, err := mh.zr.Rules.SetEPHostState(em.HostName, em.EPPort, em.EPProto, em.State)
	return ret, err
}

// NetParamSet - Set operational params of loxinet
func (na *NetAPIStruct) NetParamSet(param cmn.ParamMod) (int, error) {
	if na.BgpPeerMode {
		return 0, errors.New("running in bgp only mode")
	}
	ret, err := mh.ParamSet(param)
	return ret, err
}

// NetParamGet - Get operational params of loxinet
func (na *NetAPIStruct) NetParamGet(param *cmn.ParamMod) (int, error) {
	if na.BgpPeerMode {
		return 0, errors.New("running in bgp only mode")
	}
	ret, err := mh.ParamGet(param)
	return ret, err
}

// NetGoBGPNeighGet - Get bgp neigh to gobgp
func (na *NetAPIStruct) NetGoBGPNeighGet() ([]cmn.GoBGPNeighGetMod, error) {
	if mh.bgp != nil {
		a, err := mh.bgp.BGPNeighGet("", false)
		if err != nil {
			return nil, err
		}
		return a, nil
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return nil, errors.New("loxilb BGP mode is disabled")

}

// NetGoBGPNeighAdd - Add bgp neigh to gobgp
func (na *NetAPIStruct) NetGoBGPNeighAdd(param *cmn.GoBGPNeighMod) (int, error) {
	if mh.bgp != nil {
		return mh.bgp.BGPNeighMod(true, param.Addr, param.RemoteAS, uint32(param.RemotePort), param.MultiHop)
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return 0, errors.New("loxilb BGP mode is disabled")

}

// NetGoBGPNeighDel - Del bgp neigh from gobgp
func (na *NetAPIStruct) NetGoBGPNeighDel(param *cmn.GoBGPNeighMod) (int, error) {
	if mh.bgp != nil {
		return mh.bgp.BGPNeighMod(false, param.Addr, param.RemoteAS, uint32(param.RemotePort), param.MultiHop)
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return 0, errors.New("loxilb BGP mode is disabled")
}

// NetGoBGPGCAdd - Add bgp global config
func (na *NetAPIStruct) NetGoBGPGCAdd(param *cmn.GoBGPGlobalConfig) (int, error) {
	if mh.bgp != nil {
		return mh.bgp.BGPGlobalConfigAdd(*param)
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return 0, errors.New("loxilb BGP mode is disabled")

}

// NetGoBGPGCGet - Get bgp global config
func (na *NetAPIStruct) NetGoBGPGCGet() (cmn.GoBGPGlobalConfig, error) {
	if mh.bgp != nil {
		return mh.bgp.BGPGlobalConfigGet()
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return cmn.GoBGPGlobalConfig{}, errors.New("loxilb BGP mode is disabled")
}

// NetHandlePanic - Handle panics
func (na *NetAPIStruct) NetHandlePanic() {
	mh.dp.DpHooks.DpEbpfUnInit()
}

func (na *NetAPIStruct) NetGoBGPPolicyDefinedSetGet(name string, DefinedTypeString string) ([]cmn.GoBGPPolicyDefinedSetMod, error) {
	if mh.bgp != nil {
		a, err := mh.bgp.GetPolicyDefinedSet(name, DefinedTypeString)
		if err != nil {
			return nil, err
		}
		return a, nil
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return nil, errors.New("loxilb BGP mode is disabled")

}

// NetGoBGPPolicyPrefixAdd - Add Prefixset in bgp
func (na *NetAPIStruct) NetGoBGPPolicyDefinedSetAdd(param *cmn.GoBGPPolicyDefinedSetMod) (int, error) {
	if mh.bgp != nil {
		return mh.bgp.AddPolicyDefinedSets(*param)
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return 0, errors.New("loxilb BGP mode is disabled")

}

// NetGoBGPPolicyPrefixAdd - Add Prefixset in bgp
func (na *NetAPIStruct) NetGoBGPPolicyDefinedSetDel(param *cmn.GoBGPPolicyDefinedSetMod) (int, error) {
	if mh.bgp != nil {
		return mh.bgp.DelPolicyDefinedSets(param.Name, param.DefinedTypeString)
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return 0, errors.New("loxilb BGP mode is disabled")

}

// NetGoBGPPolicyDefinitionsGet - Add bgp neigh to gobgp
func (na *NetAPIStruct) NetGoBGPPolicyDefinitionsGet() ([]cmn.GoBGPPolicyDefinitionsMod, error) {
	if mh.bgp != nil {
		a, err := mh.bgp.GetPolicyDefinitions()
		if err != nil {
			return nil, err
		}
		return a, nil
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return nil, errors.New("loxilb BGP mode is disabled")

}

// NetGoBGPPolicyNeighAdd - Add bgp neigh to gobgp
func (na *NetAPIStruct) NetGoBGPPolicyDefinitionAdd(param *cmn.GoBGPPolicyDefinitionsMod) (int, error) {
	if mh.bgp != nil {
		return mh.bgp.AddPolicyDefinitions(param.Name, param.Statement)
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return 0, errors.New("loxilb BGP mode is disabled")

}

// NetGoBGPPolicyNeighAdd - Add bgp neigh to gobgp
func (na *NetAPIStruct) NetGoBGPPolicyDefinitionDel(param *cmn.GoBGPPolicyDefinitionsMod) (int, error) {
	if mh.bgp != nil {
		return mh.bgp.DelPolicyDefinitions(param.Name)
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return 0, errors.New("loxilb BGP mode is disabled")

}

// NetGoBGPPolicyApplyAdd - Add bgp neigh to gobgp
func (na *NetAPIStruct) NetGoBGPPolicyApplyAdd(param *cmn.GoBGPPolicyApply) (int, error) {
	if mh.bgp != nil {
		return mh.bgp.BGPApplyPolicyToNeighbor("add", param.NeighIPAddress, param.PolicyType, param.Polices, param.RouteAction)
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return 0, errors.New("loxilb BGP mode is disabled")

}

// NetGoBGPPolicyApplyDel - Del bgp neigh to gobgp
func (na *NetAPIStruct) NetGoBGPPolicyApplyDel(param *cmn.GoBGPPolicyApply) (int, error) {
	if mh.bgp != nil {
		return mh.bgp.BGPApplyPolicyToNeighbor("del", param.NeighIPAddress, param.PolicyType, param.Polices, param.RouteAction)
	}
	tk.LogIt(tk.LogDebug, "loxilb BGP mode is disabled \n")
	return 0, errors.New("loxilb BGP mode is disabled")

}

// NetUserAdd - Add a user in loxilb
func (na *NetAPIStruct) NetUserAdd(param *cmn.User) (int, error) {
	return mh.UserService.AddUser(*param)
}

// NetUserGet - Get a user in loxilb
func (na *NetAPIStruct) NetUserGet() ([]cmn.User, error) {
	return mh.UserService.GetUsers()
}

// NetUserDel - Delete a user in loxilb
func (na *NetAPIStruct) NetUserDel(ID int) error {
	return mh.UserService.DeleteUser(ID)
}

// NetUserUpdate - Update a user in loxilb
func (na *NetAPIStruct) NetUserUpdate(param *cmn.User) error {
	return mh.UserService.UpdateUser(*param)
}

// NetUserLogin - Validate a user in loxilb
func (na *NetAPIStruct) NetUserLogin(param *cmn.User) (string, bool, error) {
	return mh.UserService.Login(param.Username, param.Password)
}

func (na *NetAPIStruct) NetUserValidate(token string) (interface{}, error) {
	return mh.UserService.ValidateToken(token)
}

// NetUserLogout - Validate a user in loxilb
func (na *NetAPIStruct) NetUserLogout(tokenString string) error {
	return mh.UserService.Logout(tokenString)
}

// NetOauthUserTokenStore - User Log in loxilb using OAuth
func (na *NetAPIStruct) NetOauthUserTokenStore(userEmail, token, refreshToken string, expiry time.Time) (string, bool, error) {
	return mh.OauthUserService.StoreOauthTokenCredentials(userEmail, token, refreshToken, expiry)
}

// NetOauthUserValidate - Validate a user in loxilb using OAuth
func (na *NetAPIStruct) NetOauthUserValidate(token string) (interface{}, error) {
	return mh.OauthUserService.ValidateOuathToken(token)
}

// NetOauthValidateAllTokens - Validate all tokens (Access & Refresh) in cache
func (na *NetAPIStruct) NetOauthValidateAllTokens(token, refreshToken string) (interface{}, error) {
	return mh.OauthUserService.ValidateOuathTokenWithRefreshToken(token, refreshToken)
}

// NetOauthDeleteToken - Delete a token credential in cache
func (na *NetAPIStruct) NetOauthDeleteToken(token string) error {
	return mh.OauthUserService.DeleteOauthTokenCredential(token)
}

func (na *NetAPIStruct) NetPrometheusEnable() error {
	mh.PrometheusInit()
	return nil
}

// ============================================================================
// GPU-Aware Load Balancing Interface Implementations
// ============================================================================

func (na *NetAPIStruct) NetDpEbpfIsGPUMonitoringEnabled() bool {
	if mh.dpEbpf == nil {
		return false
	}
	return mh.dpEbpf.IsGPUMonitoringEnabled()
}

func (na *NetAPIStruct) NetDpEbpfEnableGPUMonitoring() error {
	if mh.dpEbpf == nil {
		return fmt.Errorf("eBPF datapath not initialized")
	}
	return mh.dpEbpf.EnableGPUMonitoring()
}

func (na *NetAPIStruct) NetDpEbpfDisableGPUMonitoring() error {
	if mh.dpEbpf == nil {
		return fmt.Errorf("eBPF datapath not initialized")
	}
	return mh.dpEbpf.DisableGPUMonitoring()
}

func (na *NetAPIStruct) NetDpEbpfGetGPUMonitoringStatus() interface{} {
	if mh.dpEbpf == nil {
		return nil
	}
	return mh.dpEbpf.GetGPUMonitoringStatus()
}

func (na *NetAPIStruct) NetDpEbpfUpdateWorkerMetrics(endpointIP string, req interface{}) error {
	if mh.dpEbpf == nil {
		return fmt.Errorf("eBPF datapath not initialized")
	}
	return mh.dpEbpf.UpdateWorkerMetrics(endpointIP, req)
}

func (na *NetAPIStruct) NetDpEbpfGetAllWorkerMetrics() []interface{} {
	if mh.dpEbpf == nil {
		return []interface{}{}
	}
	return mh.dpEbpf.GetAllWorkerMetrics()
}

func (na *NetAPIStruct) NetDpEbpfCleanupStaleConversations(cutoffTime time.Time) (int, float64, error) {
	if mh.dpEbpf == nil {
		return 0, 0.0, fmt.Errorf("eBPF datapath not initialized")
	}
	return mh.dpEbpf.CleanupStaleConversations(cutoffTime)
}

// NetTraceParserRegistryGet - Get the trace parser registry for API operations
func (na *NetAPIStruct) NetTraceParserRegistryGet() (interface{}, error) {
	if mh.dpEbpf == nil {
		return nil, fmt.Errorf("eBPF datapath not initialized")
	}
	return mh.dpEbpf.NetTraceParserRegistryGet()
}

// NetTraceCatalogInfoGet - Get catalog name and parser_type by catalog ID
func (na *NetAPIStruct) NetTraceCatalogInfoGet(catalogID uint16) (string, string, error) {
	if mh.dpEbpf == nil {
		return "", "", fmt.Errorf("eBPF datapath not initialized")
	}
	return mh.dpEbpf.NetTraceCatalogInfoGet(catalogID)
}

// NetTraceParserListGet - Get list of available parsers with metadata
func (na *NetAPIStruct) NetTraceParserListGet() ([]cmn.NetTraceParserMeta, error) {
	if mh.dpEbpf == nil {
		return nil, fmt.Errorf("eBPF datapath not initialized")
	}
	return mh.dpEbpf.NetTraceParserListGet()
}

// NetTraceCatalogParserGet - Get parser name assigned to a catalog
func (na *NetAPIStruct) NetTraceCatalogParserGet(catalogID uint16) (string, error) {
	if mh.dpEbpf == nil {
		return "", fmt.Errorf("eBPF datapath not initialized")
	}
	return mh.dpEbpf.NetTraceCatalogParserGet(catalogID)
}

// NetTraceCatalogParserUpdate - Update parser assignment for a catalog
func (na *NetAPIStruct) NetTraceCatalogParserUpdate(catalogID uint16, parserName string) error {
	if mh.dpEbpf == nil {
		return fmt.Errorf("eBPF datapath not initialized")
	}
	return mh.dpEbpf.NetTraceCatalogParserUpdate(catalogID, parserName)
}

// NetTraceCatalogParserDelete - Remove parser assignment for a catalog
func (na *NetAPIStruct) NetTraceCatalogParserDelete(catalogID uint16) error {
	if mh.dpEbpf == nil {
		return fmt.Errorf("eBPF datapath not initialized")
	}
	return mh.dpEbpf.NetTraceCatalogParserDelete(catalogID)
}

// NetL4TraceEnable - Enable L4 connection tracing with sampling rate
func (na *NetAPIStruct) NetL4TraceEnable(samplingRate uint32) error {
	if mh.dpEbpf == nil {
		return fmt.Errorf("eBPF datapath not initialized")
	}

	// Lazy initialization: Start ring buffer consumer if not already running
	// Use mutex to prevent concurrent initialization
	mh.l4TracingMtx.Lock()
	if !mh.l4TracingEnabled {
		tk.LogIt(tk.LogInfo, "[L4Trace] Initializing L4 tracing (lazy initialization from API)\n")
		if err := mh.initL4Tracing(); err != nil {
			mh.l4TracingMtx.Unlock()
			tk.LogIt(tk.LogError, "[L4Trace] Failed to initialize: %v\n", err)
			return fmt.Errorf("failed to initialize L4 tracing: %w", err)
		}
	}
	mh.l4TracingMtx.Unlock()

	config := L4TraceConfig{
		Enabled:      true,
		SamplingRate: samplingRate,
	}

	if err := mh.dpEbpf.DpL4TraceConfigSet(config); err != nil {
		return err
	}

	tk.LogIt(tk.LogInfo, "[L4Trace] Config updated: version=%d enabled=true sampling=%d%%\n",
		config.Version, samplingRate)

	return nil
}

// NetL4TraceDisable - Disable L4 connection tracing
func (na *NetAPIStruct) NetL4TraceDisable() error {
	if mh.dpEbpf == nil {
		return fmt.Errorf("eBPF datapath not initialized")
	}

	config := L4TraceConfig{
		Enabled:      false,
		SamplingRate: 100, // Keep sampling rate for next enable
	}

	return mh.dpEbpf.DpL4TraceConfigSet(config)
}

// NetL4TraceGetStatus - Get current L4 tracing status and statistics
func (na *NetAPIStruct) NetL4TraceGetStatus() (*cmn.L4TraceStatus, error) {
	if mh.dpEbpf == nil {
		return nil, fmt.Errorf("eBPF datapath not initialized")
	}

	// Get config
	cfg, err := mh.dpEbpf.DpL4TraceConfigGet()
	if err != nil {
		return nil, err
	}

	// Get statistics
	stats, err := mh.dpEbpf.DpL4TraceStatsGet()
	if err != nil {
		return nil, err
	}

	return &cmn.L4TraceStatus{
		Enabled:       cfg.Enabled,
		SamplingRate:  cfg.SamplingRate,
		ConfigVersion: cfg.Version,
		Stats:         *stats,
	}, nil
}

// NetL4TraceUpdateSampling - Update L4 tracing sampling rate
func (na *NetAPIStruct) NetL4TraceUpdateSampling(samplingRate uint32) error {
	if mh.dpEbpf == nil {
		return fmt.Errorf("eBPF datapath not initialized")
	}

	// Get current config to preserve enabled state
	cfg, err := mh.dpEbpf.DpL4TraceConfigGet()
	if err != nil {
		return err
	}

	// Update only sampling rate
	cfg.SamplingRate = samplingRate

	return mh.dpEbpf.DpL4TraceConfigSet(cfg)
}

// NetL4TraceResetStats - Reset L4 tracing statistics counters
func (na *NetAPIStruct) NetL4TraceResetStats() error {
	if mh.dpEbpf == nil {
		return fmt.Errorf("eBPF datapath not initialized")
	}

	// Call global function from lxb_l4_trace.go
	ResetL4TraceStats()
	return nil
}

// IPsec API implementations

// NetIPsecGetConfig - Get global IPsec configuration
func (na *NetAPIStruct) NetIPsecGetConfig() (*cmn.IPsecConfig, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecGetConfig()
}

// NetIPsecConfigSet - Update global IPsec configuration
func (na *NetAPIStruct) NetIPsecConfigSet(cfg *cmn.IPsecConfigMod) (int, error) {
	if mh.ipsec == nil {
		return -1, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecConfigSet(cfg)
}

// NetIPsecTunnelAdd - Create a new IPsec tunnel
func (na *NetAPIStruct) NetIPsecTunnelAdd(tm *cmn.IPsecTunnelMod) (int, error) {
	if mh.ipsec == nil {
		return -1, errors.New("IPsec not initialized")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	return mh.ipsec.NetIPsecTunnelAdd(tm)
}

// NetIPsecTunnelUpdate - Update an existing IPsec tunnel in place
func (na *NetAPIStruct) NetIPsecTunnelUpdate(tm *cmn.IPsecTunnelMod) (int, error) {
	if mh.ipsec == nil {
		return -1, errors.New("IPsec not initialized")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	return mh.ipsec.NetIPsecTunnelUpdate(tm)
}

// NetIPsecTunnelAction - Initiate/terminate/restart a tunnel connection
// Note: no mh.mtx here - the action may block on strongSwan for several
// seconds and only touches IPsecH state (guarded by its own mutex)
func (na *NetAPIStruct) NetIPsecTunnelAction(name string, action string) (int, error) {
	if mh.ipsec == nil {
		return -1, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecTunnelAction(name, action)
}

// NetIPsecTunnelDel - Delete an IPsec tunnel
func (na *NetAPIStruct) NetIPsecTunnelDel(name string) (int, error) {
	if mh.ipsec == nil {
		return -1, errors.New("IPsec not initialized")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	return mh.ipsec.NetIPsecTunnelDel(name)
}

// NetIPsecTunnelGet - Get specific tunnel details
func (na *NetAPIStruct) NetIPsecTunnelGet(name string) (*cmn.IPsecTunnel, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecTunnelGet(name)
}

// NetIPsecTunnelGetAll - Get all tunnels
func (na *NetAPIStruct) NetIPsecTunnelGetAll() ([]*cmn.IPsecTunnel, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecTunnelGetAll()
}

// NetIPsecTunnelPeerConfig - Generate remote-peer strongSwan configuration
func (na *NetAPIStruct) NetIPsecTunnelPeerConfig(name string) (*cmn.IPsecPeerConfig, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecTunnelPeerConfig(name)
}

// NetIPsecSAGetAll - Get all Security Associations (stub for now)
func (na *NetAPIStruct) NetIPsecSAGetAll() ([]*cmn.IPsecSA, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecSAGetAll()
}

// NetIPsecStatsGet - Get IPsec statistics
func (na *NetAPIStruct) NetIPsecStatsGet() (*cmn.IPsecStats, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecStatsGet()
}

// NetIPsecStatsReset - Reset IPsec statistics
func (na *NetAPIStruct) NetIPsecStatsReset() (int, error) {
	if mh.ipsec == nil {
		return -1, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecStatsReset()
}

// NetIPsecCertificateAdd - Upload and install certificate
func (na *NetAPIStruct) NetIPsecCertificateAdd(cm *cmn.IPsecCertificateMod) (int, error) {
	if mh.ipsec == nil {
		return -1, errors.New("IPsec not initialized")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	return mh.ipsec.NetIPsecCertificateAdd(cm)
}

// NetIPsecCertificateDel - Delete certificate
func (na *NetAPIStruct) NetIPsecCertificateDel(name string) (int, error) {
	if mh.ipsec == nil {
		return -1, errors.New("IPsec not initialized")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	return mh.ipsec.NetIPsecCertificateDel(name)
}

// NetIPsecCertificateGet - Get certificate details
func (na *NetAPIStruct) NetIPsecCertificateGet(name string) (*cmn.IPsecCertificate, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecCertificateGet(name)
}

// NetIPsecCertificateGetAll - Get all certificates
func (na *NetAPIStruct) NetIPsecCertificateGetAll() ([]*cmn.IPsecCertificate, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecCertificateGetAll()
}

// NetIPsecCertificateValidate - Validate certificate and private key
func (na *NetAPIStruct) NetIPsecCertificateValidate(certPEM, keyPEM, passphrase string) (*cmn.IPsecCertValidation, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecCertificateValidate(certPEM, keyPEM, passphrase)
}

// NetIPsecCACertificateAdd - Add CA certificate
func (na *NetAPIStruct) NetIPsecCACertificateAdd(cm *cmn.IPsecCACertificateMod) (int, error) {
	if mh.ipsec == nil {
		return -1, errors.New("IPsec not initialized")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	return mh.ipsec.NetIPsecCACertificateAdd(cm)
}

// NetIPsecCACertificateDel - Delete CA certificate
func (na *NetAPIStruct) NetIPsecCACertificateDel(name string) (int, error) {
	if mh.ipsec == nil {
		return -1, errors.New("IPsec not initialized")
	}
	mh.mtx.Lock()
	defer mh.mtx.Unlock()

	return mh.ipsec.NetIPsecCACertificateDel(name)
}

// NetIPsecCACertificateGet - Get CA certificate details
func (na *NetAPIStruct) NetIPsecCACertificateGet(name string) (*cmn.IPsecCACertificate, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecCACertificateGet(name)
}

// NetIPsecCACertificateGetAll - Get all CA certificates
func (na *NetAPIStruct) NetIPsecCACertificateGetAll() ([]*cmn.IPsecCACertificate, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecCACertificateGetAll()
}

// NetIPsecCertificateExportAll - Export all certificates with PEM material
// (snapshot/restore only; see cmn.NetHookInterface doc comment)
func (na *NetAPIStruct) NetIPsecCertificateExportAll() ([]cmn.IPsecCertificateMod, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecCertificateExportAll()
}

// NetIPsecCACertificateExportAll - Export all CA certificates with PEM material
// (snapshot/restore only)
func (na *NetAPIStruct) NetIPsecCACertificateExportAll() ([]cmn.IPsecCACertificateMod, error) {
	if mh.ipsec == nil {
		return nil, errors.New("IPsec not initialized")
	}
	return mh.ipsec.NetIPsecCACertificateExportAll()
}

// ============================================================================
// AI Gateway - API key lifecycle management
// ============================================================================

// NetAPIKeyCreate - Create a new API key for a tenant.
func (na *NetAPIStruct) NetAPIKeyCreate(entry cmn.ApiKeyEntry) (string, string, error) {
	if mh.UserService == nil {
		return "", "", errors.New("user service not initialized")
	}
	return mh.UserService.CreateAPIKey(entry)
}

// NetAPIKeyList - List API keys. If tenantID is empty, returns all keys.
func (na *NetAPIStruct) NetAPIKeyList(tenantID string) ([]cmn.ApiKeySummary, error) {
	if mh.UserService == nil {
		return nil, errors.New("user service not initialized")
	}
	return mh.UserService.ListAPIKeys(tenantID)
}

// NetAPIKeyGet - Retrieve a single API key by its key_id.
func (na *NetAPIStruct) NetAPIKeyGet(keyID string) (*cmn.ApiKeySummary, error) {
	if mh.UserService == nil {
		return nil, errors.New("user service not initialized")
	}
	return mh.UserService.GetAPIKeyByID(keyID)
}

// NetAPIKeyRevoke - Disable an API key and evict it from cache.
func (na *NetAPIStruct) NetAPIKeyRevoke(keyID string) error {
	if mh.UserService == nil {
		return errors.New("user service not initialized")
	}
	return mh.UserService.RevokeAPIKey(keyID)
}

// NetAPIKeyDelete - Permanently delete an API key and evict it from cache.
func (na *NetAPIStruct) NetAPIKeyDelete(keyID string) error {
	if mh.UserService == nil {
		return errors.New("user service not initialized")
	}
	return mh.UserService.DeleteAPIKey(keyID)
}

// NetAPIKeyPatch - Update allowed_models and/or enabled for an API key.
func (na *NetAPIStruct) NetAPIKeyPatch(keyID string, allowedModels []string, enabled *bool) error {
	if mh.UserService == nil {
		return errors.New("user service not initialized")
	}
	return mh.UserService.PatchAPIKey(keyID, allowedModels, enabled)
}

// NetTenantRateLimitSet - Upsert per-tenant rate limit configuration,
// including any per-model token quotas carried alongside it.
func (na *NetAPIStruct) NetTenantRateLimitSet(tenantID string, rps, tokensPerMin, burstPct int, modelLimits []cmn.TenantModelRateLimit) error {
	if mh.UserService == nil {
		return errors.New("user service not initialized")
	}
	if err := mh.UserService.SetTenantRateLimit(tenantID, rps, tokensPerMin, burstPct); err != nil {
		return err
	}
	for _, ml := range modelLimits {
		if err := mh.UserService.SetTenantModelRateLimit(tenantID, ml.Model, ml.TokensPerMin); err != nil {
			return err
		}
	}
	return nil
}

// NetTenantRateLimitGet - Retrieve the full rate limit entry for a tenant.
func (na *NetAPIStruct) NetTenantRateLimitGet(tenantID string) (*cmn.TenantRateLimitEntry, error) {
	if mh.UserService == nil {
		return nil, errors.New("user service not initialized")
	}
	return mh.UserService.GetTenantRateLimitEntry(tenantID)
}

// NetGetOrAllocBridgeVid - : thin wrapper over the
// package-level bridge VID allocator. Routing the call through the
// cmn.NetHookInterface lets api/loxinlp reach the allocator without
// importing pkg/loxinet (which already imports api/loxinlp -- direct call
// would form an import cycle). See 47-02-SUMMARY.md "Deviations" for the
// Option A design decision. Runs on netlink goroutines; the underlying
// allocator carries its own sync.Mutex -- no mh.mtx acquisition needed.
func (*NetAPIStruct) NetGetOrAllocBridgeVid(name string) (int, error) {
	return GetOrAllocBridgeVid(name)
}

// NetLookupBridgeVid - : thin wrapper for DEL paths.
// Lookup-only; MUST NOT allocate. Returns (vid, true) if a VID has already
// been assigned for the bridge name, else (0, false) so callers treat the
// DELETE as a no-op for never-seen bridges.
func (*NetAPIStruct) NetLookupBridgeVid(name string) (int, bool) {
	return LookupBridgeVid(name)
}

// NetReleaseBridgeVid - : thin wrapper for DelLink path.
// Called by api/loxinlp after a successful NetVlanDel on the bridge itself
// to return the slot to the pool. Prevents allocator-slot leakage during
// bridge rename churn.
func (*NetAPIStruct) NetReleaseBridgeVid(name string) error {
	return ReleaseBridgeVid(name)
}
