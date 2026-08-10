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
	"net"
	"strconv"
	"strings"

	tk "github.com/loxilb-io/loxilib"

	cmn "github.com/loxilb-io/loxilb/common"
)

// error codes
const (
	PolErrBase = iota - 100000
	PolModErr
	PolInfoErr
	PolAttachErr
	PolNoExistErr
	PolExistsErr
	PolAllocErr
)

// constants
const (
	MinPolRate  = 8
	MaxPols     = 8 * 1024
	DflPolBlkSz = 6 * 5000 * 1000
)

// PolKey - key for a policer entry
type PolKey struct {
	PolName string
}

// PolStats - stats related to policer
type PolStats struct {
	PacketsOk  uint64
	PacketsNok uint64
	Bytes      uint64
}

// PolAttachObjT - empty interface to hold policer attachments
type PolAttachObjT interface {
}

// PolObjInfo - an object which is attached to a policer
type PolObjInfo struct {
	Args      cmn.PolObj
	AttachObj PolAttachObjT
	Parent    *PolEntry
	Sync      DpStatusT
}

// PolEntry - a policer entry
type PolEntry struct {
	Key   PolKey
	Info  cmn.PolInfo
	Zone  *Zone
	HwNum uint64
	Stats PolStats
	Sync  DpStatusT
	PObjs []PolObjInfo
}

// PolH - context container
type PolH struct {
	PolMap map[PolKey]*PolEntry
	Zone   *Zone
	Mark   *tk.Counter
}

// PolInit - initialize the policer subsystem
func PolInit(zone *Zone) *PolH {
	var nPh = new(PolH)
	nPh.PolMap = make(map[PolKey]*PolEntry)
	nPh.Zone = zone
	nPh.Mark = tk.NewCounter(1, MaxPols)
	return nPh
}

// PolInfoXlateValidate - validates info passed in pInfo and
// translates it to internally used units
func PolInfoXlateValidate(pInfo *cmn.PolInfo) bool {
	if pInfo.CommittedInfoRate < MinPolRate {
		return false
	}

	// PeakInfoRate=0 is valid for srTCM (single-rate, RFC2697) where only CIR is used
	if pInfo.PeakInfoRate != 0 && pInfo.PeakInfoRate < MinPolRate {
		return false
	}

	pInfo.CommittedInfoRate = pInfo.CommittedInfoRate * 1000000
	pInfo.PeakInfoRate = pInfo.PeakInfoRate * 1000000

	if pInfo.CommittedBlkSize == 0 {
		pInfo.CommittedBlkSize = DflPolBlkSz
		pInfo.ExcessBlkSize = 2 * DflPolBlkSz
	} else {
		pInfo.ExcessBlkSize = 2 * pInfo.CommittedBlkSize
	}
	return true
}

// PolObjValidate - validate object to be attached
func PolObjValidate(pObj *cmn.PolObj) bool {

	if pObj.AttachMent != cmn.PolAttachPort && pObj.AttachMent != cmn.PolAttachLbRule {
		return false
	}

	return true
}

// PolGetAll - Get all of the policer in loxinet
func (P *PolH) PolGetAll() ([]cmn.PolMod, error) {
	var getPols []cmn.PolMod
	for pk, pe := range P.PolMap {
		var pol cmn.PolMod
		// Policy name getting
		pol.Ident = pk.PolName

		// Policy Info getting
		pol.Info.ColorAware = pe.Info.ColorAware
		pol.Info.PeakInfoRate = pe.Info.PeakInfoRate / 1000000
		pol.Info.CommittedInfoRate = pe.Info.CommittedInfoRate / 1000000
		pol.Info.CommittedBlkSize = pe.Info.CommittedBlkSize
		pol.Info.ExcessBlkSize = pe.Info.ExcessBlkSize
		pol.Info.PolType = pe.Info.PolType

		// Policy Target
		for _, target := range pe.PObjs {
			pol.Target = target.Args
		}

		// Append Policy
		getPols = append(getPols, pol)
	}
	return getPols, nil
}

// PolAdd - Add a policer in loxinet
func (P *PolH) PolAdd(pName string, pInfo cmn.PolInfo, pObjArgs cmn.PolObj) (int, error) {

	if PolObjValidate(&pObjArgs) == false {
		tk.LogIt(tk.LogError, "policer add - %s: bad attach point\n", pName)
		return PolAttachErr, errors.New("pol-attachpoint error")
	}

	if PolInfoXlateValidate(&pInfo) == false {
		tk.LogIt(tk.LogError, "policer add - %s: info error\n", pName)
		return PolInfoErr, errors.New("pol-info error")
	}

	key := PolKey{pName}
	p, found := P.PolMap[key]

	if found == true {
		if p.Info != pInfo {
			P.PolDelete(pName)
		} else {
			return PolExistsErr, errors.New("pol-exists error")
		}
	}

	p = new(PolEntry)
	p.Key.PolName = pName
	p.Info = pInfo
	p.Zone = P.Zone
	p.HwNum, _ = P.Mark.GetCounter()
	if p.HwNum < 0 {
		return PolAllocErr, errors.New("pol-alloc error")
	}

	pObjInfo := PolObjInfo{Args: pObjArgs}
	pObjInfo.Parent = p

	// Append PObjs BEFORE DP call so DP can resolve TargetLBMark from attachments
	p.PObjs = append(p.PObjs, pObjInfo)

	P.PolMap[key] = p

	p.DP(DpCreate)
	pObjInfo.PolObj2DP(DpCreate)

	tk.LogIt(tk.LogInfo, "policer added - %s\n", pName)

	return 0, nil
}

// PolAssociateLbRule - : associate a PRE-EXISTING policer ident to a VIP
// LB rule, reusing policer↔LB-rule association mechanism. lbKey is the
// "VIP:PORT:PROTO" key that GetLBRuleMarkByKey resolves to the rule mark. loxilb only
// associates an EXISTING ident — an unresolvable ident surfaces PolNoExistErr (no
// silent-drop); the external Octavia driver owns creating the
// policy via /config/policy. The association is idempotent: re-associating the same
// ident→rule is a no-op (the LB-rule attachment is set, not appended twice).
func (P *PolH) PolAssociateLbRule(ident string, lbKey string) (int, error) {
	if ident == "" {
		// Empty ⇒ caller must not associate; treat as a no-op success so an absent
		// vip_qos_policy_id round-trips byte-identical. Defensive — the
		// LB-create caller already guards on a non-empty ident.
		return 0, nil
	}

	key := PolKey{ident}
	p, found := P.PolMap[key]
	if found == false {
		tk.LogIt(tk.LogError, "policer associate - %s: no such policer (vip_qos_policy_id)\n", ident)
		return PolNoExistErr, errors.New("no such policer error")
	}

	// Idempotent: if this LB-rule attachment already exists on the policer, do nothing.
	for idx := range p.PObjs {
		pObj := &p.PObjs[idx]
		if pObj.Args.AttachMent == cmn.PolAttachLbRule && pObj.Args.PolObjName == lbKey {
			return 0, nil
		}
	}

	pObjArgs := cmn.PolObj{PolObjName: lbKey, AttachMent: cmn.PolAttachLbRule}
	if PolObjValidate(&pObjArgs) == false {
		return PolAttachErr, errors.New("pol-attachpoint error")
	}

	pObjInfo := PolObjInfo{Args: pObjArgs}
	pObjInfo.Parent = p
	// Append BEFORE the DP call so p.DP resolves TargetLBMark via GetLBRuleMarkByKey.
	p.PObjs = append(p.PObjs, pObjInfo)

	p.DP(DpCreate)
	pObjInfo.PolObj2DP(DpCreate)

	tk.LogIt(tk.LogInfo, "policer %s associated to lb-rule %s (vip_qos_policy_id)\n", ident, lbKey)

	return 0, nil
}

// PolDelete - Delete a policer from loxinet
func (P *PolH) PolDelete(pName string) (int, error) {

	key := PolKey{pName}
	p, found := P.PolMap[key]

	if found == false {
		tk.LogIt(tk.LogError, "policer delete - %s: not found error\n", pName)
		return PolNoExistErr, errors.New("no such policer error")
	}

	for idx, pObj := range p.PObjs {
		pP := &p.PObjs[idx]
		pObj.PolObj2DP(DpRemove)
		pP.Parent = nil
	}

	p.DP(DpRemove)

	delete(P.PolMap, p.Key)
	defer P.Mark.PutCounter(p.HwNum)

	tk.LogIt(tk.LogInfo, "policer deleted - %s\n", pName)

	return 0, nil
}

// PolPortDelete - if port related to any policer is deleted,
// we need to make sure that policer is resynced
func (P *PolH) PolPortDelete(name string) {
	for _, p := range P.PolMap {
		for idx, pObj := range p.PObjs {
			var pP *PolObjInfo
			if pObj.Args.AttachMent == cmn.PolAttachPort &&
				pObj.Args.PolObjName == name {
				pP = &p.PObjs[idx]
				pP.Sync = 1
			}
		}
	}
}

// PolDestructAll - destroy all policers
func (P *PolH) PolDestructAll() {
	for _, p := range P.PolMap {
		P.PolDelete(p.Key.PolName)
	}
}

// PolTicker - a ticker routine for policers
func (P *PolH) PolTicker() {
	for _, p := range P.PolMap {
		if p.Sync != 0 {
			p.DP(DpCreate)
			for _, pObj := range p.PObjs {
				pObj.PolObj2DP(DpCreate)
			}
		} else {
			p.DP(DpStatsGet)
			for idx, pObj := range p.PObjs {
				var pP *PolObjInfo
				pP = &p.PObjs[idx]
				if pP.Sync != 0 {
					pP.PolObj2DP(DpCreate)
				} else {
					if pObj.Args.AttachMent == cmn.PolAttachPort {
						port := pObj.Parent.Zone.Ports.PortFindByName(pObj.Args.PolObjName)
						if port == nil {
							pP.Sync = 1
						}
					}
				}
			}
		}
	}

	// collect DOCA meter stats when MeterOffload is active
	P.polTickerDocaMeterStats()
}

// polTickerDocaMeterStats queries DOCA shared meter stats for active meters.
// All CGO calls go through DocaBridge.submit (never direct C calls from PolTicker goroutine).
// P49-R2/R3: also drives the per-pipe HW counter collector and the
// kernel-bridge byte sampler — both piggyback the existing 10s PolTicker tick
// rather than spawning new goroutines (same pattern as dpu_metrics.go).
func (P *PolH) polTickerDocaMeterStats() {
	if mh.dpuMgr == nil {
		return
	}
	mh.dpuMgr.CollectMeterStats()
	mh.dpuMgr.CollectHwOffloadStats()
	SampleKernelBridgeBytes()
}

// PolObj2DP - Sync state of policer's attachment point with data-path
func (pObjInfo *PolObjInfo) PolObj2DP(work DpWorkT) int {

	// LB rule attachment: handled via TargetLBMark in DP → ShadowPolAdd path
	if pObjInfo.Args.AttachMent == cmn.PolAttachLbRule {
		pObjInfo.Sync = 0
		return 0
	}

	if pObjInfo.Args.AttachMent != cmn.PolAttachPort {
		return -1
	}

	port := pObjInfo.Parent.Zone.Ports.PortFindByName(pObjInfo.Args.PolObjName)
	if port == nil {
		pObjInfo.Sync = 1
		return -1
	}

	if work == DpCreate {
		_, err := pObjInfo.Parent.Zone.Ports.PortUpdateProp(port.Name, cmn.PortPropPol,
			pObjInfo.Parent.Zone.Name, true, int(pObjInfo.Parent.HwNum))
		if err != nil {
			pObjInfo.Sync = 1
			return -1
		}
	} else if work == DpRemove {
		pObjInfo.Parent.Zone.Ports.PortUpdateProp(port.Name, cmn.PortPropPol,
			pObjInfo.Parent.Zone.Name, false, 0)
	}

	pObjInfo.Sync = 0

	return 0
}

// DP - Sync state of policer with data-path
func (p *PolEntry) DP(work DpWorkT) int {

	if work == DpStatsGet {
		nStat := new(StatDpWorkQ)
		nStat.Work = work
		nStat.Mark = uint32(p.HwNum)
		nStat.Name = MapNameIpol
		nStat.Packets = &p.Stats.PacketsOk
		nStat.DropPackets = &p.Stats.PacketsNok
		nStat.Bytes = &p.Stats.Bytes

		mh.dp.ToDpCh <- nStat
		return 0
	}

	pwq := new(PolDpWorkQ)
	pwq.Work = work
	pwq.Mark = int(p.HwNum)
	pwq.Color = p.Info.ColorAware
	pwq.Cir = p.Info.CommittedInfoRate
	pwq.Pir = p.Info.PeakInfoRate
	pwq.Cbs = p.Info.CommittedBlkSize
	pwq.Ebs = p.Info.ExcessBlkSize
	pwq.Status = &p.Sync
	pwq.Name = p.Key.PolName

	// resolve LB rule mark + VIP match info for DOCA meter pipe
	for _, pObj := range p.PObjs {
		if pObj.Args.AttachMent == cmn.PolAttachLbRule && pObj.Args.PolObjName != "" {
			if mark := p.Zone.Rules.GetLBRuleMarkByKey(pObj.Args.PolObjName); mark > 0 {
				pwq.TargetLBMark = mark
			}
			// Parse "VIP:PORT:PROTO" for meter pipe match fields
			parts := strings.SplitN(pObj.Args.PolObjName, ":", 3)
			if len(parts) >= 1 {
				ip := net.ParseIP(parts[0])
				if ip != nil {
					pwq.MeterDstIP = tk.IPtonl(ip)
				}
			}
			if len(parts) >= 2 {
				if p, err := strconv.ParseUint(parts[1], 10, 16); err == nil {
					pwq.MeterDstPort = tk.Htons(uint16(p))
				}
			}
			if len(parts) >= 3 {
				switch parts[2] {
				case "tcp":
					pwq.MeterProto = 6
				case "udp":
					pwq.MeterProto = 17
				}
			}
			break
		}
	}

	mh.dp.ToDpCh <- pwq

	return 0
}
