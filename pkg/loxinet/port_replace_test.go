// Copyright (c) 2026 LoxiLB Authors
// SPDX-License-Identifier: Apache-2.0

package loxinet

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestPortSameNameNewIndexIgnoresLateDelete(t *testing.T) {
	oldZones, oldRoot, oldDP := mh.zn, mh.zr, mh.dp
	t.Cleanup(func() { mh.zn, mh.zr, mh.dp = oldZones, oldRoot, oldDP })
	mh.zn = ZoneInit()
	mh.zr = &Zone{Name: RootZone, ZoneNum: 1, Ports: PortInit()}
	mh.zr.L3 = L3Init(mh.zr)
	mh.zr.Rt = RtInit(mh.zr)
	mh.zr.Nh = NeighInit(mh.zr)
	mh.zn.ZoneMap[RootZone] = mh.zr
	mh.dp = &DpH{ToDpCh: make(chan interface{}, 4)}

	const name = "front0"
	const oldIndex, newIndex, portNumber, aliasNumber = 3, 5, 11, 12
	ports := mh.zr.Ports
	port := &Port{
		Name: name, PortNo: portNumber, Zone: RootZone,
		SInfo: PortSwInfo{OsID: oldIndex, PortType: cmn.PortReal, PortActive: true, BpfLoaded: true},
		L2:    PortLayer2Info{IsPvid: true, Vid: RealPortIDB + portNumber},
	}
	ports.portSmap[name] = port
	ports.portOmap[oldIndex] = port
	ports.portImap[portNumber] = port
	alias := &Port{Name: "tmp0", PortNo: aliasNumber, Zone: RootZone, SInfo: port.SInfo, L2: port.L2}
	alias.SInfo.OsID = newIndex
	ports.portSmap[alias.Name], ports.portOmap[newIndex], ports.portImap[aliasNumber] = alias, alias, alias
	api := &NetAPIStruct{}
	if ret, err := api.NetPortAdd(&cmn.PortMod{Dev: name, LinkIndex: newIndex, Ptype: cmn.PortReal, Link: true, State: true}); err != nil || ret != 0 {
		t.Fatalf("replace: %v (%d)", err, ret)
	}
	if ports.PortFindByOSID(oldIndex) != nil || ports.PortFindByOSID(newIndex) != port || port.SInfo.OsID != newIndex || ports.PortFindByName(alias.Name) != nil {
		t.Fatalf("bad replacement mapping: old=%v new=%v osid=%d",
			ports.PortFindByOSID(oldIndex), ports.PortFindByOSID(newIndex), port.SInfo.OsID)
	}
	for _, want := range []struct {
		op     DpWorkT
		index  int
		portNo int
	}{{DpRemove, newIndex, aliasNumber}, {DpRemove, oldIndex, portNumber}, {DpCreate, newIndex, portNumber}} {
		select {
		case item := <-mh.dp.ToDpCh:
			w, ok := item.(*PortDpWorkQ)
			if !ok || w.Work != want.op || w.OsPortNum != want.index || w.PortNum != want.portNo {
				t.Fatalf("unexpected datapath work %+v, want operation %v index %d", item, want.op, want.index)
			}
		default:
			t.Fatal("no datapath operation queued")
		}
	}
	if _, err := api.NetPortDel(&cmn.PortMod{Dev: name, LinkIndex: oldIndex, Ptype: cmn.PortReal}); err != nil {
		t.Fatal(err)
	}
	if ports.PortFindByName(name) != port || ports.PortFindByOSID(newIndex) != port || len(mh.dp.ToDpCh) != 0 {
		t.Fatal("late delete removed or reprogrammed the replacement")
	}
}
