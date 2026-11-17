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
	cmn "github.com/loxilb-io/loxilb/common"
	bfd "github.com/loxilb-io/loxilb/pkg/proto"
	"net"
	"testing"
)

func TestBFDListIdleAndUnavailable(t *testing.T) {
	var absent *CIStateH
	for _, ch := range []*CIStateH{absent, {}} {
		if _, err := ch.CIBFDSessionGet(); !errors.Is(err, cmn.ErrBFDUnavailable) {
			t.Fatalf("uninitialized returned %v", err)
		}
	}
	ch := &CIStateH{Bs: bfd.StructNew(0)}
	rows, err := ch.CIBFDSessionGet()
	if err != nil || len(rows) != 0 || ch.SpawnKa {
		t.Fatalf("idle read must be empty and not start BFD: %+v %v", rows, err)
	}
	previous := mh.has
	mh.has = ch
	t.Cleanup(func() { mh.has = previous })
	rows, err = (&NetAPIStruct{}).NetBFDGet()
	if err != nil || len(rows) != 0 {
		t.Fatalf("API hook idle read: %+v %v", rows, err)
	}
	mh.has = nil
	if _, err = (&NetAPIStruct{}).NetBFDGet(); !errors.Is(err, cmn.ErrBFDUnavailable) {
		t.Fatalf("missing subsystem: %v", err)
	}
}

func TestBFDListAndDeletePreserveRemainingSessions(t *testing.T) {
	ch := &CIStateH{Bs: bfd.StructNew(0), ClusterMap: map[string]*ClusterInstance{cmn.CIDefault: {}}}
	// Gate protocol traffic and callbacks: this tests configured session state,
	// not HA transitions or a real peer. Deletion also releases gated tickers.
	gate := make(chan struct{})
	owned := map[string]bool{}
	for _, remote := range []string{"127.0.0.2", "127.0.0.3"} {
		err := ch.Bs.BFDAddRemote(bfd.ConfigArgs{RemoteIP: remote, SourceIP: "127.0.0.1", Port: 3784, Interval: 1000000, Multi: 5, Instance: cmn.CIDefault, StartGate: gate}, ch)
		if err != nil {
			t.Fatal(err)
		}
		owned[remote] = true
		t.Cleanup(func() {
			if owned[remote] {
				if err := ch.Bs.BFDDeleteRemote(bfd.ConfigArgs{RemoteIP: remote}); err != nil {
					t.Errorf("join BFD fixture %s: %v", remote, err)
				}
			}
		})
	}
	// Even a stale lifecycle hint must not hide the authoritative table.
	rows, err := ch.CIBFDSessionGet()
	if err != nil || len(rows) != 2 {
		t.Fatalf("table hidden: %+v %v", rows, err)
	}
	ch.SpawnKa = true
	if _, err = ch.CIBFDSessionDel(cmn.BFDMod{Instance: cmn.CIDefault, RemoteIP: net.ParseIP("127.0.0.2")}); err != nil {
		t.Fatal(err)
	}
	owned["127.0.0.2"] = false
	rows, err = ch.CIBFDSessionGet()
	if err != nil || len(rows) != 1 || !ch.SpawnKa {
		t.Fatalf("remaining session hidden/stopped: %+v %v %v", rows, err, ch.SpawnKa)
	}
	if _, err = ch.CIBFDSessionDel(cmn.BFDMod{Instance: cmn.CIDefault, RemoteIP: net.ParseIP("127.0.0.3")}); err != nil {
		t.Fatal(err)
	}
	owned["127.0.0.3"] = false
	rows, err = ch.CIBFDSessionGet()
	if err != nil || len(rows) != 0 || ch.SpawnKa {
		t.Fatalf("last deletion is not an empty list: %+v %v", rows, err)
	}
}

func TestBFDBgpOnlyRefusalIsTyped(t *testing.T) {
	api := &NetAPIStruct{BgpPeerMode: true}
	_, getErr := api.NetBFDGet()
	_, addErr := api.NetBFDAdd(&cmn.BFDMod{})
	_, delErr := api.NetBFDDel(&cmn.BFDMod{})
	for _, err := range []error{getErr, addErr, delErr} {
		if !errors.Is(err, cmn.ErrBFDUnsupported) {
			t.Fatalf("unsupported mode: %v", err)
		}
	}
}
