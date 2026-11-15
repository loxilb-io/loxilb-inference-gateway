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
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	bfd "github.com/loxilb-io/loxilb/pkg/proto"
)

// waitForBlockedIn polls the goroutine stacks until one of them shows fn.
func waitForBlockedIn(t *testing.T, fn string, limit time.Duration) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if strings.Contains(string(buf[:runtime.Stack(buf, true)]), fn) {
			return
		}
	}
	t.Fatalf("no goroutine reached %s", fn)
}

// The BFD receive path holds the BFD table lock while it notifies the
// cluster, and the notification takes mh.mtx. A session add that holds
// mh.mtx while it waits for the table therefore deadlocks with it.
// It swaps the global mh.has, so it must not run with t.Parallel.
func TestBFDAddDoesNotHoldGlobalMutexAcrossTable(t *testing.T) {
	ch := &CIStateH{
		Bs:         bfd.StructNew(0),
		ClusterMap: map[string]*ClusterInstance{cmn.CIDefault: {StateStr: cmn.CIMasterStateString}},
		StateMap:   map[string]int{cmn.CIMasterStateString: cmn.CIStateMaster},
	}
	previous := mh.has
	mh.has = ch
	t.Cleanup(func() { mh.has = previous })

	// Stand in for processBFD: hold the table lock as it does.
	ch.Bs.BFDMtx.Lock()
	tableHeld := true
	release := func() {
		if tableHeld {
			tableHeld = false
			ch.Bs.BFDMtx.Unlock()
		}
	}
	defer release()

	item := cmn.BFDMod{Instance: cmn.CIDefault, RemoteIP: net.ParseIP("127.0.0.2"),
		SourceIP: net.ParseIP("127.0.0.1"), Interval: 1000000, RetryCount: 5}
	added := make(chan error, 1)
	joined, deleted := false, false
	var addResult error
	t.Cleanup(func() {
		release()
		if !joined {
			select {
			case addResult = <-added:
				joined = true
			case <-time.After(5 * time.Second):
				t.Error("BFD add worker did not join")
				return
			}
		}
		if addResult == nil && !deleted {
			if err := ch.Bs.BFDDeleteRemote(bfd.ConfigArgs{RemoteIP: item.RemoteIP.String()}); err != nil {
				t.Errorf("join BFD lock-order fixture: %v", err)
			}
		}
	})
	go func() {
		_, err := (&NetAPIStruct{}).NetBFDAdd(&item)
		added <- err
	}()
	waitForBlockedIn(t, "proto.(*Struct).BFDAddRemote", 5*time.Second)

	// The notification the receive path sends while holding the table.
	// Same state as the instance has, so it stops at the state compare.
	notified := make(chan struct{})
	go func() {
		ch.BFDSessionNotify(cmn.CIDefault, "127.0.0.2:3784", cmn.CIMasterStateString)
		close(notified)
	}()
	select {
	case <-notified:
	case <-time.After(5 * time.Second):
		release()
		<-notified
		t.Fatal("BFD notification blocked on mh.mtx held by a session add waiting for the BFD table")
	}

	release()
	addResult = <-added
	joined = true
	if addResult != nil {
		t.Fatal(addResult)
	}
	if _, err := (&NetAPIStruct{}).NetBFDDel(&item); err != nil {
		t.Fatal(err)
	}
	deleted = true
}
