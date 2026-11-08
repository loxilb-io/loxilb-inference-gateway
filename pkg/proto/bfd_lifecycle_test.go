/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 NetLOX Inc.
 */
package bfd

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockedBFDNotify struct {
	entered, release       chan struct{}
	enterOnce, releaseOnce sync.Once
}

func newBlockedBFDNotify() *blockedBFDNotify {
	return &blockedBFDNotify{entered: make(chan struct{}), release: make(chan struct{})}
}
func (n *blockedBFDNotify) BFDSessionNotify(string, string, string) {
	n.enterOnce.Do(func() { close(n.entered) })
	<-n.release
}
func (n *blockedBFDNotify) unblock() { n.releaseOnce.Do(func() { close(n.release) }) }

type discardBFDNotify struct{}

func (discardBFDNotify) BFDSessionNotify(string, string, string) {}

type lifecycleFixture struct {
	bs   *Struct
	args ConfigArgs
	peer net.PacketConn
	sess *bfdSession
	gate chan struct{}
}

func newLifecycleFixture(t *testing.T, n Notifer) lifecycleFixture {
	t.Helper()
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	gate := make(chan struct{})
	bs := &Struct{BFDSessMap: make(map[string]*bfdSession)}
	args := ConfigArgs{RemoteIP: "127.0.0.1", SourceIP: "127.0.0.1", Port: uint16(peer.LocalAddr().(*net.UDPAddr).Port), Interval: BFDMinSysTXIntervalUs, Multi: 3, Instance: "lifecycle", StartGate: gate}
	if err := bs.BFDAddRemote(args, n); err != nil {
		t.Fatal(err)
	}
	return lifecycleFixture{bs, args, peer, bs.BFDSessMap[args.RemoteIP], gate}
}
func blockTickerNotification(t *testing.T, f lifecycleFixture, n *blockedBFDNotify) {
	t.Helper()
	f.sess.Mutex.Lock()
	f.sess.State = BFDUp
	f.sess.RemDisc = 1
	f.sess.LastRxTS = time.Now().Add(-time.Second)
	f.sess.TimeOut = 1
	f.sess.Mutex.Unlock()
	close(f.gate)
	select {
	case <-n.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("ticker did not enter notification")
	}
}

func TestBFDDeleteReleasesTableBeforeJoin(t *testing.T) {
	n := newBlockedBFDNotify()
	f := newLifecycleFixture(t, n)
	defer func() { n.unblock(); f.bs.BFDDeleteRemote(f.args) }()
	blockTickerNotification(t, f, n)
	done := make(chan error, 1)
	go func() { done <- f.bs.BFDDeleteRemote(f.args) }()
	// Leave the delete running while its callback is deliberately held.
	time.Sleep(20 * time.Millisecond)
	read := make(chan error, 1)
	go func() { _, err := f.bs.BFDGet(); read <- err }()
	select {
	case err := <-read:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(150 * time.Millisecond):
		t.Error("session join held the BFD table lock")
	}
	n.unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("delete did not join after callback returned")
	}
}

func TestBFDDeleteBoundsBlockedCallbackAndAllowsRetry(t *testing.T) {
	n := newBlockedBFDNotify()
	f := newLifecycleFixture(t, n)
	defer func() { n.unblock(); f.bs.BFDDeleteRemote(f.args) }()
	blockTickerNotification(t, f, n)
	done := make(chan error, 1)
	go func() { done <- f.bs.BFDDeleteRemote(f.args) }()
	timedOut := false
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Errorf("blocked callback reported successful deletion: %v", err)
		}
		rows, getErr := f.bs.BFDGet()
		if getErr != nil || len(rows) != 1 {
			t.Errorf("unjoined session disappeared: rows=%v err=%v", rows, getErr)
		}
		if err := f.bs.BFDAddRemote(f.args, n); err == nil {
			t.Error("reused a session while its old callback was still active")
		}
	case <-time.After(2 * time.Second):
		timedOut = true
		t.Error("delete has no bounded stop/join deadline")
	}
	n.unblock()
	if timedOut {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("old delete did not finish after release")
		}
		return
	}
	if err := f.bs.BFDDeleteRemote(f.args); err != nil {
		t.Fatalf("retry did not finish the joined deletion: %v", err)
	}
}

func TestBFDDeleteSendsAdminDownAndClosesConnection(t *testing.T) {
	f := newLifecycleFixture(t, discardBFDNotify{})
	defer f.bs.BFDDeleteRemote(f.args)
	close(f.gate)
	buffer := make([]byte, 64)
	f.peer.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := f.peer.ReadFrom(buffer); err != nil || n != 24 {
		t.Fatalf("initial packet: n=%d err=%v", n, err)
	}
	if err := f.bs.BFDDeleteRemote(f.args); err != nil {
		t.Fatal(err)
	}
	f.peer.SetReadDeadline(time.Now().Add(time.Second))
	seen := false
	for !seen {
		n, _, err := f.peer.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("AdminDown packet missing: %v", err)
		}
		seen = n == 24 && decodeCtrlPacket(buffer, n).State == BFDAdminDown
	}
	f.peer.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if _, _, err := f.peer.ReadFrom(buffer); err == nil {
		t.Error("old worker sent a packet after final AdminDown")
	}
	if _, err := f.sess.Cxn.Write([]byte{1}); err == nil {
		t.Error("delete left the UDP connection open")
	}
	if err := f.bs.BFDAddRemote(f.args, discardBFDNotify{}); err != nil {
		t.Fatalf("re-add after delete: %v", err)
	}
}

func TestBFDConcurrentUpdateAndPacketSnapshot(t *testing.T) {
	f := newLifecycleFixture(t, discardBFDNotify{})
	defer f.bs.BFDDeleteRemote(f.args)
	close(f.gate)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1500; i++ {
			f.sess.checkSessTimeout()
			f.sess.encodeCtrlPacket()
		}
	}()
	for i := 0; i < 100; i++ {
		args := f.args
		args.Interval += uint32(i%5) * 1000
		args.Multi = uint8(1 + i%3)
		if err := f.bs.BFDAddRemote(args, discardBFDNotify{}); err != nil {
			t.Error(err)
			break
		}
		if _, err := f.bs.BFDGet(); err != nil {
			t.Error(err)
		}
	}
	wg.Wait()
}

func TestBFDUpdateRetainsPendingStartGate(t *testing.T) {
	f := newLifecycleFixture(t, discardBFDNotify{})
	defer f.bs.BFDDeleteRemote(f.args)
	args := f.args
	args.Interval += 50000
	args.Multi = 7
	if err := f.bs.BFDAddRemote(args, discardBFDNotify{}); err != nil {
		t.Fatal(err)
	}
	rows, err := f.bs.BFDGet()
	if err != nil || len(rows) != 1 || rows[0].Interval != uint64(args.Interval) || rows[0].RetryCount != 7 {
		t.Fatalf("updated pending config: %v %v", rows, err)
	}
	buffer := make([]byte, 64)
	f.peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, err := f.peer.ReadFrom(buffer); err == nil {
		t.Error("update bypassed the initial HA traffic gate")
	}
	close(f.gate)
	f.peer.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := f.peer.ReadFrom(buffer)
	if err != nil || n != 24 {
		t.Fatalf("updated session did not start: %d %v", n, err)
	}
	packet := decodeCtrlPacket(buffer, n)
	if packet.Multi != 7 || packet.DesMinTxInt != args.Interval {
		t.Fatalf("wrong updated wire state: %+v", packet)
	}
}

func TestBFDUpdateBoundsCallbackWaitWithoutHoldingTable(t *testing.T) {
	n := newBlockedBFDNotify()
	f := newLifecycleFixture(t, n)
	defer func() { n.unblock(); f.bs.BFDDeleteRemote(f.args) }()
	blockTickerNotification(t, f, n)
	if err := f.bs.BFDAddRemote(f.args, n); err != nil {
		t.Fatalf("idempotent config waited on a notifier: %v", err)
	}
	args := f.args
	args.Interval += 1000
	done := make(chan error, 1)
	go func() { done <- f.bs.BFDAddRemote(args, n) }()
	time.Sleep(20 * time.Millisecond)
	read := make(chan error, 1)
	go func() { _, err := f.bs.BFDGet(); read <- err }()
	select {
	case err := <-read:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(150 * time.Millisecond):
		t.Error("update held the table while waiting for a callback")
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Errorf("blocked update returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("update has no bounded callback wait")
		n.unblock()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("update did not finish after release")
		}
	}
	n.unblock()
}

func TestBFDDeleteJoinsReceiveCallback(t *testing.T) {
	n := newBlockedBFDNotify()
	f := newLifecycleFixture(t, n)
	defer func() { n.unblock(); f.bs.BFDDeleteRemote(f.args) }()
	close(f.gate)
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		f.sess.RunSessionSM(&WireRaw{State: BFDInit, Multi: 3, Disc: 1, DesMinTxInt: BFDMinSysTXIntervalUs})
	}()
	select {
	case <-n.entered:
	case <-time.After(time.Second):
		t.Fatal("receive state machine did not notify")
	}
	done := make(chan error, 1)
	go func() { done <- f.bs.BFDDeleteRemote(f.args) }()
	returned := false
	select {
	case err := <-done:
		returned = true
		t.Errorf("delete returned with receive callback live: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	n.unblock()
	if !returned {
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("delete did not join receive callback")
		}
	}
	select {
	case <-inputDone:
	case <-time.After(time.Second):
		t.Fatal("receive callback survived deletion")
	}
}

func TestBFDConcurrentUpdateDeleteAndReadd(t *testing.T) {
	f := newLifecycleFixture(t, discardBFDNotify{})
	close(f.gate)
	defer f.bs.BFDDeleteRemote(f.args)
	var wg sync.WaitGroup
	var observed sync.Map
	for worker := 0; worker < 3; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				switch worker {
				case 0:
					args := f.args
					args.Interval += uint32(i%5) * 1000
					if err := f.bs.BFDAddRemote(args, discardBFDNotify{}); err != nil && !strings.Contains(err.Error(), "stopping") {
						t.Error(err)
					}
				case 1:
					if err := f.bs.BFDDeleteRemote(f.args); err != nil && !strings.Contains(err.Error(), "no bfd session") {
						t.Error(err)
					}
				case 2:
					if _, err := f.bs.BFDGet(); err != nil {
						t.Error(err)
					}
				}
				f.bs.BFDMtx.RLock()
				s := f.bs.BFDSessMap[f.args.RemoteIP]
				f.bs.BFDMtx.RUnlock()
				if s != nil {
					observed.Store(s, true)
					if worker == 2 {
						s.RunSessionSM(&WireRaw{State: BFDDown, Multi: 3, Disc: 1, DesMinTxInt: BFDMinSysTXIntervalUs})
					}
				}
			}
		}(worker)
	}
	wg.Wait()
	if err := f.bs.BFDDeleteRemote(f.args); err != nil && !strings.Contains(err.Error(), "no bfd session") {
		t.Fatal(err)
	}
	rows, err := f.bs.BFDGet()
	if err != nil || len(rows) != 0 {
		t.Fatalf("final registry: %v %v", rows, err)
	}
	observed.Range(func(key, value any) bool {
		s := key.(*bfdSession)
		if _, err := s.Cxn.Write([]byte{1}); err == nil {
			t.Error("an old session connection survived final deletion")
		}
		return true
	})
	if err := f.bs.BFDAddRemote(f.args, discardBFDNotify{}); err != nil {
		t.Fatalf("fresh re-add: %v", err)
	}
}
