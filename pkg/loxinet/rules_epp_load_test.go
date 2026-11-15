/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/epp/epptest"
)

// eppTestRuleSel is eppTestRule with the rule's endpoint selector chosen by
// the caller (CHWBL / WRR_HASH keep bounded-load units; round-robin does not).
func eppTestRuleSel(t *testing.T, port uint16, eppAddr, failureMode string, timeoutMs uint32,
	sel cmn.EpSelect, eps ...cmn.LbEndPointArg) cmn.LbServiceArg {
	t.Helper()
	serv := cmn.LbServiceArg{
		ServIP: eppTestVIP, ServPort: port, Proto: "tcp", Mode: cmn.LBModeFullProxy, Sel: sel,
		EppEndpoint: eppAddr, EppFailureMode: failureMode, EppTimeoutMs: timeoutMs, EppPlaintext: true,
	}
	if _, err := eppTestAddRule(serv, eps); err != nil {
		t.Fatalf("add rule on :%d: %v", port, err)
	}
	t.Cleanup(func() { eppTestDeleteRule(serv) })
	return serv
}

// eppTestHoldingBackend is a backend that signals `hit` when a request
// reaches it and answers only once `release` is closed, so a test can look
// at the data plane while the request is in flight.
func eppTestHoldingBackend(t *testing.T, name string, hit chan<- struct{}, release <-chan struct{}) cmn.LbEndPointArg {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		select {
		case hit <- struct{}{}:
		default:
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"served":"%s"}`, name)
	}))
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(l.Addr().String())
	var p int
	fmt.Sscanf(port, "%d", &p)
	return cmn.LbEndPointArg{EpIP: host, EpPort: uint16(p), Weight: 1}
}

// TestEppPinHoldsChwblLoadUnit: on a CHWBL rule the endpoint the Endpoint
// Picker pins holds exactly one bounded-load unit while its request is in
// flight and none once the connection is torn down. CHWBL charges the unit
// inside its selector and proxy_release_fd_ctx gives it back by ep_num; a
// pinned candidate never went through the selector, so epp_pin has to
// charge it itself (design §7.5 I4) — without that the release takes a
// unit another connection legitimately holds (or logs an underflow at 0)
// and a FailOpen fallback selects on a load lower than the truth.
func TestEppPinHoldsChwblLoadUnit(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	for _, sel := range []struct {
		name string
		sel  cmn.EpSelect
	}{{"chwbl", cmn.LbSelCHWBL}, {"wrr-hash", cmn.LbSelWRRHash}} {
		t.Run(sel.name, func(t *testing.T) {
			hit := make(chan struct{}, 1)
			release := make(chan struct{})
			epA := eppTestHoldingBackend(t, "a", hit, release)
			_, epB, _ := eppTestBackendSeen(t, "b")
			f := epptest.New("echo")
			f.Dest = eppAddr(epA)
			addr, stop := epptest.Start(t, f, false)
			defer stop()
			serv := eppTestRuleSel(t, 28170, addr, cmn.EppFailureModeFailClose, 3000, sel.sel, epA, epB)
			ruleNum := eppTestRuleMark(fmt.Sprintf("%s:%d:%s", serv.ServIP, serv.ServPort, serv.Proto))
			if ruleNum == 0 {
				t.Fatal("rule number not found")
			}
			if got := DpChwblEpLoad(uint32(ruleNum), 0); got != 0 {
				t.Fatalf("before any request: EP0 holds %d units, want 0", got)
			}

			done := make(chan error, 1)
			go func() {
				code, _, err := eppTestRequest(28170, `{"model":"alias","prompt":"hello"}`, 10*time.Second)
				if err == nil && code != 200 {
					err = fmt.Errorf("status %d", code)
				}
				done <- err
			}()
			select {
			case <-hit:
			case err := <-done:
				t.Fatalf("request ended before the backend held it: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("the pinned backend never saw the request")
			}
			// In flight: the pinned endpoint holds one unit, the other none.
			if got := DpChwblEpLoad(uint32(ruleNum), 0); got != 1 {
				t.Errorf("in flight: EP0 (pinned by the EPP) holds %d units, want 1", got)
			}
			if got := DpChwblEpLoad(uint32(ruleNum), 1); got != 0 {
				t.Errorf("in flight: EP1 holds %d units, want 0", got)
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatalf("request: %v", err)
			}
			// Teardown runs on the worker after the client leaves: give it back
			// exactly once.
			deadline := time.Now().Add(3 * time.Second)
			for {
				if got := DpChwblEpLoad(uint32(ruleNum), 0); got == 0 {
					break
				} else if time.Now().After(deadline) {
					t.Fatalf("after teardown: EP0 still holds %d units, want 0", got)
				}
				time.Sleep(20 * time.Millisecond)
			}
			if got := DpChwblEpLoad(uint32(ruleNum), 1); got != 0 {
				t.Errorf("after teardown: EP1 holds %d units, want 0 (a unit was stolen)", got)
			}
		})
	}
}

// TestEppBackendCloseReleasesChwblUnitOnce: a backend that closes its side
// first (a `Connection: close` request, an engine that drops the keep-alive)
// ends its leg before the client's teardown. Both teardowns reach the
// client's load-unit release; the unit must go back exactly once, or the
// second pass takes the unit of another connection in flight on the same
// endpoint and CHWBL's bounded load undercounts it (the cluster report of
// 2026-10-13, item 3, "underflow protection" on the FailOpen fallback).
func TestEppBackendCloseReleasesChwblUnitOnce(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	var mu sync.Mutex
	nreq := 0
	hit := make(chan struct{}, 2)
	release := make(chan struct{})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The first request is held until `release`; every later one is
	// answered at once, and its connection then closes (the client asked
	// for that), so its backend leg ends before its client leg does.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		mu.Lock()
		nreq++
		n := nreq
		mu.Unlock()
		if n == 1 {
			hit <- struct{}{}
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"served":"a","n":%d}`, n)
	}))
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(l.Addr().String())
	var p int
	fmt.Sscanf(port, "%d", &p)
	epA := cmn.LbEndPointArg{EpIP: host, EpPort: uint16(p), Weight: 1}
	_, epB, _ := eppTestBackendSeen(t, "b")
	f := epptest.New("echo")
	f.Dest = eppAddr(epA)
	addr, stop := epptest.Start(t, f, false)
	defer stop()
	serv := eppTestRuleSel(t, 28172, addr, cmn.EppFailureModeFailClose, 3000, cmn.LbSelCHWBL, epA, epB)
	ruleNum := eppTestRuleMark(fmt.Sprintf("%s:%d:%s", serv.ServIP, serv.ServPort, serv.Proto))
	if ruleNum == 0 {
		t.Fatal("rule number not found")
	}

	// Request 1: held in flight on EP0.
	done := make(chan error, 1)
	go func() {
		code, _, err := eppTestRequest(28172, `{"model":"alias","prompt":"held"}`, 10*time.Second)
		if err == nil && code != 200 {
			err = fmt.Errorf("status %d", code)
		}
		done <- err
	}()
	select {
	case <-hit:
	case err := <-done:
		t.Fatalf("request 1 ended before the backend held it: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the backend never saw request 1")
	}
	if got := DpChwblEpLoad(uint32(ruleNum), 0); got != 1 {
		t.Fatalf("request 1 in flight: EP0 holds %d units, want 1", got)
	}
	// Request 2: answered, and its backend leg closed first.
	if code, _, err := eppTestRequest(28172, `{"model":"alias","prompt":"quick"}`, 10*time.Second); err != nil || code != 200 {
		t.Fatalf("request 2: code=%d err=%v", code, err)
	}
	time.Sleep(300 * time.Millisecond) // request 2's two teardowns are done by now
	if got := DpChwblEpLoad(uint32(ruleNum), 0); got != 1 {
		t.Errorf("request 1 still in flight after request 2's backend closed first: EP0 holds %d units, want 1 (request 2's unit was released twice)", got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("request 1: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for DpChwblEpLoad(uint32(ruleNum), 0) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("after both requests: EP0 still holds %d units, want 0", DpChwblEpLoad(uint32(ruleNum), 0))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
