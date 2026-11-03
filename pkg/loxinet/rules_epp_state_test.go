/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"net"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/epp"
	"github.com/loxilb-io/loxilb/pkg/epp/epptest"
)

// eppRuleGet returns the GET view of the rule on port.
func eppRuleGet(t *testing.T, port uint16) cmn.LbServiceArg {
	t.Helper()
	rules, err := mh.zr.Rules.GetLBRule()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Serv.ServIP == eppTestVIP && r.Serv.ServPort == port {
			return r.Serv
		}
	}
	t.Fatalf("rule on :%d not in GET", port)
	return cmn.LbServiceArg{}
}

func waitEppState(t *testing.T, port uint16, want string) cmn.LbServiceArg {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	var s cmn.LbServiceArg
	for time.Now().Before(deadline) {
		s = eppRuleGet(t, port)
		if s.EppState == want {
			return s
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("eppState stayed %q (since %q, lastError %q), want %q", s.EppState, s.EppStateSince, s.EppLastError, want)
	return s
}

// The rule GET carries the gateway's view of its EPP: up while the EPP
// listens, down once it is gone (noticed by the probe, no request needed),
// with the last request error, and up again when it returns. A rule without
// an EPP carries none of the fields.
func TestEppStateOnRuleGet(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	saved := epp.HealthProbeInterval
	epp.HealthProbeInterval = 100 * time.Millisecond
	defer func() { epp.HealthProbeInterval = saved }()
	_, ep, _ := eppTestBackendSeen(t, "a")

	f := epptest.New("echo")
	f.Dest = eppAddr(ep)
	addr, stop := epptest.Start(t, f, false)
	eppTestRule(t, 28300, addr, cmn.EppFailureModeFailOpen, 2000, ep)

	s := waitEppState(t, 28300, epp.HealthUp)
	if _, err := time.Parse(time.RFC3339, s.EppStateSince); err != nil {
		t.Fatalf("eppStateSince %q is not RFC3339: %v", s.EppStateSince, err)
	}
	if s.EppLastError != "" {
		t.Fatalf("fresh EPP with a last error: %q", s.EppLastError)
	}

	stop()
	waitEppState(t, 28300, epp.HealthDown)
	// A request through the rule is still served (FailOpen) and leaves the
	// reason on the GET.
	if code, _, err := eppTestRequest(28300, `{"model":"alias","prompt":"hi"}`, 8*time.Second); err != nil || code != 200 {
		t.Fatalf("FailOpen with the EPP down: code=%d err=%v", code, err)
	}
	if s = eppRuleGet(t, 28300); s.EppLastError == "" {
		t.Fatal("request error against the dead EPP not reported in eppLastError")
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot rebind %s: %v", addr, err)
	}
	_, stop2 := epptest.StartOn(t, f, l)
	defer stop2()
	if s = waitEppState(t, 28300, epp.HealthUp); s.EppLastError != "" {
		t.Fatalf("eppLastError should clear once the EPP is back: %q", s.EppLastError)
	}

	// No EPP, no fields.
	serv := cmn.LbServiceArg{ServIP: eppTestVIP, ServPort: 28302, Proto: "tcp", Mode: cmn.LBModeFullProxy, Sel: cmn.LbSelRr}
	if _, err := mh.zr.Rules.AddLbRule(serv, nil, nil, nil, []cmn.LbEndPointArg{ep}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mh.zr.Rules.DeleteLbRule(serv) })
	if s = eppRuleGet(t, 28302); s.EppState != "" || s.EppStateSince != "" || s.EppLastError != "" {
		t.Fatalf("rule without an EPP reports EPP state: %+v", s)
	}
	eppTestSettled(t)
}
