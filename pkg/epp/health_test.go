/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package epp_test

import (
	"net"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/pkg/epp"
	"github.com/loxilb-io/loxilb/pkg/epp/epptest"
)

func waitHealth(t *testing.T, c *epp.Client, cfg epp.RuleCfg, want string) epp.Health {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	var h epp.Health
	for time.Now().Before(deadline) {
		h = c.Health(cfg)
		if h.State == want {
			return h
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("EPP health stayed %q (last error %q), want %q", h.State, h.LastError, want)
	return h
}

// The health view follows the EPP: up while it answers, down once nothing
// listens on its address, up again when it is back - sampled by the probe
// loop, so a rule that sends no requests sees the change too.
func TestClientHealthFollowsTheEPP(t *testing.T) {
	saved := epp.HealthProbeInterval
	epp.HealthProbeInterval = 100 * time.Millisecond
	defer func() { epp.HealthProbeInterval = saved }()

	f := epptest.New("echo")
	addr, stop := epptest.Start(t, f, false)
	c := epp.NewClient()
	defer c.Close()
	cfg := epp.RuleCfg{Endpoint: addr, Plaintext: true, TimeoutMs: 2000}

	h := c.Health(cfg)
	if h.State != epp.HealthConnecting && h.State != epp.HealthUp {
		t.Fatalf("first look: state=%q, want connecting or up", h.State)
	}
	h = waitHealth(t, c, cfg, epp.HealthUp)
	if h.Since.IsZero() {
		t.Fatal("up without a Since timestamp")
	}

	// The EPP goes away; the probe loop notices without any request.
	stop()
	h = waitHealth(t, c, cfg, epp.HealthDown)
	if h.Since.IsZero() {
		t.Fatal("down without a Since timestamp")
	}

	// A request now fails and leaves its reason on the connection.
	dec, _ := c.Submit(t.Context(), cfg, &epp.Request{Method: "POST", Path: "/v1/completions", Body: []byte(`{"model":"m"}`)})
	if dec.Status != epp.StatusError {
		t.Fatalf("submit to a dead EPP: status=%v", dec.Status)
	}
	if h = c.Health(cfg); h.LastError == "" || h.LastErrorAt.IsZero() {
		t.Fatalf("request error not recorded: %+v", h)
	}

	// Back on the same address: up again, last error cleared.
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot rebind %s: %v", addr, err)
	}
	_, stop2 := epptest.StartOn(t, f, l)
	defer stop2()
	h = waitHealth(t, c, cfg, epp.HealthUp)
	if h.LastError != "" {
		t.Fatalf("last error should clear once the EPP is up again: %q", h.LastError)
	}
}

// A rule whose EPP address never answers is reported down, with the reason.
func TestClientHealthUnreachableAddress(t *testing.T) {
	saved := epp.HealthProbeInterval
	epp.HealthProbeInterval = 100 * time.Millisecond
	defer func() { epp.HealthProbeInterval = saved }()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	c := epp.NewClient()
	defer c.Close()
	h := waitHealth(t, c, epp.RuleCfg{Endpoint: addr, Plaintext: true}, epp.HealthDown)
	if h.State != epp.HealthDown {
		t.Fatalf("state=%q", h.State)
	}
}
