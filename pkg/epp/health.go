/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package epp

import (
	"time"

	tk "github.com/loxilb-io/loxilib"
	"google.golang.org/grpc/connectivity"
)

// Health is what the gateway knows about one EPP address: the state of its
// gRPC connection, sampled every HealthProbeInterval whether or not requests
// flow, and the last request-phase outcome seen on it.
type Health struct {
	// State is "up" (the connection is ready), "connecting" (dialing or
	// idle, not yet proven), "down" (the dial fails and gRPC is backing
	// off) or "unknown" (no connection has been attempted yet).
	State string
	// Since is when State last changed.
	Since time.Time
	// LastError is the last request-phase error on this connection ("" when
	// none since the connection came up); LastErrorAt is when it happened.
	LastError   string
	LastErrorAt time.Time
	// LastOKAt is when the EPP last answered a request on this connection.
	LastOKAt time.Time
}

const (
	HealthUp         = "up"
	HealthConnecting = "connecting"
	HealthDown       = "down"
	HealthUnknown    = "unknown"
)

// HealthProbeInterval is how often every cached connection is re-dialed if
// it dropped and its state re-sampled, so an idle EPP that dies is noticed
// without a request. A variable so tests can shorten it.
var HealthProbeInterval = 5 * time.Second

func healthState(s connectivity.State) string {
	switch s {
	case connectivity.Ready:
		return HealthUp
	case connectivity.TransientFailure, connectivity.Shutdown:
		return HealthDown
	default: // Idle, Connecting
		return HealthConnecting
	}
}

// sample asks gRPC to (re)connect if it is idle and records the state.
func (e *connEntry) sample(key string) {
	e.cc.Connect()
	st := healthState(e.cc.GetState())
	e.hmu.Lock()
	prev := e.state
	if st != prev {
		e.state = st
		e.since = time.Now()
		if st == HealthUp {
			e.lastErr = ""
		}
	}
	e.hmu.Unlock()
	if st != prev && prev != "" {
		tk.LogIt(tk.LogInfo, "[EPP] %s: connection %s -> %s\n", key, prev, st)
	}
}

func (e *connEntry) noteOK() {
	e.hmu.Lock()
	e.lastOKAt = time.Now()
	e.hmu.Unlock()
}

func (e *connEntry) noteErr(err error) {
	if err == nil {
		return
	}
	e.hmu.Lock()
	e.lastErr = err.Error()
	e.lastErrAt = time.Now()
	e.hmu.Unlock()
}

func (e *connEntry) health() Health {
	e.hmu.Lock()
	defer e.hmu.Unlock()
	h := Health{State: e.state, Since: e.since, LastError: e.lastErr, LastErrorAt: e.lastErrAt, LastOKAt: e.lastOKAt}
	if h.State == "" {
		h.State = HealthUnknown
	}
	return h
}

// Health reports the connection to the EPP named by cfg. The connection is
// opened if the rule has not sent a request yet, so a freshly created rule
// shows "connecting" and then "up" or "down" within a probe interval.
func (c *Client) Health(cfg RuleCfg) Health {
	e, err := c.conn(cfg)
	if err != nil {
		return Health{State: HealthDown, LastError: err.Error(), LastErrorAt: time.Now()}
	}
	e.sample(connKey(cfg))
	return e.health()
}

// probeLoop samples every cached connection until Close.
func (c *Client) probeLoop() {
	t := time.NewTicker(HealthProbeInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			c.mu.Lock()
			snapshot := make(map[string]*connEntry, len(c.conns))
			for k, e := range c.conns {
				snapshot[k] = e
			}
			c.mu.Unlock()
			for k, e := range snapshot {
				e.sample(k)
			}
		}
	}
}
