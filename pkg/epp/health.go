/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package epp

import (
	"context"
	"time"

	tk "github.com/loxilb-io/loxilib"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// Health is what the gateway knows about one EPP address: the state of its
// gRPC connection, sampled every HealthProbeInterval whether or not requests
// flow, and the last request-phase outcome seen on it.
type Health struct {
	// State is "up" (the connection is ready and the EPP answered the last
	// liveness ping), "connecting" (dialing, or idle and not yet proven),
	// "down" (the dial fails, or the EPP stopped answering pings) or
	// "unknown" (no connection has been attempted yet).
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

// HealthProbeTimeout bounds the liveness RPC of one probe.
var HealthProbeTimeout = 2 * time.Second

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

// ping proves the peer is alive with one standard gRPC health Check. An
// EPP that does not serve the health service answers UNIMPLEMENTED, which is
// an answer: the connection carries RPCs. No answer within
// HealthProbeTimeout (a peer that vanished without closing the connection,
// e.g. a force-deleted pod, leaves the socket looking open) is down.
func (e *connEntry) ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), HealthProbeTimeout)
	defer cancel()
	_, err := healthpb.NewHealthClient(e.cc).Check(ctx, &healthpb.HealthCheckRequest{})
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.Unimplemented, codes.NotFound, codes.InvalidArgument, codes.PermissionDenied, codes.Unauthenticated:
		return nil // the peer answered
	}
	return err
}

// probe re-dials an idle connection, samples its state and, when it looks
// up, proves it with a ping. Run by the probe loop, not by Health(), so a
// GET never waits on the EPP.
func (e *connEntry) probe(key string) {
	e.cc.Connect()
	st := healthState(e.cc.GetState())
	var perr error
	if st == HealthUp {
		if perr = e.ping(); perr != nil {
			st = HealthDown
		}
	}
	e.record(key, st, perr)
}

// sample is the cheap part of a probe (no RPC), used by Health() for a
// connection the loop has not visited yet.
func (e *connEntry) sample(key string) {
	e.cc.Connect()
	st := healthState(e.cc.GetState())
	if st == HealthUp {
		// A ready socket proves nothing by itself: keep what the last ping
		// established (up, or down for a peer that stopped answering), and
		// report connecting until the loop has pinged a new connection.
		e.hmu.Lock()
		known := e.state
		e.hmu.Unlock()
		if known == HealthUp || known == HealthDown {
			st = known
		} else {
			st = HealthConnecting
		}
	}
	e.record(key, st, nil)
}

func (e *connEntry) record(key, st string, perr error) {
	e.hmu.Lock()
	prev := e.state
	if st != prev {
		e.state = st
		e.since = time.Now()
		if st == HealthUp {
			e.lastErr = ""
		}
	}
	if perr != nil {
		e.lastErr = "probe: " + perr.Error()
		e.lastErrAt = time.Now()
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

// Health reports the connection to the EPP named by cfg without waiting on
// the EPP. The connection is opened if the rule has not sent a request yet,
// so a freshly created rule shows "connecting" and then, once the probe loop
// has pinged it, "up" or "down" within a probe interval.
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
				e.probe(k)
			}
		}
	}
}
