/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	cmn "github.com/loxilb-io/loxilb/common"
)

// lbReplaceChange is what a replace of a load-balancer rule changes, by
// class, as AddLbRule compares it.
type lbReplaceChange struct {
	// Recreate: a value the data plane takes only when it creates the pool.
	Recreate bool
	// Refresh: a value the data plane's refresh of an existing pool applies
	// (the selector between CHWBL and WRR_HASH, the CHWBL parameters, the
	// sockmap mode, the prefill timeout).
	Refresh bool
	// GatewayOnly: a value the Gateway applies and no data-plane pool of a
	// full-proxy rule holds (probe settings, monitor, allowed sources, trace
	// type, name, EPP transport, persistence timeout, a migration attach).
	GatewayOnly bool
	// Endpoints: the endpoint set, an endpoint's declared values, or the
	// rule's admin state (every endpoint inactive while paused).
	Endpoints bool
	// InPlaceOnly: only values of the in-place class changed (admission,
	// flow control, half-close, default reservation, objective, no-endpoint
	// status, a staged backend TLS policy).
	InPlaceOnly bool
	// ZeroEpEdge: the rule is emptied or refilled and nothing else changes.
	ZeroEpEdge bool
	// TooManyEps: the new endpoint set is above MaxLBEndPoints and all
	// endpoints are reset.
	TooManyEps bool
}

// lbReplaceRemovesPool tells whether a replace removes the rule's data-plane
// pool before it is created again.
//
// A full-proxy pool is removed and created again on a replace, so that it
// takes every value of the rule at create. A CHWBL or WRR_HASH pool keeps its
// bounded-load counts and ring when the data plane can refresh it: when only
// endpoints, values the refresh applies, values the Gateway applies or the
// in-place class change. A change of any other value removes it as for any
// other selector, also when the endpoint set is reset for having too many
// endpoints. Emptying or refilling a rule never removes the pool.
func lbReplaceRemovesPool(oldSel, newSel cmn.EpSelect, mode cmn.LBMode, c lbReplaceChange) bool {
	hashed := isCHWBLSelector(oldSel) || isCHWBLSelector(newSel)
	if c.TooManyEps {
		// The endpoint-count reset: a hashed full-proxy pool is refreshed
		// unless a value it cannot refresh changes with it.
		// AddLbRule refuses more than MaxLBEndPoints endpoints before it gets here, so no replace reaches this today.
		if !hashed {
			return true
		}
		return mode == cmn.LBModeFullProxy && c.Recreate
	}
	if mode != cmn.LBModeFullProxy || c.InPlaceOnly || c.ZeroEpEdge {
		return false
	}
	return !hashed || c.Recreate
}

// lbSelChangeRefreshes tells whether a selector change is applied by the data
// plane's refresh of the pool: only between CHWBL and WRR_HASH, which build
// their ring and loads through the refresh's validated candidate.
func lbSelChangeRefreshes(oldSel, newSel cmn.EpSelect) bool {
	return isCHWBLSelector(oldSel) && isCHWBLSelector(newSel)
}

// lbReplaceRefreshesHashedPool tells whether a replace refreshed a CHWBL or
// WRR_HASH pool in place. Only such a pool is put back by restoring its
// hashing values and selector and pushing it again; a pool that was removed
// is put back by the general undo, as for any other selector.
func lbReplaceRefreshesHashedPool(hashed, removed bool) bool {
	return hashed && !removed
}
