/*
 * Copyright (c) 2025 NetLOX Inc
 *
 * SPDX (Short Identifier): Apache-2.0
 */

package loxinet

import (
	"github.com/loxilb-io/loxilb/pkg/aikey"
)

// Decision values the data plane returns. They are the Go-side names for the
// ladder documented in ai_gateway_dp.go and in sockproxy_ai_gw.h; those two
// sites are kept in agreement by scripts/check-source-invariants.sh.
const (
	aiDecisionAllow    = 0
	aiDecisionDeny401  = 1
	aiDecisionDeny403  = 2
	aiDecisionDeny429  = 3
	aiDecisionDeny503  = 4
	aiErrPolicyStoreNA = "policy_store_unavailable"
)

// keyStoreVerdict decides what the data plane must answer when it is asked to
// validate a key, based on whether a key store exists at all.
//
// This lives here, outside the cgo file, for the same reason
// validateAPIKeyInternal does: the decision is the part worth testing and no
// test in this tree can import "C". Without a seam the only way to observe
// "a missing store never admits a request" is a live gate with the store
// stopped, which cannot run on every commit.
//
// It takes the concrete *aikey.Service the process actually holds, rather than
// the apiKeyValidator interface, and that is deliberate. If this field were
// ever changed to an interface type, `store == nil` would silently become a
// typed-nil comparison that is false for a nil *aikey.Service wrapped in an
// interface — the store would read as present, the code would call a method on
// a nil pointer, and the recover() in the export would turn a policy-store
// outage into a 401. Taking the concrete type means that change breaks this
// signature instead of quietly admitting traffic.
//
// haveStore is returned separately from the decision because the caller needs
// to distinguish "no verdict yet, carry on" from "allow": returning
// aiDecisionAllow for the healthy case would make a caller that ignored the
// boolean admit every request without validating it.
func keyStoreVerdict(store *aikey.Service) (decision int, errorCode string, haveStore bool) {
	if store == nil {
		// The data-plane gate only calls the validator when the service's
		// api_key_auth policy is "required", so a nil store is not "nobody
		// asked for auth" — it is "the operator asked for auth and the store
		// cannot answer". That fails CLOSED.
		//
		// Deliberately not a 401. A client must be able to tell "your key is
		// wrong" from "the gateway cannot tell right now": the first is the
		// client's problem and permanent, the second is the operator's and
		// transient, and a client that retries is right in the second case
		// and wrong in the first.
		return aiDecisionDeny503, aiErrPolicyStoreNA, false
	}
	return aiDecisionAllow, "", true
}

// gateDenialStatuses maps each deny decision to the HTTP status the C gate
// answers the client with. It sits next to the decision constants because the
// two must move together, and scripts/check-source-invariants.sh asserts the
// table covers exactly the aiDecisionDenyNNN set — a new decision value that
// lands without a status here fails that check rather than being counted under
// the wrong one.
//
// The map exists because the status is NOT derivable from the denial reason.
// Two different exports return aiDecisionDeny503: the key validator when the
// store cannot answer, and the rate-limit stage when it finds a keyed identity
// with no store behind it. Reading the second as "came from the rate limiter,
// therefore 429" files a policy-store outage as a throttling event, which is
// the report an on-call engineer then acts on.
var gateDenialStatuses = map[int]int{
	aiDecisionDeny401: 401,
	aiDecisionDeny403: 403,
	aiDecisionDeny429: 429,
	aiDecisionDeny503: 503,
}

// gateDenialStatus returns the HTTP status the data plane sends for a deny
// decision, for use as the status label on a denied request.
//
// An unmapped decision returns 500 rather than guessing at a plausible 4xx.
// The denial is still counted — dropping it would reopen the hole this whole
// path exists to close — but it is counted under a status no gate arm emits,
// so it shows up as {outcome="denied",status="500"} instead of hiding inside
// the 401s. It cannot collide with a backend 500, which carries
// outcome="completed".
func gateDenialStatus(decision int) int {
	if status, ok := gateDenialStatuses[decision]; ok {
		return status
	}
	return 500
}
