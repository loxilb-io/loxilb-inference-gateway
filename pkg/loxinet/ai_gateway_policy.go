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
