/*
 * Copyright (c) 2026 LoxiLB Authors
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
package snapshot

import (
	cmn "github.com/loxilb-io/loxilb/common"
)

// DependencyStatus is one external_dependencies entry of the §9
// persist/restore response contract: a recovery_dependencies manifest
// identity plus the reporting operation's disposition toward it. Identity
// fields mirror cmn.RecoveryDependency exactly (and inherit its rule:
// never store content or credential material).
type DependencyStatus struct {
	Type       string `json:"type"`
	ID         string `json:"id,omitempty"`
	Generation string `json:"generation,omitempty"`
	Digest     string `json:"digest,omitempty"`
	Required   bool   `json:"required"`
	Status     string `json:"status"`
}

// DependencyStatus.Status vocabulary. Persist responses use ready and
// configured (capture-time dispositions); restore responses use verified,
// warning, failed and declared (stageVerifyDeps dispositions).
const (
	// DepStatusReady: capture read this store's identity from the live
	// process (compiled contract registry, published profile generation,
	// managed cert directory) -- the store was present at capture.
	DepStatusReady = "ready"
	// DepStatusConfigured: the store is wired and its identity recorded,
	// but reachability is deliberately unclaimed -- the auth-plane stores
	// dial in the background so a persist never blocks on (or lies about)
	// store liveness. The readiness surface owns liveness reporting.
	DepStatusConfigured = "configured"
	// DepStatusVerified: restore verified this REQUIRED entry against the
	// node's actual store before planning anything. For cert-store the
	// per-cert digest authority remains the cert domain apply stage;
	// verified here means the pre-plan gate passed.
	DepStatusVerified = "verified"
	// DepStatusWarning: verification passed but degraded (the warning text
	// is in warnings[]); the restore proceeds.
	DepStatusWarning = "warning"
	// DepStatusFailed: verification failed (the error is in errors[]); the
	// restore stopped before planning, wiping, or applying anything.
	DepStatusFailed = "failed"
	// DepStatusDeclared: an OPTIONAL manifest entry, reported for
	// visibility; optional entries are informational and never verified.
	DepStatusDeclared = "declared"
)

// CaptureDependencyStatuses maps a captured recovery_dependencies manifest
// to the persist response's external_dependencies entries: database
// dependencies report configured (identity recorded, reachability
// deliberately unclaimed), every other store reports ready (its identity
// was just read from the live process -- a capture with an unavailable
// store identity fails instead of writing a dishonest manifest).
func CaptureDependencyStatuses(deps []cmn.RecoveryDependency) []DependencyStatus {
	if len(deps) == 0 {
		return nil
	}
	out := make([]DependencyStatus, 0, len(deps))
	for _, d := range deps {
		status := DepStatusReady
		switch d.Type {
		case cmn.RecoveryDepAPIKeyDB, cmn.RecoveryDepAuthDB:
			status = DepStatusConfigured
		}
		out = append(out, DependencyStatus{
			Type:       d.Type,
			ID:         d.ID,
			Generation: d.Generation,
			Digest:     d.Digest,
			Required:   d.Required,
			Status:     status,
		})
	}
	return out
}
