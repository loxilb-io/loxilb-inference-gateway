/*
 * Copyright (c) 2026 NetLOX Inc
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
package common

// Recovery-dependency types: the closed vocabulary of external stores a
// snapshot document may declare it depends on for full recovery. The
// snapshot itself never embeds these stores' content -- the manifest
// records their identity (generation/digest) at capture time so a restore
// can verify the same store state is reachable before declaring the
// gateway recovered.
//
// The vocabulary is closed on purpose: restore refuses a REQUIRED
// dependency of a type it does not know (fail closed -- an unknown
// requirement cannot be verified, and proceeding would guess), while an
// unknown OPTIONAL type is tolerated for forward compatibility.
const (
	// RecoveryDepAPIKeyDB is the data-plane API-key/tenant store
	// (PostgreSQL). Key material is never in the snapshot; recovery of
	// key-authenticated traffic needs the same store reachable.
	RecoveryDepAPIKeyDB = "api-key-db"
	// RecoveryDepAuthDB is the management-plane user/auth store
	// (PostgreSQL). Management authentication recovers only with it.
	RecoveryDepAuthDB = "auth-db"
	// RecoveryDepEngineContracts is the compiled engine-contract registry
	// (generation + manifest digest baked into the binary at build time).
	// kvexactbinding entries reference contract generations.
	RecoveryDepEngineContracts = "engine-contracts"
	// RecoveryDepKvModelProfiles is the published ModelPromptProfile
	// registry generation (trusted on-disk artifacts, digest-pinned at
	// load). kvexactbinding entries reference profile generations.
	RecoveryDepKvModelProfiles = "kv-model-profiles"
	// RecoveryDepCertStore is the node-local managed certificate
	// directory. The cert domain carries per-cert {id, digest}; this
	// entry summarizes the whole set for the manifest reader.
	RecoveryDepCertStore = "cert-store"
)

// KnownRecoveryDepTypes is the validation set for the vocabulary above.
var KnownRecoveryDepTypes = map[string]bool{
	RecoveryDepAPIKeyDB:        true,
	RecoveryDepAuthDB:          true,
	RecoveryDepEngineContracts: true,
	RecoveryDepKvModelProfiles: true,
	RecoveryDepCertStore:       true,
}

// RecoveryDependency is one entry of the snapshot document's
// recovery_dependencies manifest (schema 1.4): the identity of an external
// store the captured configuration depends on, recorded so restore can
// verify -- never rebuild -- it. Identity only: no member of this struct
// may ever carry store content or credential material.
type RecoveryDependency struct {
	// Type is one of the RecoveryDep* constants.
	Type string `json:"type"`
	// ID is the stable identity of the concrete store instance (database
	// name, registry schema identifier, source root). Optional: a type
	// with a single well-known instance may omit it.
	ID string `json:"id,omitempty"`
	// Generation is the store's generation at capture, as a decimal
	// string (uint64 producers) or an opaque version token. Optional:
	// stores without generation tracking omit it.
	Generation string `json:"generation,omitempty"`
	// Digest is the store's content digest at capture ("sha256:<hex>").
	// Optional: stores without content digests omit it.
	Digest string `json:"digest,omitempty"`
	// Required classifies the dependency: a required entry must verify
	// before a restore of this document may declare the gateway
	// recovered; an optional entry is informational.
	Required bool `json:"required"`
}
