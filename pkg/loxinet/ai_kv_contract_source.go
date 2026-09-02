/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package loxinet

// ai_kv_contract_source.go — the compiled engine-contract registry adapted
// to the KvEngineContractSource seam (ai_kv_binding.go). Registration at
// init replaces the fail-closed nil source: strict KV-exact rules resolve
// their contract reference against the registry compiled from
// engine-contracts/contracts.yaml. The seam still carries ONLY reference
// identity and digests — contract content never crosses it.

import (
	"fmt"

	"github.com/loxilb-io/loxilb/pkg/enginecontract"
)

// kvLlamacppProfileID is the compiled no-KV llama.cpp profile whose
// capability answers drive the typed feature refusals in rules.go.
const kvLlamacppProfileID = "llamacpp-nokv-v1"

// KvReasonCapabilityUnavailable is the stable engine-contract reason code
// for a feature request an engine's contract profile declares absent.
const KvReasonCapabilityUnavailable = "ENGINE_CONTRACT_CAPABILITY_UNAVAILABLE"

// KvContractError is a typed admission refusal carrying a stable
// engine-contract reason code as a STRUCTURED field. The message keeps the
// operator-facing wording (and thereby today's HTTP 400 classification);
// the code is for the API layer to surface without substring matching.
type KvContractError struct {
	Code string
	msg  string
}

func (e *KvContractError) Error() string { return e.msg }

// kvContractRefusal builds a capability-unavailable refusal.
func kvContractRefusal(msg string) *KvContractError {
	return &KvContractError{Code: KvReasonCapabilityUnavailable, msg: msg}
}

// kvCompiledContractSource adapts the compiled registry to the
// KvEngineContractSource interface. Resolution is deterministic and
// fail-closed by construction: no default profile (llamacpp), an unknown
// family, or a stale registry generation never resolves.
type kvCompiledContractSource struct{}

// CurrentRef resolves the engine family's default contract reference.
func (kvCompiledContractSource) CurrentRef(engineFamily string) (KvEngineContractRef, error) {
	r, err := enginecontract.CurrentRef(kvEngineEffective(engineFamily))
	if err != nil {
		return KvEngineContractRef{}, err
	}
	return KvEngineContractRef{ID: r.ID, Gen: r.Gen}, nil
}

// ResolveDigest resolves a reference to its profile content digest.
func (kvCompiledContractSource) ResolveDigest(ref KvEngineContractRef) (string, error) {
	return enginecontract.ResolveDigest(enginecontract.Ref{ID: ref.ID, Gen: ref.Gen})
}

// KvContractSourceInit registers the compiled registry as the process's
// engine-contract source (called once at gateway init). It sanity-pins the
// legacy wire-profile table against the compiled registry so a manifest
// edit that breaks legacy resolution fails loudly at boot, not at the
// first subscriber spawn.
func KvContractSourceInit() error {
	for engine, profID := range kvLegacyWireProfile {
		if _, ok := enginecontract.ProfileByID(profID); !ok {
			return fmt.Errorf("kv-contract: legacy wire profile %q (engine %q) missing from compiled registry", profID, engine)
		}
	}
	if _, ok := enginecontract.ProfileByID(kvLlamacppProfileID); !ok {
		return fmt.Errorf("kv-contract: %q missing from compiled registry", kvLlamacppProfileID)
	}
	KvRegisterEngineContractSource(kvCompiledContractSource{})
	return nil
}
