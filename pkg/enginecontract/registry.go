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

// Package enginecontract is the compiled engine-contract registry: the
// build-time product of engine-contracts/contracts.yaml (see cmd/ecgen).
// Resolution is deterministic and fail-closed — an identity the registry
// does not know never resolves, and a stale generation never resolves.
// The registry is immutable at runtime by construction (DEC-012: no hot
// reload; promoting support requires a new gateway release).
package enginecontract

import (
	"fmt"

	"github.com/loxilb-io/loxilb/pkg/enginecontract/schema"
)

// Ref is a contract reference: one profile at one manifest generation.
type Ref struct {
	ID  string
	Gen uint64
}

// CurrentRef resolves an engine family's default contract reference — the
// profile a rule binds when it declares only the family. Engines without a
// family default (no KV contract, e.g. llamacpp) fail closed.
func CurrentRef(engineFamily string) (Ref, error) {
	for i := range Profiles {
		p := &Profiles[i]
		if p.Engine == engineFamily && p.FamilyDefault {
			return Ref{ID: p.ID, Gen: Generation}, nil
		}
	}
	return Ref{}, fmt.Errorf("enginecontract: no default contract profile for engine family %q", engineFamily)
}

// ResolveDigest resolves a reference to its profile content digest. The
// reference's generation must be this build's manifest generation — a
// reference minted against another manifest never resolves.
func ResolveDigest(ref Ref) (string, error) {
	if ref.Gen != Generation {
		return "", fmt.Errorf("enginecontract: reference %s@%d is not from this registry generation (%d)",
			ref.ID, ref.Gen, Generation)
	}
	d, ok := ProfileDigests[ref.ID]
	if !ok {
		return "", fmt.Errorf("enginecontract: unknown contract profile %q", ref.ID)
	}
	return d, nil
}

// ProfileByID returns the compiled profile.
func ProfileByID(id string) (*schema.Profile, bool) {
	for i := range Profiles {
		if Profiles[i].ID == id {
			return &Profiles[i], true
		}
	}
	return nil, false
}

// ResolveVersion deterministically resolves (engine, exact version) to the
// single profile whose selector matches, or fails closed.
func ResolveVersion(engine, version string) (*schema.Profile, error) {
	for i := range Profiles {
		p := &Profiles[i]
		if p.Engine == engine && p.Versions.Matches(version) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("enginecontract: no contract profile for engine %q version %q", engine, version)
}
