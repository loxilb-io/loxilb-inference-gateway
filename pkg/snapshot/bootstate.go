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

import "sync"

// BootRestoreState is the boot config replay's recorded outcome: what the
// boot loader found, what it applied, and whether the gateway is running
// in a degraded configuration state. The boot loader (api/loxinlp) records
// it; the readiness/status surface reads it -- a gateway whose boot
// restore failed must never look READY silently, whichever profile it
// booted under.
type BootRestoreState struct {
	// Profile is the --config-boot-profile the boot ran under
	// ("strict" or "compat"); empty until the boot replay runs.
	Profile string `json:"profile,omitempty"`
	// SnapshotFound reports whether a snapshot.json existed (and was
	// chosen by the §6.2 arbitration) at boot.
	SnapshotFound bool `json:"snapshot_found"`
	// Succeeded reports a fully applied boot snapshot restore.
	Succeeded bool `json:"succeeded"`
	// Generation is the applied document's lineage generation (success
	// only; zero for pre-1.5 documents, which carry no generation).
	Generation uint64 `json:"generation,omitempty"`
	// QuarantinePath is where the failing snapshot was preserved
	// (failure only; empty when the quarantine rename itself failed --
	// that failure is in Reasons).
	QuarantinePath string `json:"quarantine_path,omitempty"`
	// LegacyFallback reports that the compat profile replayed the legacy
	// *.txt artifacts after a failed snapshot restore.
	LegacyFallback bool `json:"legacy_fallback"`
	// Degraded reports that the boot snapshot restore FAILED: under
	// strict the gateway booted empty awaiting operator recovery, under
	// compat it may be running legacy-replayed (older) configuration.
	// Recovery via a later successful commit restore is the status
	// surface's call, not this record's -- this is the boot's history.
	Degraded bool `json:"degraded"`
	// Reasons carries the failure detail (restore errors, quarantine
	// disposition), empty on success.
	Reasons []string `json:"reasons,omitempty"`
}

var (
	bootStateMu sync.Mutex
	bootState   BootRestoreState
)

// RecordBootRestoreState stores the boot replay outcome (called once by
// the boot loader when the replay settles; later calls overwrite, which a
// production boot never does).
func RecordBootRestoreState(s BootRestoreState) {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	// Copy the slice so the caller cannot mutate the record afterwards.
	s.Reasons = append([]string(nil), s.Reasons...)
	bootState = s
}

// RecordBootLegacyFallback marks that the compat profile's legacy replay
// ran after a failed snapshot restore (recorded separately because the
// fallback happens after the failure record is written).
func RecordBootLegacyFallback() {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	bootState.LegacyFallback = true
}

// BootRestoreStateGet returns a copy of the recorded boot replay outcome.
func BootRestoreStateGet() BootRestoreState {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	out := bootState
	out.Reasons = append([]string(nil), bootState.Reasons...)
	return out
}
