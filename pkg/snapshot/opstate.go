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
	"fmt"
	"sync"
	"time"
)

// OpRecord is one successful persist or restore, as the status surface
// reports it (FR-class "most recent successful persist/restore generation
// and checksum through a status API").
type OpRecord struct {
	Generation uint64    `json:"generation,omitempty"`
	Checksum   string    `json:"checksum,omitempty"`
	Mode       string    `json:"mode,omitempty"` // persist: trigger; restore: commit|boot
	At         time.Time `json:"at"`
}

var (
	opStateMu   sync.Mutex
	lastPersist *OpRecord
	lastRestore *OpRecord
)

// recordPersistSuccess is called by Persist after the document is durably
// on disk.
func recordPersistSuccess(gen uint64, checksum string, trigger Trigger) {
	opStateMu.Lock()
	defer opStateMu.Unlock()
	lastPersist = &OpRecord{Generation: gen, Checksum: checksum, Mode: string(trigger), At: time.Now().UTC()}
}

// recordRestoreSuccess is called by the engine when a mutating restore
// (commit or boot -- never dry-run) fully succeeds.
func recordRestoreSuccess(gen uint64, checksum, mode string) {
	opStateMu.Lock()
	defer opStateMu.Unlock()
	lastRestore = &OpRecord{Generation: gen, Checksum: checksum, Mode: mode, At: time.Now().UTC()}
}

// LastPersist returns a copy of the most recent successful persist record,
// nil when none has happened in this process.
func LastPersist() *OpRecord {
	opStateMu.Lock()
	defer opStateMu.Unlock()
	if lastPersist == nil {
		return nil
	}
	out := *lastPersist
	return &out
}

// LastRestore returns a copy of the most recent successful mutating
// restore record (commit or boot), nil when none has happened.
func LastRestore() *OpRecord {
	opStateMu.Lock()
	defer opStateMu.Unlock()
	if lastRestore == nil {
		return nil
	}
	out := *lastRestore
	return &out
}

// ReadinessReasons derives the configuration-readiness verdict: an empty
// slice means READY. Pure function over its inputs so the policy is
// unit-testable without hooks or a REST server:
//
//   - the boot config replay must have settled (the write gate is open);
//   - a degraded boot (failed snapshot restore -- strict empty boot or
//     compat legacy fallback) keeps the gateway NOT ready until an
//     operator's commit restore succeeds in this process (lastRestore
//     with mode "commit"): recovery is the designed exit from degraded,
//     and nothing else silently clears it;
//   - every REQUIRED external dependency must be live right now
//     (depFailures carries the probe errors, one per failing store).
func ReadinessReasons(settled bool, boot BootRestoreState, lastRestore *OpRecord, depFailures []string) []string {
	var reasons []string
	if !settled {
		reasons = append(reasons, "boot config replay has not settled")
	}
	if boot.Degraded {
		recovered := lastRestore != nil && lastRestore.Mode == string(ModeCommit)
		if !recovered {
			r := "boot snapshot restore failed"
			if boot.LegacyFallback {
				r += " (running legacy-replayed configuration)"
			} else if boot.Profile != "" {
				r += fmt.Sprintf(" (%s profile: booted empty)", boot.Profile)
			}
			r += "; recover via POST /config/restore"
			reasons = append(reasons, r)
		}
	}
	reasons = append(reasons, depFailures...)
	return reasons
}
