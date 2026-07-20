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

package aictrl

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const testSvcKey = "10.0.0.12:9003:tcp"

func testKnown() map[string][]uint32 {
	// Fleet-mirroring fixture: 4 prefill + 1 decode EP indices.
	return map[string][]uint32{testSvcKey: {0, 1, 2, 3, 4}}
}

// validSnapshot returns a snapshot that passes every V5 rule relative to
// the fake clock anchor tBase (deadline 30s ahead, epoch 42).
func validSnapshot() *Snapshot {
	return &Snapshot{
		Epoch:                   42,
		BootId:                  "boot-A",
		StalenessDeadlineUnixMs: uint64(tBase.Add(30 * time.Second).UnixMilli()),
		MinApplierVersion:       1,
		Nonce:                   "nonce-42",
		Services: []*ServiceSnapshot{{
			ServiceKey: testSvcKey,
			Eps: []*EpEntry{
				{EpIdx: 0, EpAddr: "10.0.0.7:8100", Role: Role_ROLE_PREFILL, Weight: 80, State: EpState_EP_STATE_ACTIVE},
				{EpIdx: 1, EpAddr: "10.0.0.8:8100", Role: Role_ROLE_PREFILL, Weight: 100, State: EpState_EP_STATE_ACTIVE},
				{EpIdx: 4, EpAddr: "10.0.0.10:8200", Role: Role_ROLE_DECODE, Weight: 100, State: EpState_EP_STATE_ACTIVE},
			},
		}},
	}
}

func TestValidateSnapshot(t *testing.T) {
	window := 30 * time.Second

	t.Run("valid snapshot accepted", func(t *testing.T) {
		if err := ValidateSnapshot(validSnapshot(), testKnown(), "", 0, tBase, window); err != nil {
			t.Fatalf("valid snapshot rejected: %v", err)
		}
	})

	t.Run("nil snapshot rejected", func(t *testing.T) {
		if err := ValidateSnapshot(nil, testKnown(), "", 0, tBase, window); err == nil {
			t.Fatal("nil snapshot accepted")
		}
	})

	t.Run("weight > 100 rejected", func(t *testing.T) {
		s := validSnapshot()
		s.Services[0].Eps[0].Weight = 101
		if err := ValidateSnapshot(s, testKnown(), "", 0, tBase, window); err == nil ||
			!strings.Contains(err.Error(), "weight") {
			t.Fatalf("weight 101 not rejected with weight error: %v", err)
		}
	})

	t.Run("invalid state enum rejected", func(t *testing.T) {
		s := validSnapshot()
		s.Services[0].Eps[0].State = EpState(7)
		if err := ValidateSnapshot(s, testKnown(), "", 0, tBase, window); err == nil ||
			!strings.Contains(err.Error(), "state") {
			t.Fatalf("state 7 not rejected with state error: %v", err)
		}
	})

	t.Run("UNSPECIFIED state is the frozen no-instruction value — accepted", func(t *testing.T) {
		s := validSnapshot()
		s.Services[0].Eps[0].State = EpState_EP_STATE_UNSPECIFIED
		if err := ValidateSnapshot(s, testKnown(), "", 0, tBase, window); err != nil {
			t.Fatalf("UNSPECIFIED state rejected: %v", err)
		}
	})

	t.Run("unknown service rejected", func(t *testing.T) {
		s := validSnapshot()
		s.Services[0].ServiceKey = "10.9.9.9:1234:tcp"
		if err := ValidateSnapshot(s, testKnown(), "", 0, tBase, window); err == nil ||
			!strings.Contains(err.Error(), "unknown service") {
			t.Fatalf("unknown service not rejected: %v", err)
		}
	})

	t.Run("unknown ep_idx rejected", func(t *testing.T) {
		s := validSnapshot()
		s.Services[0].Eps[0].EpIdx = 99
		if err := ValidateSnapshot(s, testKnown(), "", 0, tBase, window); err == nil ||
			!strings.Contains(err.Error(), "unknown ep_idx") {
			t.Fatalf("unknown ep_idx not rejected: %v", err)
		}
	})

	t.Run("duplicate ep_idx rejected", func(t *testing.T) {
		s := validSnapshot()
		s.Services[0].Eps[1].EpIdx = 0
		if err := ValidateSnapshot(s, testKnown(), "", 0, tBase, window); err == nil ||
			!strings.Contains(err.Error(), "duplicate ep_idx") {
			t.Fatalf("duplicate ep_idx not rejected: %v", err)
		}
	})

	t.Run("replay attack: same boot_id, epoch 41 after 42 — rejected typed", func(t *testing.T) {
		s := validSnapshot()
		s.Epoch = 41
		err := ValidateSnapshot(s, testKnown(), "boot-A", 42, tBase, window)
		if err == nil {
			t.Fatal("replay accepted")
		}
		if !errors.Is(err, ErrEpochReplay) {
			t.Fatalf("replay error not typed ErrEpochReplay: %v", err)
		}
		// The message is what surfaces in Ack.error_detail — assert it names
		// the replay condition (client_test.go asserts the wire plumbing).
		if !strings.Contains(err.Error(), "epoch replay on same boot_id") {
			t.Fatalf("replay error_detail text missing: %v", err)
		}
	})

	t.Run("same boot_id, equal epoch — rejected (monotone strictly)", func(t *testing.T) {
		s := validSnapshot() // epoch 42
		if err := ValidateSnapshot(s, testKnown(), "boot-A", 42, tBase, window); !errors.Is(err, ErrEpochReplay) {
			t.Fatalf("equal epoch on same boot_id not rejected: %v", err)
		}
	})

	t.Run("boot_id change resets the epoch floor — accepted", func(t *testing.T) {
		s := validSnapshot()
		s.Epoch = 1
		s.BootId = "boot-B"
		if err := ValidateSnapshot(s, testKnown(), "boot-A", 42, tBase, window); err != nil {
			t.Fatalf("fresh boot_id epoch reset rejected: %v", err)
		}
	})

	t.Run("staleness deadline in the past rejected", func(t *testing.T) {
		s := validSnapshot()
		s.StalenessDeadlineUnixMs = uint64(tBase.Add(-time.Second).UnixMilli())
		if err := ValidateSnapshot(s, testKnown(), "", 0, tBase, window); err == nil ||
			!strings.Contains(err.Error(), "not in the future") {
			t.Fatalf("past deadline not rejected: %v", err)
		}
	})

	t.Run("staleness deadline > 10x window ahead rejected", func(t *testing.T) {
		s := validSnapshot()
		s.StalenessDeadlineUnixMs = uint64(tBase.Add(301 * time.Second).UnixMilli())
		if err := ValidateSnapshot(s, testKnown(), "", 0, tBase, window); err == nil ||
			!strings.Contains(err.Error(), "10x decay window") {
			t.Fatalf("far-future deadline not rejected: %v", err)
		}
	})

	t.Run("min_applier_version above mine rejected", func(t *testing.T) {
		s := validSnapshot()
		s.MinApplierVersion = ApplierVersion + 1
		if err := ValidateSnapshot(s, testKnown(), "", 0, tBase, window); err == nil ||
			!strings.Contains(err.Error(), "min_applier_version") {
			t.Fatalf("future min_applier_version not rejected: %v", err)
		}
	})
}
