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

// ai_kv_freshness_metrics_test.go — writer-path tests for the two KV
// freshness families (last-event timestamp, inventory-fresh flag), driven
// through the FULL runKvSubscriberLoop against the fake subscriber from
// ai_kv_reconnect_resync_test.go. Pure-Go frame building; no libzmq.

package loxinet

import (
	"context"
	"fmt"
	"testing"
	"time"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
	"github.com/vmihailenco/msgpack/v5"
)

// kvAllBlocksClearedBatch encodes a KVEventBatch carrying one
// AllBlocksCleared event in the tagged-array wire format.
func kvAllBlocksClearedBatch(t *testing.T) []byte {
	t.Helper()
	batch := []interface{}{
		0.0,
		[]interface{}{
			[]interface{}{"AllBlocksCleared"},
		},
		nil,
	}
	b, err := msgpack.Marshal(batch)
	if err != nil {
		t.Fatalf("msgpack marshal AllBlocksCleared batch: %v", err)
	}
	return b
}

// driveFreshnessLoop runs runKvSubscriberLoop over the scripted steps until
// the script exhausts (the fake cancels ctx). Unlike driveSubscriberLoop it
// does not require a reconnect to have happened — freshness scripts drive
// the healthy live-stream path.
func driveFreshnessLoop(t *testing.T, svc *kvServiceState, epIdx int, steps []recvStep) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := &fakeKvSub{t: t, steps: steps, cancel: cancel}

	done := make(chan struct{})
	inv := svc.inventories[epIdx]
	serviceID := svc.serviceID
	go func() {
		runKvSubscriberLoop(ctx, epIdx, serviceID, inv, fake, nil, "inproc://test")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		cancel()
		t.Fatal("runKvSubscriberLoop did not exit within timeout — possible wedge")
	}
}

// cleanupFreshnessService unregisters the service and reaps its series so
// gauge state cannot leak across tests (metrics are process-global).
func cleanupFreshnessService(t *testing.T, serviceID uint32, epIdx int) {
	t.Helper()
	t.Cleanup(func() {
		kvServicesMu.Lock()
		delete(kvServices, serviceID)
		kvServicesMu.Unlock()
		prom.ClearKvEpSeries(fmt.Sprintf("%d", serviceID), fmt.Sprintf("%d", epIdx))
	})
}

// An accepted BlockStored batch must stamp the last-event timestamp with
// the current unix time and prove the inventory fresh.
func TestKvFreshnessStoredBatchStampsAndProves(t *testing.T) {
	const serviceID uint32 = 990401
	const epIdx = 0
	svcLabel, epLabel := fmt.Sprintf("%d", serviceID), fmt.Sprintf("%d", epIdx)

	svc := seedLoopService(t, serviceID, epIdx, nil, -1)
	cleanupFreshnessService(t, serviceID, epIdx)

	before := float64(time.Now().UnixMilli())/1000.0 - 1
	driveFreshnessLoop(t, svc, epIdx, []recvStep{
		{frames: kvFrames(1, kvBlockStoredBatch(t, []uint64{0xAA, 0xBB}))},
	})

	if got := prom.KvInventoryFreshValue(svcLabel, epLabel); got != 1 {
		t.Errorf("inventory_fresh = %v after applied BlockStored, want 1", got)
	}
	ts := prom.KvSubscriberLastEventValue(svcLabel, epLabel)
	if ts < before || ts > float64(time.Now().UnixMilli())/1000.0+1 {
		t.Errorf("last_event_timestamp = %v, want ~now (>=%v)", ts, before)
	}
}

// A payload the wire binding rejects must NOT stamp event freshness — a
// stream of garbage is exactly the silent-staleness case the timestamp
// exists to expose (the wire-reject counter counts it instead).
func TestKvFreshnessRejectedPayloadDoesNotStamp(t *testing.T) {
	const serviceID uint32 = 990402
	const epIdx = 0
	svcLabel, epLabel := fmt.Sprintf("%d", serviceID), fmt.Sprintf("%d", epIdx)

	svc := seedLoopService(t, serviceID, epIdx, nil, -1)
	cleanupFreshnessService(t, serviceID, epIdx)

	driveFreshnessLoop(t, svc, epIdx, []recvStep{
		{frames: kvFrames(1, []byte{0xC1, 0xFF, 0x00})}, // undecodable payload
	})

	if got := prom.KvSubscriberLastEventValue(svcLabel, epLabel); got != 0 {
		t.Errorf("last_event_timestamp = %v after rejected payload, want 0 (unstamped)", got)
	}
	if got := prom.KvInventoryFreshValue(svcLabel, epLabel); got != 0 {
		t.Errorf("inventory_fresh = %v after rejected payload, want 0", got)
	}
}

// AllBlocksCleared invalidates freshness: the inventory no longer holds
// provable current-incarnation content until the next stored block.
func TestKvFreshnessClearedByAllBlocksCleared(t *testing.T) {
	const serviceID uint32 = 990403
	const epIdx = 0
	svcLabel, epLabel := fmt.Sprintf("%d", serviceID), fmt.Sprintf("%d", epIdx)

	svc := seedLoopService(t, serviceID, epIdx, nil, -1)
	cleanupFreshnessService(t, serviceID, epIdx)

	driveFreshnessLoop(t, svc, epIdx, []recvStep{
		{frames: kvFrames(1, kvBlockStoredBatch(t, []uint64{0xAA}))},
		{frames: kvFrames(2, kvAllBlocksClearedBatch(t))},
	})

	if got := prom.KvInventoryFreshValue(svcLabel, epLabel); got != 0 {
		t.Errorf("inventory_fresh = %v after AllBlocksCleared, want 0", got)
	}
	// Both batches were accepted, so the timestamp IS stamped: event flow
	// and inventory validity are independent signals.
	if got := prom.KvSubscriberLastEventValue(svcLabel, epLabel); got == 0 {
		t.Errorf("last_event_timestamp = 0, want stamped (Cleared batch was accepted)")
	}
}

// A live-stream seq regression (publisher restarted behind a transparent
// SUB reconnect) clears the inventory — freshness must drop with it, and a
// following stored block from the NEW incarnation must re-prove it.
func TestKvFreshnessSeqRegressionClearsThenReproves(t *testing.T) {
	const serviceID uint32 = 990404
	const epIdx = 0
	svcLabel, epLabel := fmt.Sprintf("%d", serviceID), fmt.Sprintf("%d", epIdx)

	svc := seedLoopService(t, serviceID, epIdx, []uint64{0x11}, 100)
	cleanupFreshnessService(t, serviceID, epIdx)

	// seq 101: healthy continuation, proves fresh. seq 3: regression →
	// CLEAR (the BlockRemoved payload applies to the already-empty
	// inventory and must NOT re-prove freshness).
	driveFreshnessLoop(t, svc, epIdx, []recvStep{
		{frames: kvFrames(101, kvBlockStoredBatch(t, []uint64{0x22}))},
		{frames: kvFrames(3, kvBlockRemovedBatch(t, []uint64{0x22}))},
	})
	if got := prom.KvInventoryFreshValue(svcLabel, epLabel); got != 0 {
		t.Errorf("inventory_fresh = %v after seq regression, want 0", got)
	}

	// The new incarnation's first stored block re-proves freshness.
	driveFreshnessLoop(t, svc, epIdx, []recvStep{
		{frames: kvFrames(4, kvBlockStoredBatch(t, []uint64{0x33}))},
	})
	if got := prom.KvInventoryFreshValue(svcLabel, epLabel); got != 1 {
		t.Errorf("inventory_fresh = %v after new-incarnation BlockStored, want 1", got)
	}
}
