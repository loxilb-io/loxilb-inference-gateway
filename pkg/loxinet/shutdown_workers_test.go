// Copyright (c) 2026 NetLOX Inc
// SPDX-License-Identifier: Apache-2.0

package loxinet

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func saveWorkerShutdownHooks(t *testing.T) {
	t.Helper()
	oldMetrics, oldBGP, oldKV := metricsStopFn, bgpRecoveryStopFn, kvSubscriberStopFn
	kvServicesMu.Lock()
	oldServices := kvServices
	kvServices = map[uint32]*kvServiceState{55201: {}, 55202: {}}
	kvServicesMu.Unlock()
	t.Cleanup(func() {
		metricsStopFn, bgpRecoveryStopFn, kvSubscriberStopFn = oldMetrics, oldBGP, oldKV
		kvServicesMu.Lock()
		kvServices = oldServices
		kvServicesMu.Unlock()
	})
}

func TestShutdownMetricsTimeoutStillDrainsBGPAndKV(t *testing.T) {
	saveWorkerShutdownHooks(t)
	stage, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	metricsErr := errors.New("metrics generation 77 still stopping")
	bgpErr := errors.New("BGP recovery drain failed")
	metricsStopFn = func(ctx context.Context) error {
		stageDeadline, _ := stage.Deadline()
		metricsDeadline, ok := ctx.Deadline()
		if !ok || !metricsDeadline.Before(stageDeadline) {
			t.Error("metrics consumed the entire stage budget")
		}
		<-ctx.Done()
		return fmt.Errorf("%w: %w", metricsErr, ctx.Err())
	}
	bgpCalled := false
	bgpRecoveryStopFn = func(ctx context.Context) error {
		bgpCalled = true
		if ctx.Err() != nil {
			t.Error("no stage budget reserved for BGP/KV")
		}
		return bgpErr
	}
	stopped := map[uint32]bool{}
	kvSubscriberStopFn = func(id uint32) { stopped[id] = true }
	err := shutdownWorkers(stage)
	if !errors.Is(err, metricsErr) || !errors.Is(err, bgpErr) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost joined failure: %v", err)
	}
	if !bgpCalled || !stopped[55201] || !stopped[55202] {
		t.Fatalf("metrics failure skipped remaining drains: BGP=%v KV=%v", bgpCalled, stopped)
	}
}

func TestShutdownExpiredStageStillIssuesAllCancellations(t *testing.T) {
	saveWorkerShutdownHooks(t)
	stage, cancel := context.WithCancel(context.Background())
	cancel()
	metricsStopFn = func(ctx context.Context) error { return ctx.Err() }
	bgpCalled := false
	bgpRecoveryStopFn = func(ctx context.Context) error { bgpCalled = true; return ctx.Err() }
	stopped := 0
	kvSubscriberStopFn = func(uint32) { stopped++ }
	if err := shutdownWorkers(stage); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost stage cancellation: %v", err)
	}
	if !bgpCalled || stopped != 2 {
		t.Fatalf("expired context skipped cancellations: BGP=%v KV=%d", bgpCalled, stopped)
	}
}

func TestShutdownWorkersSuccessDrainsEverySubscriber(t *testing.T) {
	saveWorkerShutdownHooks(t)
	metricsStopFn = func(context.Context) error { return nil }
	bgpRecoveryStopFn = func(context.Context) error { return nil }
	stopped := 0
	kvSubscriberStopFn = func(uint32) { stopped++ }
	if err := shutdownWorkers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stopped != 2 {
		t.Fatalf("drained %d subscribers, want 2", stopped)
	}
}

func TestNetPrometheusEnablePropagatesInitFailure(t *testing.T) {
	old := prometheusInitFn
	t.Cleanup(func() { prometheusInitFn = old })
	want := errors.New("injected initialization failure")
	prometheusInitFn = func() error { return want }
	if err := (&NetAPIStruct{}).NetPrometheusEnable(); !errors.Is(err, want) {
		t.Fatalf("init failure discarded: %v", err)
	}
}
