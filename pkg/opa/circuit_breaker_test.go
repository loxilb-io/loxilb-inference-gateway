/*
 * Copyright (c) 2025 LoxiLB Authors
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

package opa

import (
	"testing"
	"time"
)

func TestCircuitBreakerInitialState(t *testing.T) {
	cb := NewCircuitBreaker()
	if cb.State() != CircuitClosed {
		t.Errorf("expected initial state CLOSED, got %d", cb.State())
	}
	if !cb.AllowRequest() {
		t.Error("expected AllowRequest=true in CLOSED state")
	}
}

func TestCircuitBreakerClosedAllowsRequests(t *testing.T) {
	cb := NewCircuitBreaker()
	for i := 0; i < 10; i++ {
		if !cb.AllowRequest() {
			t.Fatalf("expected AllowRequest=true on iteration %d", i)
		}
	}
}

func TestCircuitBreakerOpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker()

	// Record failures up to threshold (5)
	for i := 0; i < cbFailureThreshold-1; i++ {
		cb.RecordFailure()
		if cb.State() != CircuitClosed {
			t.Fatalf("expected CLOSED after %d failures, got %d", i+1, cb.State())
		}
	}

	// One more failure should trip the circuit
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Errorf("expected OPEN after %d failures, got %d", cbFailureThreshold, cb.State())
	}
}

func TestCircuitBreakerOpenDeniesRequests(t *testing.T) {
	cb := NewCircuitBreaker()

	// Trip the circuit
	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure()
	}

	if cb.AllowRequest() {
		t.Error("expected AllowRequest=false in OPEN state")
	}
}

func TestCircuitBreakerSuccessResetsFailureCount(t *testing.T) {
	cb := NewCircuitBreaker()

	// Record failures close to threshold
	for i := 0; i < cbFailureThreshold-1; i++ {
		cb.RecordFailure()
	}

	// Success should reset the failure count
	cb.RecordSuccess()

	// Now failures should start from 0 again
	for i := 0; i < cbFailureThreshold-1; i++ {
		cb.RecordFailure()
	}
	if cb.State() != CircuitClosed {
		t.Error("expected CLOSED - success should have reset failure count")
	}
}

func TestCircuitBreakerRecoveryToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker()
	// Use a short recovery timeout for testing
	cb.recoveryTimeout = 10 * time.Millisecond

	// Trip the circuit
	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure()
	}
	if cb.State() != CircuitOpen {
		t.Fatal("expected OPEN state")
	}

	// Wait for recovery timeout
	time.Sleep(20 * time.Millisecond)

	// AllowRequest should transition to HALF_OPEN and return true
	if !cb.AllowRequest() {
		t.Error("expected AllowRequest=true after recovery timeout")
	}
	if cb.State() != CircuitHalfOpen {
		t.Errorf("expected HALF_OPEN, got %d", cb.State())
	}
}

func TestCircuitBreakerHalfOpenClosesOnSuccessThreshold(t *testing.T) {
	cb := NewCircuitBreaker()
	cb.recoveryTimeout = 10 * time.Millisecond

	// Trip → OPEN
	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure()
	}

	// Wait → HALF_OPEN
	time.Sleep(20 * time.Millisecond)
	cb.AllowRequest()
	if cb.State() != CircuitHalfOpen {
		t.Fatal("expected HALF_OPEN")
	}

	// Record successes up to threshold (2)
	for i := 0; i < cbSuccessThreshold-1; i++ {
		cb.RecordSuccess()
		if cb.State() != CircuitHalfOpen {
			t.Fatalf("expected HALF_OPEN after %d successes", i+1)
		}
	}

	// Final success should close the circuit
	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Errorf("expected CLOSED after %d successes in HALF_OPEN, got %d", cbSuccessThreshold, cb.State())
	}
}

func TestCircuitBreakerHalfOpenReopensOnFailure(t *testing.T) {
	cb := NewCircuitBreaker()
	cb.recoveryTimeout = 10 * time.Millisecond

	// Trip → OPEN
	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure()
	}

	// Wait → HALF_OPEN
	time.Sleep(20 * time.Millisecond)
	cb.AllowRequest()
	if cb.State() != CircuitHalfOpen {
		t.Fatal("expected HALF_OPEN")
	}

	// Any failure in HALF_OPEN should immediately re-open
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Errorf("expected OPEN after failure in HALF_OPEN, got %d", cb.State())
	}
}

func TestCircuitBreakerHalfOpenAllowsRequests(t *testing.T) {
	cb := NewCircuitBreaker()
	cb.recoveryTimeout = 10 * time.Millisecond

	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure()
	}

	time.Sleep(20 * time.Millisecond)
	cb.AllowRequest() // transitions to HALF_OPEN

	// Subsequent requests in HALF_OPEN should also be allowed
	if !cb.AllowRequest() {
		t.Error("expected AllowRequest=true in HALF_OPEN state")
	}
}

func TestCircuitBreakerOpenBeforeRecoveryTimeout(t *testing.T) {
	cb := NewCircuitBreaker()
	cb.recoveryTimeout = 1 * time.Hour // very long timeout

	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure()
	}

	// Should still be OPEN (not enough time elapsed)
	if cb.AllowRequest() {
		t.Error("expected AllowRequest=false before recovery timeout")
	}
	if cb.State() != CircuitOpen {
		t.Error("expected OPEN state")
	}
}
