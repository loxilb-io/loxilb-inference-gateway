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
	"sync"
	"time"

	tk "github.com/loxilb-io/loxilib"
)

const (
	// cbFailureThreshold is the number of consecutive failures before opening the circuit.
	cbFailureThreshold = 5
	// cbRecoveryTimeout is the duration to wait in OPEN state before transitioning to HALF_OPEN.
	cbRecoveryTimeout = 60 * time.Second
	// cbSuccessThreshold is the number of consecutive successes in HALF_OPEN to close the circuit.
	cbSuccessThreshold = 2
)

// CircuitBreaker implements a thread-safe circuit breaker pattern for OPA policy fetching.
type CircuitBreaker struct {
	mu               sync.Mutex
	state            CircuitBreakerState
	failureCount     int
	successCount     int
	lastFailureTime  time.Time
	recoveryTimeout  time.Duration
	failureThreshold int
	successThreshold int
}

// NewCircuitBreaker creates a CircuitBreaker with default thresholds.
func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		state:            CircuitClosed,
		recoveryTimeout:  cbRecoveryTimeout,
		failureThreshold: cbFailureThreshold,
		successThreshold: cbSuccessThreshold,
	}
}

// AllowRequest returns true if the circuit breaker permits a request.
// In CLOSED state, all requests are allowed.
// In OPEN state, requests are denied until the recovery timeout has elapsed,
// at which point the state transitions to HALF_OPEN.
// In HALF_OPEN state, requests are allowed for probing.
func (cb *CircuitBreaker) AllowRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastFailureTime) >= cb.recoveryTimeout {
			cb.state = CircuitHalfOpen
			cb.successCount = 0
			cb.failureCount = 0
			tk.LogIt(tk.LogInfo, "[OPA-L4] circuit breaker: OPEN -> HALF_OPEN (recovery timeout elapsed)\n")
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful request.
// In HALF_OPEN state, reaching the success threshold closes the circuit.
// In CLOSED state, the failure count is reset.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitHalfOpen:
		cb.successCount++
		if cb.successCount >= cb.successThreshold {
			cb.state = CircuitClosed
			cb.failureCount = 0
			cb.successCount = 0
			tk.LogIt(tk.LogInfo, "[OPA-L4] circuit breaker: HALF_OPEN -> CLOSED (success threshold reached)\n")
		}
	case CircuitClosed:
		cb.failureCount = 0
	}
}

// RecordFailure records a failed request.
// In CLOSED state, reaching the failure threshold opens the circuit.
// In HALF_OPEN state, any failure immediately opens the circuit.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailureTime = time.Now()

	switch cb.state {
	case CircuitClosed:
		cb.failureCount++
		if cb.failureCount >= cb.failureThreshold {
			cb.state = CircuitOpen
			tk.LogIt(tk.LogWarning, "[OPA-L4] circuit breaker: CLOSED -> OPEN (failure threshold %d reached)\n", cb.failureThreshold)
		}
	case CircuitHalfOpen:
		cb.state = CircuitOpen
		cb.successCount = 0
		tk.LogIt(tk.LogWarning, "[OPA-L4] circuit breaker: HALF_OPEN -> OPEN (failure during probe)\n")
	}
}

// State returns the current circuit breaker state.
func (cb *CircuitBreaker) State() CircuitBreakerState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}
