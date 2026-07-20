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

// OPAPolicyResponse represents the OPA REST API response for L4 policies.
// Expected structure: {"result":{"l4":{"firewall_access_rules":[...]}}}
type OPAPolicyResponse struct {
	Result struct {
		L4 struct {
			FirewallAccessRules []OPARule `json:"firewall_access_rules"`
		} `json:"l4"`
	} `json:"result"`
}

// OPARule represents a single firewall rule from OPA policy.
type OPARule struct {
	SourceIP           string `json:"sourceIP"`
	DestinationIP      string `json:"destinationIP"`
	Protocol           int    `json:"protocol"`
	MinSourcePort      int    `json:"minSourcePort"`
	MaxSourcePort      int    `json:"maxSourcePort"`
	MinDestinationPort int    `json:"minDestinationPort"`
	MaxDestinationPort int    `json:"maxDestinationPort"`
	Action             string `json:"action"` // "allow" or "deny"
	Preference         int    `json:"preference"`
}

// DiffKey is a stable string used as map key for rule diffing.
type DiffKey string

// CircuitBreakerState represents the circuit breaker's current state.
type CircuitBreakerState int

const (
	// CircuitClosed indicates the circuit breaker is allowing all requests.
	CircuitClosed CircuitBreakerState = 0
	// CircuitOpen indicates the circuit breaker is denying all requests.
	CircuitOpen CircuitBreakerState = 1
	// CircuitHalfOpen indicates the circuit breaker is allowing probe requests.
	CircuitHalfOpen CircuitBreakerState = 2
)
