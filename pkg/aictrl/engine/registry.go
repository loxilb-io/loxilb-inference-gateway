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

// Package engine is the global AI controller's brain as a PURE-GO library
// (CTRL-02/03/04): capability registry (in-repo versioned YAML +
// loader + discovery validation), decision engine v1 (capacity-normalized
// weights ONLY — no TTFT, no scraped load; bounded step, EWMA, dead-band),
// and the SotW snapshot generator emitting the frozen loxilb.aictrl.v1
// contract (pkg/aictrl).
//
// It must build and test with CGO_ENABLED=0 on darwin: no cgo, no
// pkg/loxinet imports — only pkg/aictrl (frozen proto types) and
// pkg/aimetrics (WorkerSample.LastUpdate staleness stamping).
package engine

import (
	"fmt"
	"os"
	"regexp"
	"sync"

	yaml "gopkg.in/yaml.v3"
)

// ServiceDecl identifies the loxilb service the controller instructs.
// Key is the "xip:xport:proto" service key frozen by contract
// (ServiceSnapshot.service_key, e.g. "10.0.0.12:9003:tcp").
type ServiceDecl struct {
	Key  string `yaml:"key"`
	VIP  string `yaml:"vip"`
	Port int    `yaml:"port"`
}

// Host is one fleet endpoint's declared capabilities. The TWO-CAPACITY
// discipline (P8) is structural here: ExpectedNumGPUBlocks is KV/memory
// capacity (validated against the discovered vllm:num_gpu_blocks), while
// ServingThroughputPrior is serving-throughput capacity (a day-0 SKU-table
// estimate). They are consumed by DISTINCT getters
// (Registry.KvCapacity vs Registry.ThroughputPrior) and never combined.
type Host struct {
	GPUModel string `yaml:"gpu_model"`
	HbmGb    int    `yaml:"hbm_gb"`
	Role     string `yaml:"role"` // "prefill" | "decode"
	Port     int    `yaml:"port"`
	// EpIdx is the loxilb EP-array index for this host (matches
	// golden fixture ordering and per-EP metric labeling).
	EpIdx uint32 `yaml:"ep_idx"`
	// ExpectedNumGPUBlocks is the day-0 KV-capacity expectation. Discovery
	// validation compares the live value against it — mismatch ⇒ WARN +
	// counter at the caller, and the DISCOVERED value wins.
	ExpectedNumGPUBlocks uint32 `yaml:"expected_num_gpu_blocks"`
	// ServingThroughputPrior is the relative serving-throughput SKU prior
	// (L4 1.0, L40S 2.0 at day 0 calibrates empirically). It is
	// RETAINED even when a calibration block is present — it is
	// fallback whenever the calibration fingerprint is absent or unverified.
	ServingThroughputPrior float64 `yaml:"serving_throughput_prior"`
	// Calibration is the OPTIONAL empirically-calibrated throughput block
	//. POINTER on purpose: old-shape YAML (no calibration
	// key) must keep parsing under the strict KnownFields(true) decoder.
	// Values are emitted by the calibration harness and reviewed +
	// committed by an operator; the controller never writes them.
	Calibration *CalibrationDecl `yaml:"calibration,omitempty"`
}

// CalibrationDecl is one host's empirically-calibrated serving-throughput
// record, keyed to an exact EP configuration by a config fingerprint.
// A calibration is only trusted when the fingerprint VERIFIES against the
// live-discovered configuration — on any mismatch the consumer falls back to
// ServingThroughputPrior (: report-only, never an eligibility change).
type CalibrationDecl struct {
	// ThroughputTokensPerSec is the raw measured saturation-plateau
	// throughput (tokens/sec) — audit/reporting value.
	ThroughputTokensPerSec float64 `yaml:"throughput_tokens_per_sec"`
	// ThroughputRatio is the within-role relative throughput with the
	// minimum EP of that role ≡ 1.0 — the value the decision engine
	// consumes in place of ServingThroughputPrior when verified.
	ThroughputRatio float64 `yaml:"throughput_ratio"`
	// Fingerprint is hex(sha256(canonical fingerprint_fields))[:16]
	// (see FingerprintHash). The loader re-derives it from
	// FingerprintFields at load time — first tamper check.
	Fingerprint string `yaml:"fingerprint"`
	// FingerprintFields is the explicit, auditable config tuple the
	// fingerprint hashes (gpu_sku, model_id, max_model_len, vllm_image,
	// block_size, num_gpu_blocks, role, kv_connector).
	FingerprintFields map[string]string `yaml:"fingerprint_fields"`
	// MeasuredDate records when the calibration sweep ran (audit trail).
	MeasuredDate string `yaml:"measured_date"`
	// HarnessVersion is the calibration-harness protocol version.
	HarnessVersion int `yaml:"harness_version"`
}

// fingerprintRe: exactly 16 lowercase hex chars (the FingerprintHash shape).
var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// Host role values accepted by LoadRegistry.
const (
	RolePrefill = "prefill"
	RoleDecode  = "decode"
)

// Registry is the loaded, validated capability registry plus the live
// discovery overlay (discovered KV capacities recorded by
// ValidateDiscovery). Safe for concurrent use after LoadRegistry.
type Registry struct {
	Version        int              `yaml:"version"`
	Service        ServiceDecl      `yaml:"service"`
	EpochPeriodSec int              `yaml:"epoch_period_sec"`
	Hosts          map[string]*Host `yaml:"hosts"`

	mu         sync.RWMutex
	discovered map[string]uint32 // ip -> discovered num_gpu_blocks (wins over expected)
}

// Mismatch is the record ValidateDiscovery returns. Mismatched==true means
// the discovered KV capacity disagrees with the registry expectation (or the
// IP is not in the registry at all — Known==false). The BINARY logs
// the WARN and increments the counter; this library only reports.
type Mismatch struct {
	IP         string
	Known      bool // ip present in the registry
	Expected   uint32
	Discovered uint32
	Mismatched bool
}

// LoadRegistry reads and strictly validates a capability-registry YAML
// (bench/testbed/ai-controller.yaml shape). Unknown YAML fields, unknown
// roles, duplicate ep_idx values, and empty host sets are all errors —
// the registry is operator-authored input at a trust boundary.
func LoadRegistry(path string) (*Registry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("registry open: %w", err)
	}
	defer f.Close()

	var r Registry
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true) // strict: reject unknown fields (schema drift)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("registry decode %s: %w", path, err)
	}
	if err := r.validate(); err != nil {
		return nil, fmt.Errorf("registry validate %s: %w", path, err)
	}
	r.discovered = make(map[string]uint32, len(r.Hosts))
	return &r, nil
}

func (r *Registry) validate() error {
	if r.Version != 1 {
		return fmt.Errorf("unsupported version %d (want 1)", r.Version)
	}
	if r.Service.Key == "" {
		return fmt.Errorf("service.key empty")
	}
	if r.EpochPeriodSec <= 0 {
		return fmt.Errorf("epoch_period_sec %d not positive", r.EpochPeriodSec)
	}
	if len(r.Hosts) == 0 {
		return fmt.Errorf("hosts empty")
	}
	seenIdx := make(map[uint32]string, len(r.Hosts))
	for ip, h := range r.Hosts {
		if h == nil {
			return fmt.Errorf("host %s: empty entry", ip)
		}
		if h.Role != RolePrefill && h.Role != RoleDecode {
			return fmt.Errorf("host %s: unknown role %q", ip, h.Role)
		}
		if h.GPUModel == "" {
			return fmt.Errorf("host %s: gpu_model empty", ip)
		}
		if h.Port <= 0 || h.Port > 65535 {
			return fmt.Errorf("host %s: invalid port %d", ip, h.Port)
		}
		if h.ExpectedNumGPUBlocks == 0 {
			return fmt.Errorf("host %s: expected_num_gpu_blocks must be positive", ip)
		}
		if h.ServingThroughputPrior <= 0 {
			return fmt.Errorf("host %s: serving_throughput_prior %v not positive",
				ip, h.ServingThroughputPrior)
		}
		if prev, dup := seenIdx[h.EpIdx]; dup {
			return fmt.Errorf("duplicate ep_idx %d (hosts %s and %s)", h.EpIdx, prev, ip)
		}
		seenIdx[h.EpIdx] = ip
		if h.Calibration != nil {
			if err := h.Calibration.validate(ip); err != nil {
				return err
			}
		}
	}
	return nil
}

// validate checks one host's optional calibration block. The
// fingerprint self-consistency check (Fingerprint MUST equal the hash
// re-derived from FingerprintFields) is the loader's first tamper check —
// a hand-edited ratio with a stale fingerprint, or a hand-edited fingerprint
// that no longer matches its own declared fields, is REJECTED at load
// .
func (c *CalibrationDecl) validate(ip string) error {
	if c.ThroughputTokensPerSec <= 0 {
		return fmt.Errorf("host %s: calibration.throughput_tokens_per_sec %v not positive",
			ip, c.ThroughputTokensPerSec)
	}
	if c.ThroughputRatio <= 0 {
		return fmt.Errorf("host %s: calibration.throughput_ratio %v not positive",
			ip, c.ThroughputRatio)
	}
	if !fingerprintRe.MatchString(c.Fingerprint) {
		return fmt.Errorf("host %s: calibration.fingerprint %q is not 16 lowercase hex chars",
			ip, c.Fingerprint)
	}
	if len(c.FingerprintFields) == 0 {
		return fmt.Errorf("host %s: calibration.fingerprint_fields empty", ip)
	}
	if got := FingerprintHash(c.FingerprintFields); got != c.Fingerprint {
		return fmt.Errorf("host %s: calibration.fingerprint %q does not match hash of fingerprint_fields (%s) — tampered or stale calibration block",
			ip, c.Fingerprint, got)
	}
	return nil
}

// ValidateDiscovery compares a live-discovered KV capacity
// (vllm:num_gpu_blocks) against the registry expectation for ip, RECORDS
// the discovered value (discovered wins for all downstream capacity math —
// and returns the Mismatch record. On mismatch the caller
// binary) logs WARN + increments a counter; the registry expectation is
// NEVER written back — git stays the audit trail.
func (r *Registry) ValidateDiscovery(ip string, discoveredBlocks uint32) Mismatch {
	h, ok := r.Hosts[ip]
	if !ok {
		return Mismatch{IP: ip, Known: false, Discovered: discoveredBlocks, Mismatched: true}
	}
	r.mu.Lock()
	r.discovered[ip] = discoveredBlocks
	r.mu.Unlock()
	return Mismatch{
		IP:         ip,
		Known:      true,
		Expected:   h.ExpectedNumGPUBlocks,
		Discovered: discoveredBlocks,
		Mismatched: discoveredBlocks != h.ExpectedNumGPUBlocks,
	}
}

// KvCapacity returns the KV/memory capacity (num_gpu_blocks) for ip: the
// DISCOVERED value when ValidateDiscovery has recorded one (discovered wins,
// else the registry expectation. This is the KV-capacity code path —
// it must never be blended with ThroughputPrior (two-capacity discipline).
func (r *Registry) KvCapacity(ip string) (uint32, bool) {
	h, ok := r.Hosts[ip]
	if !ok {
		return 0, false
	}
	r.mu.RLock()
	d, seen := r.discovered[ip]
	r.mu.RUnlock()
	if seen {
		return d, true
	}
	return h.ExpectedNumGPUBlocks, true
}

// ThroughputPrior returns the serving-throughput prior for ip. This is the
// throughput-capacity code path (decision-engine share computation) —
// structurally separate from KvCapacity.
func (r *Registry) ThroughputPrior(ip string) (float64, bool) {
	h, ok := r.Hosts[ip]
	if !ok {
		return 0, false
	}
	return h.ServingThroughputPrior, true
}

// CalibratedThroughputRatio returns the serving-THROUGHPUT ratio for ip:
// the calibrated within-role ThroughputRatio when a calibration block is
// present AND the caller has verified its fingerprint against the live
// configuration (fingerprintVerified), else the day-0
// ServingThroughputPrior — fallback. Fallback is REPORT-ONLY at
// this layer: availability/eligibility never changes here; the binary
// logs the WARN and bumps aictrl_fingerprint_mismatch_total.
//
// Two-capacity discipline (P8, locked): this getter is the THROUGHPUT
// capacity path ONLY. KV/memory capacity (num_gpu_blocks) lives behind
// Registry.KvCapacity and is NEVER returned or blended here.
func (r *Registry) CalibratedThroughputRatio(ip string, fingerprintVerified bool) (float64, bool) {
	h, ok := r.Hosts[ip]
	if !ok {
		return 0, false
	}
	if h.Calibration != nil && fingerprintVerified {
		return h.Calibration.ThroughputRatio, true
	}
	return h.ServingThroughputPrior, true
}
