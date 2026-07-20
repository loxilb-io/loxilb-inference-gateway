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

package engine

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const fixturePath = "testdata/registry_fixture.yaml"

func TestRegistryLoadHappyPath(t *testing.T) {
	r, err := LoadRegistry(fixturePath)
	if err != nil {
		t.Fatalf("LoadRegistry(%s): %v", fixturePath, err)
	}
	if r.Version != 1 {
		t.Errorf("version = %d, want 1", r.Version)
	}
	if r.Service.Key != "10.0.0.12:9003:tcp" {
		t.Errorf("service.key = %q", r.Service.Key)
	}
	if r.EpochPeriodSec != 10 {
		t.Errorf("epoch_period_sec = %d, want 10", r.EpochPeriodSec)
	}
	if len(r.Hosts) != 5 {
		t.Fatalf("hosts = %d, want 5", len(r.Hosts))
	}

	// Fleet SKU truth spot checks (96-RESEARCH table).
	h7 := r.Hosts["10.0.0.7"]
	if h7.Role != RolePrefill || h7.GPUModel != "L4" || h7.HbmGb != 24 ||
		h7.Port != 8100 || h7.EpIdx != 0 {
		t.Errorf("10.0.0.7 = %+v", h7)
	}
	h10 := r.Hosts["10.0.0.10"]
	if h10.Role != RoleDecode || h10.GPUModel != "L40S" || h10.HbmGb != 48 ||
		h10.Port != 8200 || h10.EpIdx != 4 {
		t.Errorf("10.0.0.10 = %+v", h10)
	}

	// Two-capacity discipline: distinct getters, distinct values.
	if kv, ok := r.KvCapacity("10.0.0.7"); !ok || kv != 7408 {
		t.Errorf("KvCapacity(10.0.0.7) = %d,%v, want 7408,true", kv, ok)
	}
	if p, ok := r.ThroughputPrior("10.0.0.7"); !ok || p != 1.0 {
		t.Errorf("ThroughputPrior(10.0.0.7) = %v,%v, want 1.0,true", p, ok)
	}
	if p, ok := r.ThroughputPrior("10.0.0.11"); !ok || p != 2.0 {
		t.Errorf("ThroughputPrior(10.0.0.11) = %v,%v, want 2.0,true", p, ok)
	}
	if _, ok := r.KvCapacity("10.9.9.9"); ok {
		t.Errorf("KvCapacity(unknown) reported ok")
	}
	if _, ok := r.ThroughputPrior("10.9.9.9"); ok {
		t.Errorf("ThroughputPrior(unknown) reported ok")
	}
}

// TestRegistryValidationErrors mutates the fixture text per case; every
// LoadRegistry validation error must fire.
func TestRegistryValidationErrors(t *testing.T) {
	base, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		mutate  func(s string) string
		wantErr string
	}{
		{
			name:    "unknown role",
			mutate:  func(s string) string { return strings.Replace(s, "role: decode", "role: turbo", 1) },
			wantErr: "unknown role",
		},
		{
			name:    "duplicate ep_idx",
			mutate:  func(s string) string { return strings.Replace(s, "ep_idx: 4", "ep_idx: 0", 1) },
			wantErr: "duplicate ep_idx",
		},
		{
			name: "empty hosts",
			mutate: func(s string) string {
				return s[:strings.Index(s, "hosts:")] + "hosts: {}\n"
			},
			wantErr: "hosts empty",
		},
		{
			name:    "bad version",
			mutate:  func(s string) string { return strings.Replace(s, "version: 1", "version: 2", 1) },
			wantErr: "unsupported version",
		},
		{
			name:    "empty service key",
			mutate:  func(s string) string { return strings.Replace(s, `key: "10.0.0.12:9003:tcp"`, `key: ""`, 1) },
			wantErr: "service.key empty",
		},
		{
			name:    "non-positive epoch period",
			mutate:  func(s string) string { return strings.Replace(s, "epoch_period_sec: 10", "epoch_period_sec: 0", 1) },
			wantErr: "epoch_period_sec",
		},
		{
			name: "zero expected blocks",
			mutate: func(s string) string {
				return strings.Replace(s, "expected_num_gpu_blocks: 32600", "expected_num_gpu_blocks: 0", 1)
			},
			wantErr: "expected_num_gpu_blocks",
		},
		{
			name: "non-positive throughput prior",
			mutate: func(s string) string {
				return strings.Replace(s, "serving_throughput_prior: 2.0", "serving_throughput_prior: 0", 1)
			},
			wantErr: "serving_throughput_prior",
		},
		{
			name:    "zero port",
			mutate:  func(s string) string { return strings.Replace(s, "port: 8200", "port: 0", 1) },
			wantErr: "invalid port",
		},
		{
			name:    "empty gpu_model",
			mutate:  func(s string) string { return strings.Replace(s, "gpu_model: L40S", `gpu_model: ""`, 1) },
			wantErr: "gpu_model empty",
		},
		{
			name: "unknown field (strict decode)",
			mutate: func(s string) string {
				return strings.Replace(s, "epoch_period_sec: 10",
					"epoch_period_sec: 10\ncombined_capacity: 42", 1)
			},
			wantErr: "field combined_capacity not found",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(string(base))
			if mutated == string(base) {
				t.Fatalf("mutation did not change the fixture — test is inert")
			}
			p := filepath.Join(t.TempDir(), "reg.yaml")
			if err := os.WriteFile(p, []byte(mutated), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadRegistry(p)
			if err == nil {
				t.Fatalf("LoadRegistry accepted a %s registry", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestRegistryLoadMissingFile(t *testing.T) {
	if _, err := LoadRegistry(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("LoadRegistry on a missing file did not error")
	}
}

// TestRegistryDiscoveryMismatch: expected 7408, discovered 9000 ⇒ Mismatch
// record AND the discovered value wins for capacity math.
func TestRegistryDiscoveryMismatch(t *testing.T) {
	r, err := LoadRegistry(fixturePath)
	if err != nil {
		t.Fatal(err)
	}

	// Fixture decode EP expects 7408 (the superseded NIXL-override value).
	m := r.ValidateDiscovery("10.0.0.10", 9000)
	if !m.Known || !m.Mismatched {
		t.Fatalf("mismatch not reported: %+v", m)
	}
	if m.Expected != 7408 || m.Discovered != 9000 {
		t.Fatalf("mismatch record %+v, want expected=7408 discovered=9000", m)
	}
	// Discovered wins downstream.
	if kv, ok := r.KvCapacity("10.0.0.10"); !ok || kv != 9000 {
		t.Fatalf("KvCapacity after discovery = %d,%v, want 9000,true (discovered wins)", kv, ok)
	}
	// Registry expectation is never rewritten (git stays the audit trail).
	if r.Hosts["10.0.0.10"].ExpectedNumGPUBlocks != 7408 {
		t.Fatal("ValidateDiscovery mutated the registry expectation")
	}
	// ThroughputPrior is untouched by KV discovery (two-capacity discipline).
	if p, _ := r.ThroughputPrior("10.0.0.10"); p != 2.0 {
		t.Fatalf("ThroughputPrior changed after KV discovery: %v", p)
	}

	// Agreeing discovery ⇒ no mismatch, value still recorded.
	m = r.ValidateDiscovery("10.0.0.7", 7408)
	if m.Mismatched || !m.Known {
		t.Fatalf("agreeing discovery flagged: %+v", m)
	}
	if kv, _ := r.KvCapacity("10.0.0.7"); kv != 7408 {
		t.Fatalf("KvCapacity(10.0.0.7) = %d", kv)
	}

	// Unknown IP ⇒ Known=false, Mismatched=true, nothing recorded.
	m = r.ValidateDiscovery("10.9.9.9", 123)
	if m.Known || !m.Mismatched {
		t.Fatalf("unknown-IP discovery record %+v", m)
	}
	if _, ok := r.KvCapacity("10.9.9.9"); ok {
		t.Fatal("unknown-IP discovery leaked into KvCapacity")
	}
}

// TestRegistryRealRepoFile: the committed bench/testbed/ai-controller.yaml
// itself parses and matches the fleet contract (guarded by an existence
// skip so `go test` still passes from a partial checkout).
func TestRegistryRealRepoFile(t *testing.T) {
	real := filepath.Join("..", "..", "..", "bench", "testbed", "ai-controller.yaml")
	if _, err := os.Stat(real); err != nil {
		t.Skipf("repo registry not present: %v", err)
	}
	r, err := LoadRegistry(real)
	if err != nil {
		t.Fatalf("real registry failed to load: %v", err)
	}
	if len(r.Hosts) != 5 {
		t.Fatalf("real registry hosts = %d, want 5", len(r.Hosts))
	}
	if r.Service.Key != "10.0.0.12:9003:tcp" {
		t.Errorf("real registry service.key = %q", r.Service.Key)
	}
	prefills, decodes := 0, 0
	for _, h := range r.Hosts {
		switch h.Role {
		case RolePrefill:
			prefills++
		case RoleDecode:
			decodes++
		}
	}
	if prefills != 4 || decodes != 1 {
		t.Errorf("real registry roles: %d prefill / %d decode, want 4/1", prefills, decodes)
	}
	// Heterogeneous prior contrast present (L40S 2.0 vs L4 1.0).
	if p, _ := r.ThroughputPrior("10.0.0.11"); p != 2.0 {
		t.Errorf("real registry L40S prior = %v, want 2.0", p)
	}
	if p, _ := r.ThroughputPrior("10.0.0.9"); p != 1.0 {
		t.Errorf("real registry L4 prior = %v, want 1.0", p)
	}
}

// ── : calibration schema + fingerprint library ──────────────

// calibFields is the exact RQ2 example tuple (L40S prefill on the
// pinned fleet stack) — keyed by the canonical Fp* consts.
func calibFields() map[string]string {
	return map[string]string{
		FpBlockSize:    "16",
		FpGpuSku:       "L40S",
		FpKvConnector:  "multiconnector:nixl+lmcache",
		FpMaxModelLen:  "32768",
		FpModelID:      "Qwen/Qwen2.5-7B-Instruct",
		FpNumGpuBlocks: "32600",
		FpRole:         "prefill",
		FpVllmImage:    "vllm/vllm-openai:v0.17.0",
	}
}

// calibBlock renders a host-indented YAML calibration block carrying the
// given fingerprint (fields = the RQ2 example tuple).
func calibBlock(fp string) string {
	return `    calibration:
      throughput_tokens_per_sec: 12345
      throughput_ratio: 2.31
      fingerprint: "` + fp + `"
      fingerprint_fields:
        gpu_sku: L40S
        model_id: Qwen/Qwen2.5-7B-Instruct
        max_model_len: "32768"
        vllm_image: vllm/vllm-openai:v0.17.0
        block_size: "16"
        num_gpu_blocks: "32600"
        role: prefill
        kv_connector: "multiconnector:nixl+lmcache"
      measured_date: "2026-07-05"
      harness_version: 1
`
}

// host11Tail is the unique tail of the fixture's 10.0.0.11 entry — the
// anchor the new-shape fixture builder appends the calibration block after.
const host11Tail = "    ep_idx: 3\n    expected_num_gpu_blocks: 32600\n    serving_throughput_prior: 2.0\n"

// newShapeFixture returns the base fixture with a calibration block (given
// fingerprint) attached to host 10.0.0.11, written to a temp file.
func newShapeFixture(t *testing.T, fp string) string {
	t.Helper()
	base, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(base), host11Tail, host11Tail+calibBlock(fp), 1)
	if doc == string(base) {
		t.Fatal("new-shape fixture builder did not attach the calibration block — anchor drifted")
	}
	p := filepath.Join(t.TempDir(), "reg-calib.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRegistryCalibrationOldShapeFallback: the UNCHANGED old-shape fixture
// (no calibration blocks) still loads under KnownFields(true), and
// CalibratedThroughputRatio falls back to ServingThroughputPrior regardless
// of the fingerprintVerified flag (: nothing to trust ⇒ prior).
func TestRegistryCalibrationOldShapeFallback(t *testing.T) {
	r, err := LoadRegistry(fixturePath)
	if err != nil {
		t.Fatalf("old-shape fixture failed to load: %v", err)
	}
	for _, verified := range []bool{true, false} {
		if got, ok := r.CalibratedThroughputRatio("10.0.0.7", verified); !ok || got != 1.0 {
			t.Errorf("CalibratedThroughputRatio(10.0.0.7, %v) = %v,%v, want prior 1.0,true",
				verified, got, ok)
		}
		if got, ok := r.CalibratedThroughputRatio("10.0.0.11", verified); !ok || got != 2.0 {
			t.Errorf("CalibratedThroughputRatio(10.0.0.11, %v) = %v,%v, want prior 2.0,true",
				verified, got, ok)
		}
	}
	if _, ok := r.CalibratedThroughputRatio("10.9.9.9", true); ok {
		t.Error("CalibratedThroughputRatio(unknown) reported ok")
	}
}

// TestRegistryCalibrationNewShape: a self-consistent calibration block loads
// under the strict decoder; the getter returns the calibrated ratio ONLY
// when fingerprintVerified=true, the prior otherwise, and never
// leaks into the KV-capacity path (P8).
func TestRegistryCalibrationNewShape(t *testing.T) {
	fp := FingerprintHash(calibFields())
	r, err := LoadRegistry(newShapeFixture(t, fp))
	if err != nil {
		t.Fatalf("new-shape fixture failed to load: %v", err)
	}
	c := r.Hosts["10.0.0.11"].Calibration
	if c == nil {
		t.Fatal("calibration block did not decode")
	}
	if c.ThroughputTokensPerSec != 12345 || c.ThroughputRatio != 2.31 ||
		c.Fingerprint != fp || c.HarnessVersion != 1 ||
		c.MeasuredDate != "2026-07-05" || len(c.FingerprintFields) != 8 {
		t.Fatalf("decoded calibration = %+v", c)
	}
	// Verified ⇒ calibrated ratio.
	if got, ok := r.CalibratedThroughputRatio("10.0.0.11", true); !ok || got != 2.31 {
		t.Errorf("verified getter = %v,%v, want 2.31,true", got, ok)
	}
	// Unverified ⇒ fallback to the RETAINED prior.
	if got, ok := r.CalibratedThroughputRatio("10.0.0.11", false); !ok || got != 2.0 {
		t.Errorf("unverified getter = %v,%v, want prior 2.0,true", got, ok)
	}
	// Sibling without a block still falls back even when verified=true.
	if got, ok := r.CalibratedThroughputRatio("10.0.0.7", true); !ok || got != 1.0 {
		t.Errorf("no-block sibling getter = %v,%v, want prior 1.0,true", got, ok)
	}
	// Two-capacity discipline: KV capacity untouched by calibration (P8).
	if kv, _ := r.KvCapacity("10.0.0.11"); kv != 32600 {
		t.Errorf("KvCapacity(10.0.0.11) = %d after calibration decode, want 32600", kv)
	}
}

// TestRegistryCalibrationValidationErrors: every calibration-block
// validation error fires, including the tamper check (fingerprint that does
// not equal the hash of its own declared fields is REJECTED at load —
func TestRegistryCalibrationValidationErrors(t *testing.T) {
	goodFp := FingerprintHash(calibFields())
	// A valid-FORMAT but wrong-VALUE fingerprint (flip the first hex char).
	tampered := "0" + goodFp[1:]
	if tampered == goodFp {
		tampered = "1" + goodFp[1:]
	}
	good := calibBlock(goodFp)
	cases := []struct {
		name    string
		mutate  func(s string) string
		wantErr string
	}{
		{
			name:    "tampered fingerprint (hash of fields disagrees)",
			mutate:  func(s string) string { return strings.Replace(s, goodFp, tampered, 1) },
			wantErr: "does not match hash of fingerprint_fields",
		},
		{
			name: "tampered field under a stale fingerprint",
			mutate: func(s string) string {
				return strings.Replace(s, `num_gpu_blocks: "32600"`, `num_gpu_blocks: "7408"`, 1)
			},
			wantErr: "does not match hash of fingerprint_fields",
		},
		{
			name:    "malformed fingerprint (not 16 lowercase hex)",
			mutate:  func(s string) string { return strings.Replace(s, goodFp, "NOT-A-FINGERPRNT", 1) },
			wantErr: "not 16 lowercase hex",
		},
		{
			name: "non-positive throughput_tokens_per_sec",
			mutate: func(s string) string {
				return strings.Replace(s, "throughput_tokens_per_sec: 12345", "throughput_tokens_per_sec: 0", 1)
			},
			wantErr: "throughput_tokens_per_sec",
		},
		{
			name: "non-positive throughput_ratio",
			mutate: func(s string) string {
				return strings.Replace(s, "throughput_ratio: 2.31", "throughput_ratio: -1", 1)
			},
			wantErr: "throughput_ratio",
		},
		{
			name: "unknown calibration field (strict decode)",
			mutate: func(s string) string {
				return strings.Replace(s, "      harness_version: 1",
					"      harness_version: 1\n      combined_capacity: 42", 1)
			},
			wantErr: "field combined_capacity not found",
		},
	}
	base, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block := tc.mutate(good)
			if block == good {
				t.Fatal("mutation did not change the calibration block — test is inert")
			}
			doc := strings.Replace(string(base), host11Tail, host11Tail+block, 1)
			p := filepath.Join(t.TempDir(), "reg-bad-calib.yaml")
			if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadRegistry(p)
			if err == nil {
				t.Fatalf("LoadRegistry accepted a registry with %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
	// Empty fingerprint_fields (whole-map replacement, separate shape).
	t.Run("empty fingerprint_fields", func(t *testing.T) {
		block := `    calibration:
      throughput_tokens_per_sec: 12345
      throughput_ratio: 2.31
      fingerprint: "` + goodFp + `"
      fingerprint_fields: {}
      measured_date: "2026-07-05"
      harness_version: 1
`
		doc := strings.Replace(string(base), host11Tail, host11Tail+block, 1)
		p := filepath.Join(t.TempDir(), "reg-empty-fields.yaml")
		if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadRegistry(p)
		if err == nil || !strings.Contains(err.Error(), "fingerprint_fields empty") {
			t.Fatalf("empty fingerprint_fields not rejected: %v", err)
		}
	})
}

// TestFingerprintHashDeterminism: repeated calls agree; map insertion order
// is invisible (canonical sorted serialization); any single field-value
// change changes the hash; output shape is exactly 16 lowercase hex chars.
func TestFingerprintHashDeterminism(t *testing.T) {
	h1 := FingerprintHash(calibFields())
	if h2 := FingerprintHash(calibFields()); h2 != h1 {
		t.Fatalf("non-deterministic: %s vs %s", h1, h2)
	}
	if len(h1) != 16 {
		t.Fatalf("hash length = %d, want 16", len(h1))
	}
	for _, c := range h1 {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			t.Fatalf("hash %q contains non-lowercase-hex char %q", h1, c)
		}
	}
	// Permuted insertion orders (forward, reverse, interleaved) all agree.
	fields := calibFields()
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	perms := [][]string{keys, reversed(keys), interleaved(keys)}
	for i, order := range perms {
		m := make(map[string]string, len(fields))
		for _, k := range order {
			m[k] = fields[k]
		}
		if got := FingerprintHash(m); got != h1 {
			t.Errorf("permutation %d: hash %s != %s", i, got, h1)
		}
	}
	// Every single-field change produces a different hash.
	for k := range fields {
		mutated := calibFields()
		mutated[k] = mutated[k] + "-CHANGED"
		if got := FingerprintHash(mutated); got == h1 {
			t.Errorf("changing field %q did not change the hash", k)
		}
	}
}

func reversed(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[len(in)-1-i] = s
	}
	return out
}

func interleaved(in []string) []string {
	out := make([]string, 0, len(in))
	for i := 0; i < len(in); i += 2 {
		out = append(out, in[i])
	}
	for i := 1; i < len(in); i += 2 {
		out = append(out, in[i])
	}
	return out
}

// TestFingerprintHashGolden freezes the canonical serialization: the exact
// RQ2 example tuple must hash to a PINNED literal, so the serialization
// rules (bytewise key sort, `key=value`, LF-joined, NO trailing newline,
// sha256, first 16 hex chars) can never silently drift.
//
// Serialized input (LF-joined, no trailing newline):
//
//	block_size=16
//	gpu_sku=L40S
//	kv_connector=multiconnector:nixl+lmcache
//	max_model_len=32768
//	model_id=Qwen/Qwen2.5-7B-Instruct
//	num_gpu_blocks=32600
//	role=prefill
//	vllm_image=vllm/vllm-openai:v0.17.0
//
// golden = hex(sha256(input))[:16], computed independently at authoring
// time (python3 hashlib, 2026-07-05); full digest
// e75c4585fc15539c518e89fb952b7fdc62b8754f6dcc4d09a5e786f7e40277dd.
func TestFingerprintHashGolden(t *testing.T) {
	const golden = "e75c4585fc15539c"
	if got := FingerprintHash(calibFields()); got != golden {
		t.Fatalf("canonical serialization drifted: FingerprintHash = %s, golden %s", got, golden)
	}
}

// TestFingerprintVerify: field-wise verification over ONLY the discovered
// subset; report-only records; nothing-to-verify ⇒ nil (not a mismatch).
func TestFingerprintVerify(t *testing.T) {
	decl := &CalibrationDecl{
		ThroughputTokensPerSec: 12345,
		ThroughputRatio:        2.31,
		Fingerprint:            FingerprintHash(calibFields()),
		FingerprintFields:      calibFields(),
	}

	// Agreeing discoverable subset ⇒ no mismatches.
	agree := map[string]string{
		FpNumGpuBlocks: "32600",
		FpBlockSize:    "16",
		FpModelID:      "Qwen/Qwen2.5-7B-Instruct",
		FpMaxModelLen:  "32768",
	}
	if got := VerifyFingerprint("10.0.0.11", decl, agree); got != nil {
		t.Fatalf("agreeing subset reported mismatches: %+v", got)
	}

	// One disagreeing field ⇒ exactly that record; agreeing keys and keys
	// ABSENT from discovered (vllm_image etc.) are NOT reported.
	oneOff := map[string]string{
		FpNumGpuBlocks: "7408", // the classic override drift
		FpBlockSize:    "16",
	}
	got := VerifyFingerprint("10.0.0.11", decl, oneOff)
	if len(got) != 1 {
		t.Fatalf("mismatches = %+v, want exactly 1", got)
	}
	want := FieldMismatch{IP: "10.0.0.11", Field: FpNumGpuBlocks, Expected: "32600", Discovered: "7408"}
	if got[0] != want {
		t.Fatalf("mismatch record = %+v, want %+v", got[0], want)
	}

	// Multiple mismatches come back sorted by field name (deterministic).
	twoOff := map[string]string{
		FpNumGpuBlocks: "7408",
		FpBlockSize:    "128",
		FpModelID:      "Qwen/Qwen2.5-7B-Instruct", // agrees — not reported
	}
	got = VerifyFingerprint("10.0.0.11", decl, twoOff)
	if len(got) != 2 || got[0].Field != FpBlockSize || got[1].Field != FpNumGpuBlocks {
		t.Fatalf("sorted multi-mismatch = %+v, want [block_size num_gpu_blocks]", got)
	}

	// A discovered key the declaration lacks ⇒ reported with Expected "".
	extra := map[string]string{"engine_version": "v1"}
	got = VerifyFingerprint("10.0.0.11", decl, extra)
	if len(got) != 1 || got[0].Expected != "" || got[0].Field != "engine_version" {
		t.Fatalf("undeclared discovered key = %+v", got)
	}

	// Nothing to verify ⇒ nil, never a mismatch.
	if got := VerifyFingerprint("x", nil, agree); got != nil {
		t.Fatalf("nil decl: %+v", got)
	}
	if got := VerifyFingerprint("x", decl, nil); got != nil {
		t.Fatalf("nil discovered: %+v", got)
	}
	if got := VerifyFingerprint("x", decl, map[string]string{}); got != nil {
		t.Fatalf("empty discovered: %+v", got)
	}
	if got := VerifyFingerprint("x", &CalibrationDecl{}, agree); got != nil {
		t.Fatalf("empty decl fields: %+v", got)
	}
}
