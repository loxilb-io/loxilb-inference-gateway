/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

package prometheus

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// gatherJWKS collects the keyset collector against a pedantic registry and
// returns value-by-profile maps per family. A pedantic registry is the point:
// it fails the gather on a duplicate series, which is the failure mode a
// scrape would hit in production.
func gatherJWKS(t *testing.T, states []JWKSProfileState) map[string]map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(&jwksCollector{snapshot: func() []JWKSProfileState { return states }})

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}
	out := map[string]map[string]float64{}
	for _, mf := range mfs {
		byProfile := map[string]float64{}
		for _, m := range mf.GetMetric() {
			var profile string
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "profile" {
					profile = lp.GetValue()
				}
			}
			byProfile[profile] = m.GetGauge().GetValue()
		}
		out[mf.GetName()] = byProfile
	}
	return out
}

func TestJWKSCollectorReportsKeysetState(t *testing.T) {
	last := time.Unix(1757500000, 0)
	got := gatherJWKS(t, []JWKSProfileState{
		{Profile: "kc", Keys: 3, LastSuccess: last, Usable: true},
	})

	if v := got["loxilb_ai_jwks_keys"]["kc"]; v != 3 {
		t.Errorf("loxilb_ai_jwks_keys = %v, want 3", v)
	}
	if v := got["loxilb_ai_jwks_usable"]["kc"]; v != 1 {
		t.Errorf("loxilb_ai_jwks_usable = %v, want 1", v)
	}
	if v := got["loxilb_ai_jwks_last_success_timestamp_seconds"]["kc"]; v != float64(last.Unix()) {
		t.Errorf("last success = %v, want %v", v, last.Unix())
	}
}

// A profile that has never fetched must emit NO timestamp series. Zero would
// read as "last succeeded at the epoch", and every staleness expression
// written over it — now() - last_success > cutoff — would be true forever,
// which is an alert that cries wolf from the moment a profile is created.
func TestJWKSCollectorOmitsTimestampBeforeFirstSuccess(t *testing.T) {
	got := gatherJWKS(t, []JWKSProfileState{
		{Profile: "fresh", Keys: 0, Usable: false}, // zero LastSuccess
	})

	if _, present := got["loxilb_ai_jwks_last_success_timestamp_seconds"]["fresh"]; present {
		t.Error("a profile that never fetched must emit no last-success series")
	}
	// The control: the other two families DO report it, so the absence above
	// is the timestamp rule and not the collector skipping the profile.
	if v, ok := got["loxilb_ai_jwks_keys"]["fresh"]; !ok || v != 0 {
		t.Errorf("loxilb_ai_jwks_keys = %v (present=%v), want 0 and present", v, ok)
	}
	if v, ok := got["loxilb_ai_jwks_usable"]["fresh"]; !ok || v != 0 {
		t.Errorf("loxilb_ai_jwks_usable = %v (present=%v), want 0 and present", v, ok)
	}
}

// Two profile names that sanitize to the same label would be a duplicate
// series, and the registry fails the WHOLE scrape on one — taking every other
// metric down with it. Only the first may be emitted.
func TestJWKSCollectorDropsDuplicateSanitizedProfiles(t *testing.T) {
	got := gatherJWKS(t, []JWKSProfileState{
		{Profile: "dup a", Keys: 1, Usable: true},
		{Profile: "dup_a", Keys: 9, Usable: true},
		{Profile: "", Keys: 5, Usable: true}, // unnamed: skipped entirely
	})

	if v := got["loxilb_ai_jwks_keys"]["dup_a"]; v != 1 {
		t.Errorf("first entry must win: keys = %v, want 1", v)
	}
	if n := len(got["loxilb_ai_jwks_keys"]); n != 1 {
		t.Errorf("expected exactly one profile series, got %d", n)
	}
}

func TestRecordJWTValidationLabels(t *testing.T) {
	for _, tc := range []struct {
		name       string
		tenant     string
		reason     string
		wantTenant string
		wantReason string
	}{
		{"verified tenant", "acme", "allowed", "acme", "allowed"},
		{"tenant absent before verification", "", "invalid_token", JWTLabelAbsent, "invalid_token"},
		{"reason absent", "acme", "", "acme", JWTLabelAbsent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := counterVecValue(aiJWTValidationTotal, tc.wantTenant, tc.wantReason)
			RecordJWTValidation(tc.tenant, tc.reason)
			after := counterVecValue(aiJWTValidationTotal, tc.wantTenant, tc.wantReason)
			if after-before != 1 {
				t.Errorf("series{tenant=%q,reason=%q} moved by %v, want 1",
					tc.wantTenant, tc.wantReason, after-before)
			}
		})
	}
}

// An outcome the caller invents must not create a new series: an unbounded
// label on a counter driven by a remote endpoint's behaviour is how a metric
// surface grows without anyone deciding to.
func TestRecordJWKSRefreshBoundsOutcome(t *testing.T) {
	before := counterVecValue(aiJWKSRefreshTotal, "kc", JWKSOutcomeFailure)
	RecordJWKSRefresh("kc", "some-new-transport-error")
	after := counterVecValue(aiJWKSRefreshTotal, "kc", JWKSOutcomeFailure)
	if after-before != 1 {
		t.Errorf("an unknown outcome must count as failure; moved by %v, want 1", after-before)
	}

	beforeOK := counterVecValue(aiJWKSRefreshTotal, "kc", JWKSOutcomeSuccess)
	RecordJWKSRefresh("kc", JWKSOutcomeSuccess)
	afterOK := counterVecValue(aiJWKSRefreshTotal, "kc", JWKSOutcomeSuccess)
	if afterOK-beforeOK != 1 {
		t.Errorf("success must count as success; moved by %v, want 1", afterOK-beforeOK)
	}
}
