/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

// jwt_metrics.go — observability for the bearer (JWT) admission arm.
//
// Until this file the JWT plane emitted nothing. Every other denial class the
// gateway can produce is countable; a bearer denial was visible only as a
// change in the shape of loxilb_ai_requests_total, which cannot distinguish a
// clock skew from an expired signing key from someone probing with forged
// tokens. Those need opposite responses from an operator, so they get counted
// apart.
//
// The keyset families are the ones worth alerting on. A JWKS endpoint that
// stops answering does not fail loudly: the gateway keeps serving on the
// last-known-good keyset until the staleness cutoff arbitrates, and only then
// starts refusing traffic that was fine a moment earlier. The refresh counter
// and the last-success timestamp make that window observable while it is
// still a warning rather than an outage.
package prometheus

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// JWT validation reasons that are not a client-facing error code. Denials
// carry the gate's own error_code as the reason, which keeps this label's
// value set closed: the codes are a fixed vocabulary, so no request can
// invent one.
const (
	// JWTReasonAllowed is the reason recorded for an admitted bearer request.
	JWTReasonAllowed = "allowed"
	// JWTLabelAbsent stands in for a tenant that does not exist on this
	// verdict. Most denials happen BEFORE a signature is verified, so there
	// is no trustworthy tenant to attribute them to -- and attributing them
	// to a claim that was never verified would let an unauthenticated caller
	// choose a label value.
	JWTLabelAbsent = "-"
)

// JWKS refresh outcomes.
const (
	// JWKSOutcomeSuccess is a fetch that replaced the keyset.
	JWKSOutcomeSuccess = "success"
	// JWKSOutcomeFailure is a fetch that did not, for any reason: discovery,
	// transport, parse, or a published keyset with no usable key. The reason
	// is logged; it is not a label, because an endpoint that fails in a novel
	// way must not be able to grow the series set.
	JWKSOutcomeFailure = "failure"
)

var (
	// loxilb_ai_jwt_validation_total is the bearer arm's verdict counter: one
	// increment per call into the bearer gate, admitted or refused.
	//
	// The reason label separates the classes an operator must tell apart:
	// invalid_token (the credential is bad), missing_token (there was none),
	// model_not_allowed (a real tenant asked for something it may not have),
	// and policy_store_unavailable (the gateway's own fault -- it is failing
	// closed and refusing traffic that should have been served).
	aiJWTValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_jwt_validation_total",
			Help: "Total bearer-token admission verdicts, labelled by tenant and by reason. reason=\"allowed\" counts admissions; every other value is the gate's error_code for the refusal. A tenant of \"-\" means the verdict was reached before a signature was verified, so no tenant could be attributed.",
		},
		[]string{"tenant", "reason"},
	)

	// loxilb_ai_jwks_refresh_total counts keyset fetch attempts by outcome.
	// A rising failure count with a flat success count is the signal that the
	// keyset is aging towards its staleness cutoff -- the window in which the
	// gateway still works and an operator can still fix it.
	aiJWKSRefreshTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_jwks_refresh_total",
			Help: "Total JWKS fetch attempts per bearer profile, by outcome. A failure keeps the last-known-good keyset, so failures are not immediately visible in request outcomes -- which is why they are counted here.",
		},
		[]string{"profile", "outcome"},
	)
)

// JWKSProfileState is one profile's keyset state at scrape time.
type JWKSProfileState struct {
	// Profile is the bearer profile name.
	Profile string
	// Keys is the number of usable verification keys in the snapshot.
	Keys int
	// LastSuccess is the time of the last successful fetch; the zero time
	// when none has ever succeeded.
	LastSuccess time.Time
	// Usable reports whether the request path would accept the snapshot:
	// fetched at least once, and inside the staleness cutoff.
	Usable bool
}

var (
	jwksKeysDesc = prometheus.NewDesc(
		"loxilb_ai_jwks_keys",
		"Usable verification keys in the profile's current keyset. Zero means the bearer arm cannot verify any token for this profile.",
		[]string{"profile"}, nil,
	)
	// Named _seconds per Prometheus convention for a unix timestamp, matching
	// loxilb_kv_subscriber_last_event_timestamp_seconds.
	jwksLastSuccessDesc = prometheus.NewDesc(
		"loxilb_ai_jwks_last_success_timestamp_seconds",
		"Unix time of the last successful JWKS fetch for the profile. Absent until the first fetch succeeds -- an absent series and a zero one mean different things, so no zero is emitted.",
		[]string{"profile"}, nil,
	)
	jwksUsableDesc = prometheus.NewDesc(
		"loxilb_ai_jwks_usable",
		"1 when the profile's keyset is fetched and inside the staleness cutoff, 0 when the bearer arm is failing closed for this profile.",
		[]string{"profile"}, nil,
	)
)

type jwksCollector struct {
	snapshot func() []JWKSProfileState
}

func (c *jwksCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- jwksKeysDesc
	ch <- jwksLastSuccessDesc
	ch <- jwksUsableDesc
}

func (c *jwksCollector) Collect(ch chan<- prometheus.Metric) {
	// Distinct profile names can sanitize to the same label value; emitting
	// both would fail the whole scrape with a duplicate-series error, so only
	// the first entry per sanitized label wins -- the same rule the token
	// quota collector follows.
	seen := make(map[string]struct{})
	for _, st := range c.snapshot() {
		profile := sanitizeLabel(st.Profile)
		if profile == "" {
			continue
		}
		if _, dup := seen[profile]; dup {
			continue
		}
		seen[profile] = struct{}{}

		ch <- prometheus.MustNewConstMetric(jwksKeysDesc,
			prometheus.GaugeValue, float64(st.Keys), profile)
		usable := 0.0
		if st.Usable {
			usable = 1.0
		}
		ch <- prometheus.MustNewConstMetric(jwksUsableDesc,
			prometheus.GaugeValue, usable, profile)
		// A profile that has never fetched gets no timestamp series at all.
		// Emitting 0 would read as "last succeeded at the epoch", and every
		// staleness expression written over it would be wrong by 56 years.
		if !st.LastSuccess.IsZero() {
			ch <- prometheus.MustNewConstMetric(jwksLastSuccessDesc,
				prometheus.GaugeValue, float64(st.LastSuccess.Unix()), profile)
		}
	}
}

var jwksSourceOnce sync.Once

// RegisterJWKSSource registers the scrape-time keyset collector backed by fn.
// Call it once the bearer profile holder exists; only the first registration
// takes effect.
func RegisterJWKSSource(fn func() []JWKSProfileState) {
	jwksSourceOnce.Do(func() {
		prometheus.MustRegister(&jwksCollector{snapshot: fn})
	})
}

// RecordJWTValidation counts one bearer verdict. reason is JWTReasonAllowed
// for an admission, or the gate's error_code for a refusal. An empty tenant
// becomes JWTLabelAbsent rather than an empty label, so "no tenant" is
// legible in a query instead of looking like a scrape bug.
func RecordJWTValidation(tenant, reason string) {
	t := sanitizeLabel(tenant)
	if t == "" {
		t = JWTLabelAbsent
	}
	if reason == "" {
		reason = JWTLabelAbsent
	}
	aiJWTValidationTotal.WithLabelValues(t, reason).Inc()
}

// RecordJWKSRefresh counts one keyset fetch attempt for a profile. outcome is
// JWKSOutcomeSuccess or JWKSOutcomeFailure.
func RecordJWKSRefresh(profile, outcome string) {
	p := sanitizeLabel(profile)
	if p == "" {
		p = JWTLabelAbsent
	}
	if outcome != JWKSOutcomeSuccess {
		outcome = JWKSOutcomeFailure
	}
	aiJWKSRefreshTotal.WithLabelValues(p, outcome).Inc()
}
