/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * SPDX (Short Identifier): Apache-2.0
 */
package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	opts "github.com/loxilb-io/loxilb/options"
)

// scrape drives GET /metrics the way the generated server does and returns the
// wire status and body.
func scrape(t *testing.T, authHeader string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/netlox/v1/metrics", nil)
	if authHeader != "" {
		r.Header.Set("Authorization", authHeader)
	}
	resp := ConfigGetPrometheusCounter(operations.GetMetricsParams{HTTPRequest: r})
	rec := httptest.NewRecorder()
	resp.WriteResponse(rec, runtime.JSONProducer())
	return rec.Code, rec.Body.String()
}

// validToken is the credential withMetricsState installs when it configures
// authentication, so the tests can exercise the accepted path as well as the
// refused one. Manual-token mode is used deliberately: it is the only
// authentication mode whose validation needs no ApiHooks, so these tests
// exercise the real RequireManagementAuth rather than a stub.
const validToken = "pr7-metrics-scrape-token"

// withMetricsState sets the package-globals this route reads and restores them.
// authConfigured installs a working manual-token authenticator; without it an
// empty Authorization header is not even considered a failure, because no
// authentication is configured at all.
func withMetricsState(t *testing.T, prometheus, authRequired, authConfigured bool) {
	t.Helper()
	p := opts.Opts.Prometheus
	u, o, m := opts.Opts.UserServiceEnable, opts.Opts.Oauth2Enable, opts.Opts.ManualTokenEnable
	path := opts.Opts.ManualTokenPath
	prev := MetricsAuthRequired()
	t.Cleanup(func() {
		opts.Opts.Prometheus = p
		opts.Opts.UserServiceEnable, opts.Opts.Oauth2Enable, opts.Opts.ManualTokenEnable = u, o, m
		opts.Opts.ManualTokenPath = path
		SetMetricsAuthRequired(prev)
	})
	opts.Opts.Prometheus = prometheus
	opts.Opts.UserServiceEnable, opts.Opts.Oauth2Enable = false, false
	opts.Opts.ManualTokenEnable = authConfigured
	if authConfigured {
		f := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(f, []byte(validToken), 0o600); err != nil {
			t.Fatalf("write token: %v", err)
		}
		opts.Opts.ManualTokenPath = f
	}
	SetMetricsAuthRequired(authRequired)
}

// The default posture: a scraper with no credential is served, exactly as
// before. This is the case that must not regress -- every existing Prometheus
// job in the field is this case.
func TestMetricsServedAnonymouslyWhenAuthNotRequired(t *testing.T) {
	withMetricsState(t, true, false, false)
	code, body := scrape(t, "")
	if code != http.StatusOK {
		t.Fatalf("anonymous scrape got %d, want 200 (body %q)", code, body)
	}
	if body == "" {
		t.Error("200 with an empty body is not valid exposition")
	}
}

// The fix: with the requirement on, an anonymous scrape is refused rather than
// handed the tenant roster.
func TestMetricsRefusesAnonymousScrapeWhenAuthRequired(t *testing.T) {
	withMetricsState(t, true, true, true)
	code, body := scrape(t, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("anonymous scrape got %d, want 401 (body %q)", code, body)
	}
	// Nothing about the metric surface may leak in the refusal. A body that
	// echoed family names would tell an unauthenticated caller what this
	// gateway runs, which is part of what the refusal is protecting.
	for _, leak := range []string{"loxilb_", "# HELP", "# TYPE", "tenant"} {
		if contains(body, leak) {
			t.Errorf("the 401 body leaks %q: %s", leak, body)
		}
	}
}

// An invalid credential is refused too -- the requirement is not satisfied by
// merely sending a header.
func TestMetricsRefusesInvalidCredentialWhenAuthRequired(t *testing.T) {
	withMetricsState(t, true, true, true)
	code, _ := scrape(t, "Bearer not-a-real-token")
	if code != http.StatusUnauthorized {
		t.Fatalf("invalid credential got %d, want 401", code)
	}
}

// The other half of the contract, and the half that makes the refusals mean
// something: a scraper carrying a valid credential is served the exposition.
// Without this the tests above would pass just as happily against a route that
// refused everyone.
func TestMetricsServedWithAValidCredential(t *testing.T) {
	withMetricsState(t, true, true, true)
	code, body := scrape(t, "Bearer "+validToken)
	if code != http.StatusOK {
		t.Fatalf("authenticated scrape got %d, want 200 (body %q)", code, body)
	}
	if body == "" {
		t.Error("200 with an empty body is not valid exposition")
	}
}

// Metrics-disabled is answered before the credential check, deliberately.
// Whether collection is switched on is the same answer for every caller and
// discloses no metric values; making an operator authenticate to be told the
// subsystem is off helps nobody. This pins the ordering so it is a decision
// rather than an accident.
func TestMetricsDisabledAnswersBeforeAuth(t *testing.T) {
	withMetricsState(t, false, true, true)
	code, body := scrape(t, "")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("disabled metrics with auth required got %d, want 503", code)
	}
	if !contains(body, "disabled") {
		t.Errorf("503 body does not say the subsystem is disabled: %q", body)
	}
}

// The startup decision is the only input. If this ever reads options.Opts
// directly again, the profile half of the decision (remote-tls) would be lost
// and the route would reopen under the profile that most needs it closed.
func TestMetricsAuthStateRoundTrips(t *testing.T) {
	withMetricsState(t, true, false, false)
	if MetricsAuthRequired() {
		t.Fatal("state did not take")
	}
	SetMetricsAuthRequired(true)
	if !MetricsAuthRequired() {
		t.Fatal("state did not update")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}
