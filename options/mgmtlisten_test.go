/*
 * Copyright (c) 2026 NetLOX Inc
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

package options

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jessevdk/go-flags"
)

// setOpts resets the fields MgmtListenPlan reads and restores them when the
// test ends; Opts is package-global state.
func setOpts(t *testing.T, mutate func()) {
	t.Helper()
	profile, host, tlsHost := Opts.MgmtProfile, Opts.Host, Opts.TLSHost
	tls, cert, key := Opts.TLS, Opts.TLSCertificate, Opts.TLSCertificateKey
	user, oauth, manual := Opts.UserServiceEnable, Opts.Oauth2Enable, Opts.ManualTokenEnable
	metricsAuth := Opts.MetricsAuth
	t.Cleanup(func() {
		Opts.MgmtProfile, Opts.Host, Opts.TLSHost = profile, host, tlsHost
		Opts.TLS, Opts.TLSCertificate, Opts.TLSCertificateKey = tls, cert, key
		Opts.UserServiceEnable, Opts.Oauth2Enable, Opts.ManualTokenEnable = user, oauth, manual
		Opts.MetricsAuth = metricsAuth
	})
	Opts.MgmtProfile, Opts.Host, Opts.TLSHost = "legacy", "0.0.0.0", "0.0.0.0"
	Opts.TLS, Opts.TLSCertificate, Opts.TLSCertificateKey = false, "", ""
	Opts.UserServiceEnable, Opts.Oauth2Enable, Opts.ManualTokenEnable = false, false, false
	Opts.MetricsAuth = MetricsAuthAuto
	mutate()
}

// certPair writes a readable dummy certificate and key path pair.
func certPair(t *testing.T) (flags.Filename, flags.Filename) {
	t.Helper()
	dir := t.TempDir()
	cert := filepath.Join(dir, "server.crt")
	key := filepath.Join(dir, "server.key")
	for _, f := range []string{cert, key} {
		if err := os.WriteFile(f, []byte("test"), 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	return flags.Filename(cert), flags.Filename(key)
}

// TestLegacyProfileIsUntouched proves the default profile changes nothing:
// whatever host was configured passes through and the listener set is not
// taken over.
func TestLegacyProfileIsUntouched(t *testing.T) {
	setOpts(t, func() {
		Opts.Host = "0.0.0.0"
		Opts.TLS = true
	})
	plan, err := MgmtListenPlan()
	if err != nil {
		t.Fatalf("legacy must never fail: %v", err)
	}
	if plan.Host != "0.0.0.0" || !plan.HTTP || !plan.HTTPS || plan.Explicit {
		t.Errorf("legacy plan altered behavior: %+v", plan)
	}
}

func TestApplianceLocalCoercesTheDefaultBind(t *testing.T) {
	setOpts(t, func() { Opts.MgmtProfile = "appliance-local" })
	plan, err := MgmtListenPlan()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Host != "127.0.0.1" || !plan.HTTP || plan.HTTPS || !plan.Explicit {
		t.Errorf("plan = %+v, want loopback plaintext only", plan)
	}
}

func TestApplianceLocalKeepsExplicitLoopback(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost", "127.1.2.3"} {
		setOpts(t, func() {
			Opts.MgmtProfile = "appliance-local"
			Opts.Host = host
		})
		plan, err := MgmtListenPlan()
		if err != nil {
			t.Errorf("%q: unexpected error: %v", host, err)
			continue
		}
		if plan.Host != host {
			t.Errorf("%q: host rewritten to %q", host, plan.Host)
		}
	}
}

func TestApplianceLocalRefusesReachableBind(t *testing.T) {
	for _, host := range []string{"10.0.0.5", "192.168.1.1", "::", "example.internal"} {
		setOpts(t, func() {
			Opts.MgmtProfile = "appliance-local"
			Opts.Host = host
		})
		if _, err := MgmtListenPlan(); err == nil {
			t.Errorf("%q: a reachable bind must be refused, not coerced", host)
		}
	}
}

func TestApplianceLocalConstrainsTLSHostToo(t *testing.T) {
	setOpts(t, func() {
		Opts.MgmtProfile = "appliance-local"
		Opts.TLS = true
		Opts.TLSHost = "10.0.0.5"
	})
	if _, err := MgmtListenPlan(); err == nil {
		t.Error("a reachable TLS bind under appliance-local must be refused")
	}
	setOpts(t, func() {
		Opts.MgmtProfile = "appliance-local"
		Opts.TLS = true
		// The TLS default "0.0.0.0" coerces just like the plaintext one.
	})
	plan, err := MgmtListenPlan()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.HTTPS || plan.TLSHost != "127.0.0.1" {
		t.Errorf("plan = %+v, want coerced loopback TLS listener", plan)
	}
}

// TestRemoteTLSFailsClosed walks every missing precondition separately, so a
// regression in one check cannot hide behind another.
func TestRemoteTLSFailsClosed(t *testing.T) {
	cert, key := certPair(t)
	cases := map[string]struct {
		mutate func()
		want   string
	}{
		"no tls": {func() {
			Opts.MgmtProfile = "remote-tls"
		}, "requires --tls"},
		"missing cert file": {func() {
			Opts.MgmtProfile = "remote-tls"
			Opts.TLS = true
			Opts.TLSCertificate = "/nonexistent/server.crt"
			Opts.TLSCertificateKey = key
			Opts.UserServiceEnable = true
		}, "not readable"},
		"no auth service": {func() {
			Opts.MgmtProfile = "remote-tls"
			Opts.TLS = true
			Opts.TLSCertificate = cert
			Opts.TLSCertificateKey = key
		}, "authentication service"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			setOpts(t, tc.mutate)
			_, err := MgmtListenPlan()
			if err == nil {
				t.Fatal("remote-tls started without its precondition")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the failed precondition %q", err, tc.want)
			}
		})
	}
}

func TestRemoteTLSDisablesPlaintext(t *testing.T) {
	cert, key := certPair(t)
	setOpts(t, func() {
		Opts.MgmtProfile = "remote-tls"
		Opts.TLS = true
		Opts.TLSCertificate = cert
		Opts.TLSCertificateKey = key
		Opts.ManualTokenEnable = true
		Opts.TLSHost = "0.0.0.0"
	})
	plan, err := MgmtListenPlan()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.HTTP || !plan.HTTPS || !plan.Explicit {
		t.Errorf("plan = %+v, want the plaintext listener gone and the TLS one owned", plan)
	}
	if plan.TLSHost != "0.0.0.0" {
		t.Errorf("remote-tls may serve non-loopback; TLSHost rewritten to %q", plan.TLSHost)
	}
}

// --- /metrics authentication ------------------------------------------------
//
// The property under test is a security default, so each case states what an
// operator would have been served, not just which branch ran.

// The default must not change what any existing deployment does. A scraper on
// a legacy or appliance-local gateway sends no bearer and must keep working.
func TestMetricsAuthAutoLeavesNonRemoteProfilesOpen(t *testing.T) {
	for _, profile := range []string{"legacy", "appliance-local"} {
		t.Run(profile, func(t *testing.T) {
			setOpts(t, func() { Opts.MgmtProfile = profile })
			required, err := MetricsAuthPlan()
			if err != nil {
				t.Fatalf("%s must not fail: %v", profile, err)
			}
			if required {
				t.Errorf("%s now demands a bearer on /metrics; every existing "+
					"scrape job on this profile would start returning 401", profile)
			}
		})
	}
}

// The defect #142 reports: remote-tls refuses to start without TLS and without
// an authentication service, then served the full tenant roster, per-tenant
// quota limits and per-tenant consumption to any unauthenticated caller.
func TestMetricsAuthAutoClosesRemoteTLS(t *testing.T) {
	setOpts(t, func() { Opts.MgmtProfile = "remote-tls" })
	required, err := MetricsAuthPlan()
	if err != nil {
		t.Fatalf("remote-tls with the default must not fail: %v", err)
	}
	if !required {
		t.Error("remote-tls still serves /metrics anonymously: the profile " +
			"will not start without an auth service, yet every tenant label " +
			"is readable by anyone who can reach the port")
	}
}

// require is honoured everywhere, including the profiles where auto would not
// have asked for it -- an operator on a shared network must be able to close
// the route without adopting a whole profile.
func TestMetricsAuthRequireAppliesToEveryProfile(t *testing.T) {
	for _, profile := range []string{"legacy", "appliance-local", "remote-tls"} {
		t.Run(profile, func(t *testing.T) {
			setOpts(t, func() {
				Opts.MgmtProfile = profile
				Opts.MetricsAuth = MetricsAuthRequire
			})
			required, err := MetricsAuthPlan()
			if err != nil || !required {
				t.Errorf("require not honoured on %s: required=%v err=%v",
					profile, required, err)
			}
		})
	}
}

// disable is a legitimate answer on the profiles that never promised
// otherwise. It exists so an operator with an external boundary (a scrape-only
// network, a sidecar) can keep the route open deliberately.
func TestMetricsAuthDisableIsAllowedOffRemoteTLS(t *testing.T) {
	for _, profile := range []string{"legacy", "appliance-local"} {
		t.Run(profile, func(t *testing.T) {
			setOpts(t, func() {
				Opts.MgmtProfile = profile
				Opts.MetricsAuth = MetricsAuthDisable
			})
			required, err := MetricsAuthPlan()
			if err != nil {
				t.Fatalf("disable must be allowed on %s: %v", profile, err)
			}
			if required {
				t.Errorf("disable ignored on %s", profile)
			}
		})
	}
}

// The combination the profile forbids. Refused loudly at startup rather than
// silently overridden: an operator who asked for anonymous metrics and got
// authenticated metrics would discover it from a broken scrape job, and one
// who asked and got what they asked for would ship the exposure the profile
// exists to prevent. Neither is acceptable, so the process does not start.
func TestMetricsAuthDisableIsRefusedUnderRemoteTLS(t *testing.T) {
	setOpts(t, func() {
		Opts.MgmtProfile = "remote-tls"
		Opts.MetricsAuth = MetricsAuthDisable
	})
	required, err := MetricsAuthPlan()
	if err == nil {
		t.Fatal("remote-tls accepted --metrics-auth=disable; the profile's own " +
			"guarantee that nothing on this listener is anonymous is broken")
	}
	if required {
		t.Error("a refused configuration must not also report the route as closed")
	}
	// The message has to say what is at stake, or an operator just re-runs
	// with the flag removed and never learns why it was refused.
	for _, want := range []string{"remote-tls", "metrics-auth=disable", "tenant"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
}

// An unparsed or hand-constructed value must fail closed. go-flags' choice
// list refuses unknown values, so this can only be reached by a caller that
// bypassed flag parsing -- exactly the caller that should not get an open
// route by default.
func TestMetricsAuthUnknownValueFailsClosed(t *testing.T) {
	setOpts(t, func() { Opts.MetricsAuth = "yes-please" })
	required, err := MetricsAuthPlan()
	if err == nil {
		t.Fatal("an unknown metrics-auth value was accepted")
	}
	if !required {
		t.Error("an unknown metrics-auth value left /metrics open; the " +
			"fail-closed answer is to require a credential")
	}
}
