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
	t.Cleanup(func() {
		Opts.MgmtProfile, Opts.Host, Opts.TLSHost = profile, host, tlsHost
		Opts.TLS, Opts.TLSCertificate, Opts.TLSCertificateKey = tls, cert, key
		Opts.UserServiceEnable, Opts.Oauth2Enable, Opts.ManualTokenEnable = user, oauth, manual
	})
	Opts.MgmtProfile, Opts.Host, Opts.TLSHost = "legacy", "0.0.0.0", "0.0.0.0"
	Opts.TLS, Opts.TLSCertificate, Opts.TLSCertificateKey = false, "", ""
	Opts.UserServiceEnable, Opts.Oauth2Enable, Opts.ManualTokenEnable = false, false, false
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
