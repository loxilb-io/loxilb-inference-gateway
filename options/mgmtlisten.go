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
	"fmt"
	"net"
	"os"
)

// MgmtListen is the listener plan the management-profile validation produces.
// The API server applies it verbatim; all policy lives here so it can be unit
// tested without linking the datapath.
type MgmtListen struct {
	// Host is the address the plaintext listener binds; meaningful only
	// when HTTP is true.
	Host string
	// TLSHost is the address the TLS listener binds; meaningful only when
	// HTTPS is true.
	TLSHost string
	// HTTP and HTTPS select which listeners may exist at all.
	HTTP  bool
	HTTPS bool
	// Explicit reports whether the profile takes ownership of the enabled
	// listener set. Under the legacy profile it is false and the server
	// keeps its historical behavior untouched, whatever that is.
	Explicit bool
}

// isLoopbackHost accepts only addresses that cannot be reached from another
// machine. Hostnames are not resolved: "localhost" is allowed literally, and
// anything else must parse as a loopback IP — resolving a name here would
// let /etc/hosts decide what "loopback" means.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// coerceLoopback maps the flag default "0.0.0.0" — which cannot be told
// apart from an explicitly passed "0.0.0.0" — to loopback. Any other
// non-loopback value was necessarily typed by an operator and is refused
// rather than silently overridden.
func coerceLoopback(host, flag string) (string, error) {
	if host == "0.0.0.0" {
		return "127.0.0.1", nil
	}
	if !isLoopbackHost(host) {
		return "", fmt.Errorf("mgmt-profile appliance-local requires a loopback %s, got %q: this profile must never expose the management API on a reachable interface", flag, host)
	}
	return host, nil
}

// MgmtListenPlan validates the management-profile and listener options
// together and returns the listener plan. An error here is fatal by design:
// every failure mode below means the operator asked for a profile whose
// security precondition does not hold, and starting anyway would expose an
// interface the profile promises is closed.
func MgmtListenPlan() (MgmtListen, error) {
	switch Opts.MgmtProfile {
	case "", "legacy":
		// The pre-profile behavior, byte for byte. Host may be anything,
		// authentication may be absent, and the enabled-listener set is
		// left to the server's own defaulting.
		return MgmtListen{Host: Opts.Host, TLSHost: Opts.TLSHost, HTTP: true, HTTPS: Opts.TLS}, nil

	case "appliance-local":
		host, err := coerceLoopback(Opts.Host, "--host")
		if err != nil {
			return MgmtListen{}, err
		}
		plan := MgmtListen{Host: host, HTTP: true, Explicit: true}
		if Opts.TLS {
			tlsHost, err := coerceLoopback(Opts.TLSHost, "--tls-host")
			if err != nil {
				return MgmtListen{}, err
			}
			plan.TLSHost = tlsHost
			plan.HTTPS = true
		}
		return plan, nil

	case "remote-tls":
		if !Opts.TLS {
			return MgmtListen{}, fmt.Errorf("mgmt-profile remote-tls requires --tls: a remote management profile never serves plaintext")
		}
		for flag, file := range map[string]string{
			"--tls-certificate": string(Opts.TLSCertificate),
			"--tls-key":         string(Opts.TLSCertificateKey),
		} {
			if file == "" {
				return MgmtListen{}, fmt.Errorf("mgmt-profile remote-tls requires %s", flag)
			}
			if _, err := os.Stat(file); err != nil {
				return MgmtListen{}, fmt.Errorf("mgmt-profile remote-tls: %s %q is not readable: %w", flag, file, err)
			}
		}
		if !Opts.UserServiceEnable && !Opts.Oauth2Enable && !Opts.ManualTokenEnable {
			return MgmtListen{}, fmt.Errorf("mgmt-profile remote-tls requires an authentication service (--userservice, --oauth2 or --manualtoken): without one the API authorizes every caller, which a remote profile must never do")
		}
		return MgmtListen{TLSHost: Opts.TLSHost, HTTPS: true, Explicit: true}, nil
	}
	// go-flags' choice list already refuses unknown values; this is the
	// fail-closed answer for a caller that bypassed flag parsing.
	return MgmtListen{}, fmt.Errorf("unknown mgmt-profile %q", Opts.MgmtProfile)
}
