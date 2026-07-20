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

// owned by plan 77-07 (residual: certId upload + inline-PEM + PUT rotation)
//
// cert_test.go — RED scaffold (authored by 77-01). These tests exercise the PURE certId
// registry logic that plan 77-07 adds in api/restapi/handler/cert.go (mirroring the l7policy.go family:
// FromModel / serialize / validate + a POST/PUT/DELETE handler set), /11/13:
//   - certId upload round-trips (POST then GET returns the same material/hostnames)
//   - PUT rotates the material under the SAME certId (atomic swap, zero-downtime)
//   - DELETE removes the certId registry entry (and its SNI-store hostnames)
//
// Until 77-07 lands the cmn.CertArg model + certFromModel / validateCert (and the global certStore),
// this file FAILS TO COMPILE — the intended RED. 77-07 turns it GREEN.

package handler

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// okCert returns a minimal valid certId registry entry the tests mutate (11). 77-07 defines
// cmn.CertArg as the canonical TLS-material handle: a short id + inline PEM (cert+key[+chain]); the
// hostnames are auto-derived from the cert SAN/CN on upload, not supplied by the operator.
func okCert() *cmn.CertArg {
	return &cmn.CertArg{
		CertId:  "cert-abc",
		CertPEM: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
	}
}

// TestValidateCertRequiresIdAndMaterial verifies upload validation: a certId and non-empty
// cert+key PEM are required; missing material is rejected. 77-07 implements validateCert.
func TestValidateCertRequiresIdAndMaterial(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(c *cmn.CertArg)
		wantErr bool
	}{
		{"ok", func(c *cmn.CertArg) {}, false},
		{"missing-id", func(c *cmn.CertArg) { c.CertId = "" }, true},
		{"missing-cert-pem", func(c *cmn.CertArg) { c.CertPEM = "" }, true},
		{"missing-key-pem", func(c *cmn.CertArg) { c.KeyPEM = "" }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			arg := okCert()
			c.mutate(arg)
			err := validateCert(arg)
			if (err != nil) != c.wantErr {
				t.Fatalf("validateCert(%s) err=%v, wantErr=%v", c.name, err, c.wantErr)
			}
		})
	}
}

// TestCertUploadRoundTrip encodes /11: an uploaded certId round-trips (POST→GET returns the same
// id + material). 77-07 makes this GREEN by persisting to the certStore + managed dir and reading back.
func TestCertUploadRoundTrip(t *testing.T) {
	arg := okCert()
	_ = arg
	t.Skip("RED scaffold (77-01): certId upload round-trip is implemented by plan 77-07")
}

// TestCertRotationSwapsMaterialSameId encodes : PUT /config/cert/{certId} rotates the material
// under the SAME certId (atomic swap). The id is stable; the material changes. 77-07 makes this GREEN.
func TestCertRotationSwapsMaterialSameId(t *testing.T) {
	arg := okCert()
	_ = arg
	t.Skip("RED scaffold (77-01): certId PUT rotation is implemented by plan 77-07")
}

// TestCertDeleteRemovesEntry encodes the DELETE path: removing a certId drops the registry entry (and
// its SNI-store hostnames). 77-07 makes this GREEN.
func TestCertDeleteRemovesEntry(t *testing.T) {
	arg := okCert()
	_ = arg
	t.Skip("RED scaffold (77-01): certId DELETE is implemented by plan 77-07")
}
