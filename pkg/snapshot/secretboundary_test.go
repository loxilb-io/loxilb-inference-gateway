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

// Secret-boundary sweep: every credential-bearing field a snapshot can
// carry, planted with a sentinel and scanned for in every artifact the
// snapshot machinery writes. secretbox_test.go proves the encryption
// primitive and the capture path for PSKs and private keys; this file
// closes the audited gaps around it: the passphrase field, the
// pre-restore document the PRESERVE stage writes to disk, and — first —
// the proof that the byte scan itself detects planted plaintext, so a
// green sweep can never be a scan that would have missed a leak.

package snapshot

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

const (
	plantedPSK        = "planted-psk-sentinel"
	plantedKey        = "planted-key-sentinel"
	plantedPassphrase = "planted-passphrase-sentinel"
)

// plantSecrets seeds hooks with live IPsec state carrying a sentinel in
// every secret-bearing field the domain exports: the tunnel pre-shared
// key, the certificate private key, and the certificate passphrase.
func plantSecrets(t *testing.T, hooks *mockHooks) {
	t.Helper()
	hooks.ipsecTunnels = []*cmn.IPsecTunnel{{
		IPsecTunnelMod: cmn.IPsecTunnelMod{
			Name: "tun1", LocalIP: "1.1.1.1", RemoteIP: "2.2.2.2",
			AuthMode: "psk", PSK: plantedPSK,
		},
	}}
	if _, err := hooks.NetIPsecCertificateAdd(&cmn.IPsecCertificateMod{
		Name:           "cert1",
		CertificatePEM: "PUBLIC-CERT-PEM",
		PrivateKeyPEM:  plantedKey,
		Passphrase:     plantedPassphrase,
	}); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
}

func scanForSentinels(t *testing.T, what string, raw []byte) {
	t.Helper()
	for _, sentinel := range []string{plantedPSK, plantedKey, plantedPassphrase} {
		if bytes.Contains(raw, []byte(sentinel)) {
			t.Errorf("%s leaks plaintext secret %q", what, sentinel)
		}
	}
}

// TestSecretScanDetectsPlantedPlaintext is the positive control for every
// scan in this file: a document holding the sentinels in plaintext must
// show all three in its encoded bytes. If Encode ever started scrubbing
// or re-encoding secret fields on its own, the capture-side sweeps below
// would go green for the wrong reason — this test pins that a leak, were
// one to happen, is detectable by exactly the scan they use.
func TestSecretScanDetectsPlantedPlaintext(t *testing.T) {
	doc := &Document{
		SchemaVersion:   SchemaVersion,
		Kind:            DocKind,
		GatewayVersion:  "v-test",
		Hostname:        "host-test",
		Trigger:         TriggerManual,
		IncludedDomains: []string{DomainIPsec},
	}
	doc.Domains.IPsec = IPsecDomain{
		Tunnels: []*cmn.IPsecTunnel{{
			IPsecTunnelMod: cmn.IPsecTunnelMod{Name: "tun1", AuthMode: "psk", PSK: plantedPSK},
		}},
		Certificates: []cmn.IPsecCertificateMod{{
			Name: "cert1", CertificatePEM: "P",
			PrivateKeyPEM: plantedKey, Passphrase: plantedPassphrase,
		}},
	}
	raw, err := Encode(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, sentinel := range []string{plantedPSK, plantedKey, plantedPassphrase} {
		if !bytes.Contains(raw, []byte(sentinel)) {
			t.Fatalf("scan control: sentinel %q not visible in a deliberately plaintext document — the leak scan cannot be trusted", sentinel)
		}
	}
}

// TestCaptureEncryptsEverySecretField extends the capture sweep to the
// passphrase (previously untested) and, beyond absence-of-plaintext,
// asserts each field actually holds a decryptable ciphertext: a field
// that was dropped or blanked would also pass a pure absence scan, and a
// blanked passphrase is a restore that cannot open its own key.
func TestCaptureEncryptsEverySecretField(t *testing.T) {
	defer withTestNodeSecret(t)()
	hooks := newMockHooks()
	plantSecrets(t, hooks)

	doc, err := Capture(hooks, "v-test", "host-test", TriggerManual, nil)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	raw, err := Encode(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	scanForSentinels(t, "captured document", raw)

	cert := doc.Domains.IPsec.Certificates[0]
	for name, got := range map[string]struct{ enc, want string }{
		"tunnel PSK":             {doc.Domains.IPsec.Tunnels[0].PSK, plantedPSK},
		"certificate key":        {cert.PrivateKeyPEM, plantedKey},
		"certificate passphrase": {cert.Passphrase, plantedPassphrase},
	} {
		if !strings.HasPrefix(got.enc, "enc:v1:") {
			t.Fatalf("%s not stored as ciphertext: %q", name, got.enc)
		}
		plain, err := DecryptSecretValue(got.enc)
		if err != nil {
			t.Fatalf("%s does not decrypt: %v", name, err)
		}
		if plain != got.want {
			t.Fatalf("%s decrypts to %q, want the planted value", name, plain)
		}
	}
	if cert.CertificatePEM != "PUBLIC-CERT-PEM" {
		t.Fatalf("public certificate body must ride as-is, got %q", cert.CertificatePEM)
	}
}

// TestPreRestoreFileNeverEmitsPlaintextSecrets covers the one snapshot
// artifact the earlier sweeps do not: the pre-restore document the
// PRESERVE stage writes to disk before a commit restore mutates anything.
// It is produced from live state on a different code path trigger than an
// operator capture, and it lands on disk unconditionally — a leak there
// would put credentials in a file no operator asked for.
func TestPreRestoreFileNeverEmitsPlaintextSecrets(t *testing.T) {
	defer withTestNodeSecret(t)()
	hooks := newMockHooks()
	plantSecrets(t, hooks)

	// Restore an empty ipsec document: the PRESERVE stage must first
	// capture the planted live state into the pre-restore file.
	doc := &Document{
		SchemaVersion:   SchemaVersion,
		Kind:            DocKind,
		GatewayVersion:  "v-test",
		Hostname:        "host-test",
		Trigger:         TriggerManual,
		IncludedDomains: []string{DomainIPsec},
	}
	raw, err := Encode(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	preDir := t.TempDir()
	eng := NewEngine(hooks, "v-test", "host-test", preDir)
	res, err := eng.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("restore result: %+v", res)
	}

	matches, err := filepath.Glob(filepath.Join(preDir, "pre-restore-*.json"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no pre-restore document written (err=%v); this test must fail rather than pass on a missing artifact", err)
	}
	for _, path := range matches {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		scanForSentinels(t, "pre-restore document "+filepath.Base(path), got)
		if !bytes.Contains(got, []byte("enc:v1:")) {
			t.Fatalf("pre-restore document %s carries no ciphertext at all — the planted secrets were dropped, not protected", filepath.Base(path))
		}
	}
}
