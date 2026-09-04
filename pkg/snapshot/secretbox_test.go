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

package snapshot

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// testNodeSecret pins a deterministic 32-byte secret for every test that
// touches secret values; withTestNodeSecret installs it and returns the
// restore func.
var testNodeSecret = bytes.Repeat([]byte{0x42}, nodeSecretLen)

func withTestNodeSecret(t *testing.T) func() {
	t.Helper()
	return SetNodeSecretForTest(testNodeSecret)
}

func TestSecretValueDeterministicRoundTrip(t *testing.T) {
	defer withTestNodeSecret(t)()

	a, err := EncryptSecretValue("supersecret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	b, err := EncryptSecretValue("supersecret")
	if err != nil {
		t.Fatalf("encrypt again: %v", err)
	}
	// Determinism is load-bearing (idle-capture identity, digest VERIFY):
	// the same (secret, plaintext) must encode byte-identically.
	if a != b {
		t.Fatalf("ciphertext not deterministic: %q vs %q", a, b)
	}
	if !IsEncryptedSecretValue(a) || strings.Contains(a, "supersecret") {
		t.Fatalf("ciphertext malformed or leaks plaintext: %q", a)
	}
	other, err := EncryptSecretValue("othersecret")
	if err != nil {
		t.Fatalf("encrypt other: %v", err)
	}
	if other == a {
		t.Fatalf("different plaintexts produced identical ciphertext")
	}
	plain, err := DecryptSecretValue(a)
	if err != nil || plain != "supersecret" {
		t.Fatalf("roundtrip: got %q, %v", plain, err)
	}
}

func TestSecretValuePassthroughs(t *testing.T) {
	defer withTestNodeSecret(t)()

	if v, err := EncryptSecretValue(""); err != nil || v != "" {
		t.Fatalf("empty must pass through encrypt: %q, %v", v, err)
	}
	enc, err := EncryptSecretValue("x")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Encrypt is idempotent: an already-encrypted value (intake
	// normalization ran before capture saw it) must not be double-wrapped.
	again, err := EncryptSecretValue(enc)
	if err != nil || again != enc {
		t.Fatalf("already-encrypted must pass through encrypt: %q, %v", again, err)
	}
	// Plaintext passes through decrypt: pre-encryption documents are
	// handled by intake normalization, and apply must still accept them
	// mid-migration.
	if v, err := DecryptSecretValue("plaintext-legacy"); err != nil || v != "plaintext-legacy" {
		t.Fatalf("plaintext must pass through decrypt: %q, %v", v, err)
	}
	if v, err := DecryptSecretValue(""); err != nil || v != "" {
		t.Fatalf("empty must pass through decrypt: %q, %v", v, err)
	}
}

func TestSecretValueWrongSecretFailsClosed(t *testing.T) {
	restore := SetNodeSecretForTest(testNodeSecret)
	enc, err := EncryptSecretValue("supersecret")
	restore()
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	defer SetNodeSecretForTest(bytes.Repeat([]byte{0x7e}, nodeSecretLen))()
	if _, err := DecryptSecretValue(enc); err == nil {
		t.Fatalf("decrypt under a different node secret must fail")
	} else {
		// The error guides the operator (cross-node secret transport) and
		// never includes the value.
		if !strings.Contains(err.Error(), NodeSecretFileName) || strings.Contains(err.Error(), "supersecret") {
			t.Fatalf("error must name the node secret file and never the value: %v", err)
		}
	}
}

func TestSecretValueTamperDetected(t *testing.T) {
	defer withTestNodeSecret(t)()
	enc, err := EncryptSecretValue("supersecret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Flip one character of the base64 payload: AEAD authentication must
	// refuse it.
	body := []byte(enc)
	last := len(body) - 2
	if body[last] == 'A' {
		body[last] = 'B'
	} else {
		body[last] = 'A'
	}
	if _, err := DecryptSecretValue(string(body)); err == nil {
		t.Fatalf("tampered ciphertext must not decrypt")
	}
	if _, err := DecryptSecretValue(secretValuePrefix + "!!!not-base64"); err == nil {
		t.Fatalf("malformed encoding must not decrypt")
	}
}

func TestSecretValueUninitializedFailsClosed(t *testing.T) {
	defer SetNodeSecretForTest(nil)()
	if _, err := EncryptSecretValue("supersecret"); err == nil {
		t.Fatalf("encrypt without an initialized node secret must fail, not fall back to plaintext")
	}
	restore := SetNodeSecretForTest(testNodeSecret)
	enc, err := EncryptSecretValue("supersecret")
	restore()
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptSecretValue(enc); err == nil {
		t.Fatalf("decrypt without an initialized node secret must fail")
	}
}

func TestInitNodeSecretProvisionAndReload(t *testing.T) {
	defer SetNodeSecretForTest(nil)()
	dir := t.TempDir()

	if err := InitNodeSecret(dir); err != nil {
		t.Fatalf("provision: %v", err)
	}
	path := filepath.Join(dir, NodeSecretFileName)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("secret file not provisioned: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("secret file must be 0600, got %o", perm)
	}
	enc1, err := EncryptSecretValue("supersecret")
	if err != nil {
		t.Fatalf("encrypt under provisioned secret: %v", err)
	}

	// A second init (a reboot) must load the SAME secret, not
	// re-provision: existing ciphertexts stay decryptable.
	setNodeSecret(nil)
	if err := InitNodeSecret(dir); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if plain, err := DecryptSecretValue(enc1); err != nil || plain != "supersecret" {
		t.Fatalf("reloaded secret must decrypt prior ciphertext: %q, %v", plain, err)
	}

	// A corrupt secret file is a loud error, never silently
	// re-provisioned (that would strand every encrypted snapshot).
	if err := os.WriteFile(path, []byte("not-hex!"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if err := InitNodeSecret(dir); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt secret file must fail loudly, got %v", err)
	}
}

func TestCaptureNeverEmitsPlaintextSecrets(t *testing.T) {
	// The F-CP-07 core claim: a captured document's canonical bytes never
	// contain a secret value in plaintext.
	defer withTestNodeSecret(t)()
	hooks := newMockHooks()
	hooks.ipsecTunnels = []*cmn.IPsecTunnel{{
		IPsecTunnelMod: cmn.IPsecTunnelMod{Name: "tun1", LocalIP: "1.1.1.1", RemoteIP: "2.2.2.2", AuthMode: "psk", PSK: "plaintext-psk-sentinel"},
	}}
	if _, err := hooks.NetIPsecCertificateAdd(&cmn.IPsecCertificateMod{
		Name: "cert1", CertificatePEM: "CERT-PEM", PrivateKeyPEM: "plaintext-key-sentinel",
	}); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	doc, err := Capture(hooks, "v-test", "host-test", TriggerManual, nil)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	raw, err := Encode(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, sentinel := range []string{"plaintext-psk-sentinel", "plaintext-key-sentinel"} {
		if bytes.Contains(raw, []byte(sentinel)) {
			t.Fatalf("captured document leaks plaintext secret %q", sentinel)
		}
	}
}

func TestCaptureFailsClosedWithoutNodeSecret(t *testing.T) {
	// A node whose secret never initialized must fail the capture, not
	// persist plaintext.
	defer SetNodeSecretForTest(nil)()
	hooks := newMockHooks()
	hooks.ipsecTunnels = []*cmn.IPsecTunnel{{
		IPsecTunnelMod: cmn.IPsecTunnelMod{Name: "tun1", AuthMode: "psk", PSK: "supersecret"},
	}}
	if _, err := Capture(hooks, "v-test", "host-test", TriggerManual, nil); err == nil {
		t.Fatalf("capture with secret values but no node secret must fail closed")
	}
}

func TestRestoreNormalizesInboundPlaintextSecrets(t *testing.T) {
	// A pre-encryption document carrying plaintext secrets restores, is
	// re-encrypted in memory (warned, named item, no value), and the
	// backend still receives plaintext -- the ADR migrate-and-re-encrypt
	// path.
	defer withTestNodeSecret(t)()
	doc := &Document{
		SchemaVersion:   "1.5",
		Kind:            DocKind,
		GatewayVersion:  "v-test",
		Hostname:        "host-test",
		Trigger:         TriggerManual,
		IncludedDomains: []string{DomainIPsec},
	}
	doc.Domains.IPsec = IPsecDomain{
		Tunnels: []*cmn.IPsecTunnel{{
			IPsecTunnelMod: cmn.IPsecTunnelMod{Name: "tun1", LocalIP: "1.1.1.1", RemoteIP: "2.2.2.2", AuthMode: "psk", PSK: "legacy-plain-psk"},
		}},
		Certificates: []cmn.IPsecCertificateMod{{Name: "cert1", CertificatePEM: "P", PrivateKeyPEM: "legacy-plain-key"}},
	}
	raw, err := Encode(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	hooks := newMockHooks()
	eng := NewEngine(hooks, "v-test", "host-test", t.TempDir())
	res, err := eng.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("restore result: %+v", res)
	}
	var sawTun, sawCert bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "legacy-plain-psk") || strings.Contains(w, "legacy-plain-key") {
			t.Fatalf("warning leaks a secret value: %q", w)
		}
		if strings.Contains(w, `tunnel "tun1"`) && strings.Contains(w, "re-encrypted") {
			sawTun = true
		}
		if strings.Contains(w, `certificate "cert1"`) && strings.Contains(w, "re-encrypted") {
			sawCert = true
		}
	}
	if !sawTun || !sawCert {
		t.Fatalf("expected re-encryption warnings for tunnel and certificate, got %v", res.Warnings)
	}
	if len(hooks.ipsecTunnels) != 1 || hooks.ipsecTunnels[0].PSK != "legacy-plain-psk" {
		t.Fatalf("backend must receive the plaintext PSK, got %+v", hooks.ipsecTunnels)
	}
	if len(hooks.ipsecCertMods) != 1 || hooks.ipsecCertMods[0].PrivateKeyPEM != "legacy-plain-key" {
		t.Fatalf("backend must receive the plaintext key, got %+v", hooks.ipsecCertMods)
	}
}

func TestRestoreWrongNodeSecretRefusedPreWipe(t *testing.T) {
	// A document encrypted under a DIFFERENT node's secret is refused at
	// intake, before anything is planned, wiped, or applied -- never
	// discovered mid-apply and paid for with a rollback.
	restore := SetNodeSecretForTest(bytes.Repeat([]byte{0x7e}, nodeSecretLen))
	doc := &Document{
		SchemaVersion:   "1.5",
		Kind:            DocKind,
		GatewayVersion:  "v-test",
		Hostname:        "host-test",
		Trigger:         TriggerManual,
		IncludedDomains: []string{DomainIPsec},
	}
	otherEnc, err := EncryptSecretValue("foreign-psk")
	restore()
	if err != nil {
		t.Fatalf("encrypt under foreign secret: %v", err)
	}
	doc.Domains.IPsec = IPsecDomain{
		Tunnels: []*cmn.IPsecTunnel{{
			IPsecTunnelMod: cmn.IPsecTunnelMod{Name: "tun1", LocalIP: "1.1.1.1", RemoteIP: "2.2.2.2", AuthMode: "psk", PSK: otherEnc},
		}},
	}
	raw, err := Encode(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	defer withTestNodeSecret(t)()
	hooks := newMockHooks()
	// Seed live state a wipe would destroy: the pre-wipe refusal leaves
	// it standing, while a mid-apply decrypt failure would only be
	// reached AFTER the wipe deleted it (and rollback re-added it) --
	// that difference, not just the error text, is what this test pins.
	hooks.ipsecTunnels = []*cmn.IPsecTunnel{{
		IPsecTunnelMod: cmn.IPsecTunnelMod{Name: "live-tun", LocalIP: "9.9.9.9", RemoteIP: "8.8.8.8"},
	}}
	eng := NewEngine(hooks, "v-test", "host-test", t.TempDir())
	res, err := eng.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Result == ResultOK || len(res.Errors) == 0 {
		t.Fatalf("wrong-secret document must be refused, got %+v", res)
	}
	if !strings.Contains(strings.Join(res.Errors, " "), NodeSecretFileName) {
		t.Fatalf("refusal must guide the operator to the node secret file: %v", res.Errors)
	}
	for _, c := range hooks.Calls {
		if strings.Contains(c, "NetIPsecTunnelDel") || strings.Contains(c, "NetIPsecTunnelAdd") {
			t.Fatalf("refusal must happen pre-wipe with zero mutations, saw %q (calls: %v)", c, hooks.Calls)
		}
	}
	if len(hooks.ipsecTunnels) != 1 || hooks.ipsecTunnels[0].Name != "live-tun" {
		t.Fatalf("live state must survive a pre-wipe refusal untouched, got %+v", hooks.ipsecTunnels)
	}
}

func TestRestoreEncryptedDocumentPassesVerify(t *testing.T) {
	// Capture -> restore of an encrypted document must pass the VERIFY
	// digest: getIPsec encrypts deterministically on both the doc side
	// (capture) and the live side (scratch Get), so the digests agree.
	defer withTestNodeSecret(t)()
	hooks := newMockHooks()
	hooks.ipsecTunnels = []*cmn.IPsecTunnel{{
		IPsecTunnelMod: cmn.IPsecTunnelMod{Name: "tun1", LocalIP: "1.1.1.1", RemoteIP: "2.2.2.2", AuthMode: "psk", PSK: "verify-psk"},
	}}
	doc, err := Capture(hooks, "v-test", "host-test", TriggerManual, []string{DomainIPsec})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	raw, err := Encode(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	fresh := newMockHooks()
	eng := NewEngine(fresh, "v-test", "host-test", t.TempDir())
	res, err := eng.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Result != ResultOK || len(res.Errors) > 0 {
		t.Fatalf("encrypted-doc restore must pass VERIFY, got %+v", res)
	}
	if len(fresh.ipsecTunnels) != 1 || fresh.ipsecTunnels[0].PSK != "verify-psk" {
		t.Fatalf("restored backend PSK wrong: %+v", fresh.ipsecTunnels)
	}
}
