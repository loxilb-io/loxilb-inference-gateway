/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package loxinet

// ai_kv_attest_vllm_test.go — GPU-free §5 probe suite: byte-exact fixture
// probes against httptest endpoints, the pinned response-schema checks
// (probe_schema_mismatch vs token_mismatch distinction), transport
// hardening (redirect refusal, size cap), fixture trust (pinned sha256
// drift), and §6.4 manifest loading.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// kvAttestFixtureRoot publishes a minimal profile registry from root so
// kvAttestManifestRoot() resolves there, then writes one probe fixture pair
// for profileID with the given request body and expected tokens.
func kvAttestFixtureRoot(t *testing.T, profileID, model string) string {
	t.Helper()
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, profileID, model, []byte("{\"model\":\"tok\"}"))
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("registry publish: %v", err)
	}
	return root
}

func kvWriteProbeFixture(t *testing.T, root, profileID, name string, request []byte, tokens []int64) {
	t.Helper()
	dir := filepath.Join(root, "probefixtures", profileID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(request)
	exp := map[string]interface{}{
		"requestSha256":    hex.EncodeToString(sum[:]),
		"expectedTokenIds": tokens,
		"api":              "completions",
	}
	expRaw, _ := json.Marshal(exp)
	if err := os.WriteFile(filepath.Join(dir, name+".request.json"), request, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".expect.json"), expRaw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// kvTestEndpoint converts an httptest server address into a KvAttestEndpoint.
func kvTestEndpoint(t *testing.T, ts *httptest.Server) KvAttestEndpoint {
	t.Helper()
	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	return KvAttestEndpoint{EpIdx: 0, IP: host, Port: uint16(port)}
}

func kvProbeInfo(profileID string) kvAttestRuleInfo {
	return kvAttestRuleInfo{
		svcID: 5, ruleIdent: "rule-5", modelName: "m-probe", engine: "vllm",
		hashAlgo: "sha256_cbor", blockSize: 16, profileID: profileID,
	}
}

func TestKvVllmTokenParityProbeByteExact(t *testing.T) {
	root := kvAttestFixtureRoot(t, "prof-probe", "m-probe")
	reqBody := []byte(`{"model":"m-probe","prompt":"canonical probe","add_special_tokens":false,"return_token_strs":false}`)
	kvWriteProbeFixture(t, root, "prof-probe", "plain", reqBody, []int64{101, 102, 103})

	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tokenize" {
			t.Errorf("probe hit %s, want /tokenize", r.URL.Path)
		}
		gotBody, _ = io.ReadAll(r.Body)
		fmt.Fprint(w, `{"count":3,"tokens":[101,102,103],"max_model_len":4096,"token_strs":null}`)
	}))
	defer ts.Close()

	a := newKvVllmAttest()
	f := a.TokenParityProbe(kvTestEndpoint(t, ts), kvProbeInfo("prof-probe"))
	if !f.OK {
		t.Fatalf("probe failed: %s %s", f.Reason, f.Detail)
	}
	// §5: the request bytes go out VERBATIM — no runtime templating.
	if string(gotBody) != string(reqBody) {
		t.Fatalf("probe body drifted:\n got %s\nwant %s", gotBody, reqBody)
	}
}

func TestKvVllmTokenParityProbeTokenMismatch(t *testing.T) {
	root := kvAttestFixtureRoot(t, "prof-probe", "m-probe")
	kvWriteProbeFixture(t, root, "prof-probe", "plain", []byte(`{"p":1}`), []int64{101, 102, 103})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Full array compare: same length, one token differs.
		fmt.Fprint(w, `{"count":3,"tokens":[101,999,103],"max_model_len":4096}`)
	}))
	defer ts.Close()

	f := newKvVllmAttest().TokenParityProbe(kvTestEndpoint(t, ts), kvProbeInfo("prof-probe"))
	if f.OK || f.Reason != KvAttestReasonTokenMismatch {
		t.Fatalf("finding = %+v, want token_mismatch", f)
	}
}

func TestKvVllmTokenParityProbeSchemaMismatch(t *testing.T) {
	root := kvAttestFixtureRoot(t, "prof-probe", "m-probe")
	kvWriteProbeFixture(t, root, "prof-probe", "plain", []byte(`{"p":1}`), []int64{101})

	cases := []struct{ name, body string }{
		{"missing_max_model_len", `{"count":1,"tokens":[101]}`},
		{"count_len_disagree", `{"count":2,"tokens":[101],"max_model_len":4096}`},
		{"unparseable", `{"count":`},
		{"mistyped_tokens", `{"count":1,"tokens":"101","max_model_len":4096}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tc.body)
			}))
			defer ts.Close()
			f := newKvVllmAttest().TokenParityProbe(kvTestEndpoint(t, ts), kvProbeInfo("prof-probe"))
			if f.OK || f.Reason != KvAttestReasonProbeSchema {
				t.Fatalf("finding = %+v, want probe_schema_mismatch", f)
			}
		})
	}
}

func TestKvVllmProbeRefusesRedirect(t *testing.T) {
	root := kvAttestFixtureRoot(t, "prof-probe", "m-probe")
	kvWriteProbeFixture(t, root, "prof-probe", "plain", []byte(`{"p":1}`), []int64{101})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/tokenize", http.StatusFound)
	}))
	defer ts.Close()

	f := newKvVllmAttest().TokenParityProbe(kvTestEndpoint(t, ts), kvProbeInfo("prof-probe"))
	if f.OK {
		t.Fatalf("redirected probe accepted")
	}
	if !strings.Contains(f.Detail, "redirect refused") {
		t.Fatalf("finding = %+v, want redirect refusal", f)
	}
}

func TestKvVllmProbeResponseSizeCap(t *testing.T) {
	root := kvAttestFixtureRoot(t, "prof-probe", "m-probe")
	kvWriteProbeFixture(t, root, "prof-probe", "plain", []byte(`{"p":1}`), []int64{101})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, kvProbeRespCap+1024))
	}))
	defer ts.Close()

	f := newKvVllmAttest().TokenParityProbe(kvTestEndpoint(t, ts), kvProbeInfo("prof-probe"))
	if f.OK || f.Reason != KvAttestReasonProbeSchema {
		t.Fatalf("finding = %+v, want size-cap schema failure", f)
	}
}

func TestKvVllmFixtureDriftRefused(t *testing.T) {
	root := kvAttestFixtureRoot(t, "prof-probe", "m-probe")
	kvWriteProbeFixture(t, root, "prof-probe", "plain", []byte(`{"p":1}`), []int64{101})
	// Drift the request bytes AFTER the sha256 was pinned.
	reqPath := filepath.Join(root, "probefixtures", "prof-probe", "plain.request.json")
	if err := os.WriteFile(reqPath, []byte(`{"p":2}`), 0o644); err != nil {
		t.Fatal(err)
	}

	f := newKvVllmAttest().TokenParityProbe(KvAttestEndpoint{IP: "127.0.0.1", Port: 1}, kvProbeInfo("prof-probe"))
	if f.OK || f.Reason != KvAttestReasonFixturesMissing {
		t.Fatalf("finding = %+v, want fixture refusal", f)
	}
	if !strings.Contains(f.Detail, "drifted") {
		t.Fatalf("detail %q does not name the drift", f.Detail)
	}
}

func TestKvVllmFixturesMissingRefused(t *testing.T) {
	kvAttestFixtureRoot(t, "prof-probe", "m-probe") // no probefixtures dir
	f := newKvVllmAttest().TokenParityProbe(KvAttestEndpoint{IP: "127.0.0.1", Port: 1}, kvProbeInfo("prof-probe"))
	if f.OK || f.Reason != KvAttestReasonFixturesMissing {
		t.Fatalf("finding = %+v, want probe_fixtures_missing", f)
	}
}

func TestKvVllmIdentityProbe(t *testing.T) {
	manifest := &KvAttestManifest{ProfileID: "prof-probe", ImageDigest: "sha256:x", EngineVersion: "0.27.1"}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"version":"0.27.1"}`)
	}))
	defer ts.Close()
	if f := newKvVllmAttest().IdentityProbe(kvTestEndpoint(t, ts), manifest); !f.OK {
		t.Fatalf("identity probe failed: %+v", f)
	}

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"version":"0.26.0"}`)
	}))
	defer ts2.Close()
	if f := newKvVllmAttest().IdentityProbe(kvTestEndpoint(t, ts2), manifest); f.OK || f.Reason != KvAttestReasonIdentityMismatch {
		t.Fatalf("version drift accepted: %+v", f)
	}
}

// ---- §6.4 manifest loading ----

func kvWriteManifest(t *testing.T, root, profileID, body string) {
	t.Helper()
	dir := filepath.Join(root, "manifests")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, profileID+".yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestKvAttestManifestLoad(t *testing.T) {
	root := kvAttestFixtureRoot(t, "prof-m", "m-x")
	kvWriteManifest(t, root, "prof-m",
		"profileId: prof-m\nimageDigest: sha256:abc\nengineVersion: 0.27.1\nmodelRevision: r1\n")

	m, ok := kvAttestManifestLoad("prof-m")
	if !ok {
		t.Fatalf("manifest load failed")
	}
	if m.EngineVersion != "0.27.1" || m.Digest == "" {
		t.Fatalf("manifest = %+v", m)
	}
}

func TestKvAttestManifestRefusals(t *testing.T) {
	root := kvAttestFixtureRoot(t, "prof-m", "m-x")

	// Missing entirely.
	if _, ok := kvAttestManifestLoad("prof-m"); ok {
		t.Fatalf("absent manifest loaded")
	}
	// Wrong profileId inside the document.
	kvWriteManifest(t, root, "prof-m", "profileId: other\nimageDigest: sha256:a\nengineVersion: v\n")
	if _, ok := kvAttestManifestLoad("prof-m"); ok {
		t.Fatalf("mis-owned manifest loaded")
	}
	// Unknown field = parse error (strict decode).
	kvWriteManifest(t, root, "prof-m", "profileId: prof-m\nimageDigest: sha256:a\nengineVersion: v\nbogus: 1\n")
	if _, ok := kvAttestManifestLoad("prof-m"); ok {
		t.Fatalf("unknown-field manifest loaded")
	}
	// Missing required identity fields.
	kvWriteManifest(t, root, "prof-m", "profileId: prof-m\nengineVersion: v\n")
	if _, ok := kvAttestManifestLoad("prof-m"); ok {
		t.Fatalf("identity-less manifest loaded")
	}
}
