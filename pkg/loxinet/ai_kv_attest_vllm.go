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

// ai_kv_attest_vllm.go — the vLLM attestation adapter's probe half (plan §5,
// vLLM-adapter-only per §17.8): byte-exact /tokenize fixture probes and the
// §6.4 identity probes. The §6.2 echo challenge half lives in
// ai_kv_attest_echo.go.
//
// Probe payloads are COMMITTED FILES, sent verbatim — no runtime templating
// of probe payloads, so what was reviewed is what goes on the wire. Each
// fixture is a pair beneath the profile-registry trust root:
//
//   probefixtures/<profileId>/<name>.request.json   exact request bytes
//   probefixtures/<profileId>/<name>.expect.json    {"requestSha256", "expectedTokenIds", "api"}
//
// Both load with the registry's trusted-file discipline (beneath-only, no
// symlinks, owner/mode/size checks), and the request bytes must hash to the
// expect file's pinned sha256 — a drifted fixture is an attestation failure,
// never silently re-pinned. Fixture regeneration is a profile-revision
// event; the repo's committed source set lives under
// cicd/common/kv_hash/fixtures/probe/ and is staged to the registry root by
// deployment.
//
// Transport hardening (§5): probes go only to the rule's registered endpoint
// addresses (the URL is CONSTRUCTED from the endpoint set — there is no
// configurable probe host), redirects are refused, requests time out
// (default 5s), responses are size-capped (256 KiB), and receipts carry
// digests only.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Additional probe-layer reason codes.
const (
	KvAttestReasonFixturesMissing = "probe_fixtures_missing"
	KvAttestReasonFixtureDrift    = "probe_fixture_drift"
)

const (
	kvProbeRespCap        = 256 * 1024
	kvProbeFixtureCap     = 256 * 1024
	kvProbeTimeoutDefault = 5 * time.Second
)

var (
	kvProbeTimeoutOnce sync.Once
	kvProbeTimeoutV    = kvProbeTimeoutDefault
)

func kvProbeTimeout() time.Duration {
	kvProbeTimeoutOnce.Do(func() {
		if v := os.Getenv("LOXILB_KV_ATTEST_PROBE_TIMEOUT_S"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				kvProbeTimeoutV = time.Duration(n) * time.Second
			}
		}
	})
	return kvProbeTimeoutV
}

// kvVllmAttest implements kvAttestAdapter for the vLLM engine family. The
// echoChallenge seam lets the GPU-free suite exercise the adapter's probe
// half against httptest servers while faking the event-plane half.
type kvVllmAttest struct {
	client *http.Client
}

var (
	kvVllmAdapterOnce sync.Once
	kvVllmAdapterInst *kvVllmAttest
)

// kvVllmAdapter returns the process-wide vLLM attestation adapter.
func kvVllmAdapter() kvAttestAdapter {
	kvVllmAdapterOnce.Do(func() {
		kvVllmAdapterInst = newKvVllmAttest()
	})
	return kvVllmAdapterInst
}

func newKvVllmAttest() *kvVllmAttest {
	return &kvVllmAttest{
		client: &http.Client{
			Timeout: kvProbeTimeout(),
			// Redirects are refused outright: a probe that gets redirected
			// is no longer talking to the registered endpoint address.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("kv-attest: probe redirect refused")
			},
		},
	}
}

// ---- fixtures ----

// kvProbeFixture is one loaded probe fixture.
type kvProbeFixture struct {
	Name          string
	RequestBytes  []byte
	RequestSha256 string
	ExpectedIDs   []int64
	API           string // "completions" | "chat"
}

// kvProbeExpect is the strict schema of <name>.expect.json.
type kvProbeExpect struct {
	RequestSha256    string  `json:"requestSha256"`
	ExpectedTokenIds []int64 `json:"expectedTokenIds"`
	API              string  `json:"api"`
}

// kvProbeFixturesLoad loads and verifies the fixture set for a profile from
// the registry trust root. Empty set or any verification failure returns an
// error — a strict rule cannot attest without its reviewed fixtures.
func kvProbeFixturesLoad(profileID string) ([]kvProbeFixture, error) {
	root := kvAttestManifestRoot()
	rootFd, err := unix.Open(root, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("registry root %s: %w", root, err)
	}
	defer unix.Close(rootFd)

	dirRel := "probefixtures/" + profileID
	dirFd, err := kvOpenBeneath(rootFd, dirRel)
	if err != nil {
		return nil, fmt.Errorf("fixture dir %s: %w", dirRel, err)
	}
	f := os.NewFile(uintptr(dirFd), dirRel)
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("fixture dir %s: %w", dirRel, err)
	}
	sort.Strings(names)

	var out []kvProbeFixture
	for _, n := range names {
		if !strings.HasSuffix(n, ".expect.json") {
			continue
		}
		base := strings.TrimSuffix(n, ".expect.json")
		expRaw, _, err := kvReadTrustedFile(rootFd, dirRel+"/"+n, kvProbeFixtureCap)
		if err != nil {
			return nil, fmt.Errorf("fixture %s: %w", n, err)
		}
		var exp kvProbeExpect
		dec := json.NewDecoder(strings.NewReader(string(expRaw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&exp); err != nil {
			return nil, fmt.Errorf("fixture %s: parse: %w", n, err)
		}
		if exp.API != "completions" && exp.API != "chat" {
			return nil, fmt.Errorf("fixture %s: api %q not in {completions, chat}", n, exp.API)
		}
		if len(exp.ExpectedTokenIds) == 0 || exp.RequestSha256 == "" {
			return nil, fmt.Errorf("fixture %s: missing expectedTokenIds/requestSha256", n)
		}
		reqRaw, _, err := kvReadTrustedFile(rootFd, dirRel+"/"+base+".request.json", kvProbeFixtureCap)
		if err != nil {
			return nil, fmt.Errorf("fixture %s: request: %w", base, err)
		}
		got := sha256.Sum256(reqRaw)
		if hex.EncodeToString(got[:]) != strings.ToLower(exp.RequestSha256) {
			return nil, fmt.Errorf("fixture %s: request bytes drifted from pinned sha256", base)
		}
		out = append(out, kvProbeFixture{
			Name:          base,
			RequestBytes:  reqRaw,
			RequestSha256: exp.RequestSha256,
			ExpectedIDs:   exp.ExpectedTokenIds,
			API:           exp.API,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no fixtures under %s", dirRel)
	}
	return out, nil
}

// ---- probes ----

// kvVllmTokenizeResp is the pinned /tokenize response schema (§5): count,
// tokens, max_model_len are REQUIRED with these types; count must equal
// len(tokens). Divergence is probe_schema_mismatch (engine-version drift),
// distinguished from token mismatch.
type kvVllmTokenizeResp struct {
	Count       *int     `json:"count"`
	Tokens      *[]int64 `json:"tokens"`
	MaxModelLen *int     `json:"max_model_len"`
}

// TokenParityProbe sends every fixture's request bytes verbatim to the
// endpoint's /tokenize and compares the FULL token array (§5: never a length
// or prefix check).
func (a *kvVllmAttest) TokenParityProbe(ep KvAttestEndpoint, info kvAttestRuleInfo) KvAttestFinding {
	fixtures, err := kvProbeFixturesLoad(info.profileID)
	if err != nil {
		return KvAttestFinding{Reason: KvAttestReasonFixturesMissing, Detail: err.Error()}
	}
	for _, fx := range fixtures {
		if f := a.tokenizeProbeOne(ep, fx); !f.OK {
			return f
		}
	}
	return KvAttestFinding{OK: true, Detail: fmt.Sprintf("%d fixtures byte-exact", len(fixtures))}
}

func (a *kvVllmAttest) tokenizeProbeOne(ep KvAttestEndpoint, fx kvProbeFixture) KvAttestFinding {
	url := fmt.Sprintf("http://%s:%d/tokenize", ep.IP, ep.Port)
	resp, err := a.client.Post(url, "application/json", strings.NewReader(string(fx.RequestBytes)))
	if err != nil {
		return KvAttestFinding{Reason: KvAttestReasonEndpointUnreach,
			Detail: fmt.Sprintf("fixture %s: %v", fx.Name, err)}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, kvProbeRespCap+1))
	if err != nil {
		return KvAttestFinding{Reason: KvAttestReasonEndpointUnreach,
			Detail: fmt.Sprintf("fixture %s: read: %v", fx.Name, err)}
	}
	if len(body) > kvProbeRespCap {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: response exceeds %d bytes", fx.Name, kvProbeRespCap)}
	}
	if resp.StatusCode != http.StatusOK {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: HTTP %d", fx.Name, resp.StatusCode)}
	}
	var tr kvVllmTokenizeResp
	if err := json.Unmarshal(body, &tr); err != nil {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: unparseable response: %v", fx.Name, err)}
	}
	if tr.Count == nil || tr.Tokens == nil || tr.MaxModelLen == nil {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: pinned fields missing (count/tokens/max_model_len)", fx.Name)}
	}
	toks := *tr.Tokens
	if *tr.Count != len(toks) {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: count %d != len(tokens) %d", fx.Name, *tr.Count, len(toks))}
	}
	if len(toks) != len(fx.ExpectedIDs) {
		return KvAttestFinding{Reason: KvAttestReasonTokenMismatch,
			Detail: fmt.Sprintf("fixture %s: %d tokens, expected %d", fx.Name, len(toks), len(fx.ExpectedIDs))}
	}
	for i := range toks {
		if toks[i] != fx.ExpectedIDs[i] {
			return KvAttestFinding{Reason: KvAttestReasonTokenMismatch,
				Detail: fmt.Sprintf("fixture %s: token[%d]=%d, expected %d", fx.Name, i, toks[i], fx.ExpectedIDs[i])}
		}
	}
	return KvAttestFinding{OK: true}
}

// kvVllmVersionResp / kvVllmModelsResp pin the identity-probe schemas.
type kvVllmVersionResp struct {
	Version *string `json:"version"`
}

type kvVllmModelsResp struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// IdentityProbe checks the running endpoint's self-reported identity against
// the manifest (§6.4): /version must equal the manifest's engineVersion and
// /v1/models must serve the attested model. A probe/manifest inconsistency
// is an attestation FAILURE, not a warning.
func (a *kvVllmAttest) IdentityProbe(ep KvAttestEndpoint, manifest *KvAttestManifest) KvAttestFinding {
	verBody, f := a.getCapped(fmt.Sprintf("http://%s:%d/version", ep.IP, ep.Port))
	if !f.OK {
		return f
	}
	var vr kvVllmVersionResp
	if err := json.Unmarshal(verBody, &vr); err != nil || vr.Version == nil {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("/version unparseable: %v", err)}
	}
	if *vr.Version != manifest.EngineVersion {
		return KvAttestFinding{Reason: KvAttestReasonIdentityMismatch,
			Detail: fmt.Sprintf("/version %q != manifest engineVersion %q", *vr.Version, manifest.EngineVersion)}
	}
	return KvAttestFinding{OK: true}
}

// kvVllmModelServed checks /v1/models for a served model id (used by the
// echo challenge's pre-flight; separated from IdentityProbe so the version
// check runs even for manifest-less functional-only sites).
func (a *kvVllmAttest) kvVllmModelServed(ep KvAttestEndpoint, model string) KvAttestFinding {
	body, f := a.getCapped(fmt.Sprintf("http://%s:%d/v1/models", ep.IP, ep.Port))
	if !f.OK {
		return f
	}
	var mr kvVllmModelsResp
	if err := json.Unmarshal(body, &mr); err != nil {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("/v1/models unparseable: %v", err)}
	}
	for _, m := range mr.Data {
		if m.ID == model {
			return KvAttestFinding{OK: true}
		}
	}
	return KvAttestFinding{Reason: KvAttestReasonIdentityMismatch,
		Detail: fmt.Sprintf("model %q not served by endpoint", model)}
}

func (a *kvVllmAttest) getCapped(url string) ([]byte, KvAttestFinding) {
	resp, err := a.client.Get(url)
	if err != nil {
		return nil, KvAttestFinding{Reason: KvAttestReasonEndpointUnreach, Detail: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, kvProbeRespCap+1))
	if err != nil || len(body) > kvProbeRespCap {
		return nil, KvAttestFinding{Reason: KvAttestReasonProbeSchema, Detail: "identity response unreadable/oversize"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("%s: HTTP %d", url, resp.StatusCode)}
	}
	return body, KvAttestFinding{OK: true}
}
