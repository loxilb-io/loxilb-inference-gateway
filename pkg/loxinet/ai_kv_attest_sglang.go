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

// ai_kv_attest_sglang.go — the SGLang attestation adapter (plan §16.5
// SGLang row). The candidate tuple provides /v1/tokenize + /v1/detokenize,
// so token parity takes the direct TOKEN_PARITY_VERIFIED path — the
// approved-oracle fallback is only for tuples without the route and is NOT
// implemented here (a tuple lacking the route holds fenced, fail-closed).
//
// Identity comes from /get_server_info: SGLang serves no /version route.
// The same response also self-describes the geometry the challenge depends
// on — page_size, and the kv_events advertisement {endpoint_port_base,
// dp_size} — so the challenge preflight cross-checks all of it against the
// rule's declared kvBlockSize/kvZmqPort/kvDpRankCount before any nonce is
// spent (DP-rank/port coherence, plan §16.4/§16.5). A disagreement is a
// typed engine_geometry_mismatch, never a challenge timeout to debug.
//
// The page-hash echo challenge reuses the engine-neutral §6.2 machinery
// (ai_kv_attest_echo.go): the expected chain is computed by the SAME
// implementation the data plane scores with, through the registered hasher
// seam with the rule's effective algo (sha256_sglang: parent digest ‖ LE32
// token IDs, FIRST-8 truncation, NO seed — seed agreement is not attested
// because no seed exists in the contract). DP>1: every advertised rank must
// echo a challenge of its own; receipts carry rank attribution, and one
// challenge answered from more than one rank stream fails typed (a
// nonce-unique prompt is served by exactly one rank — a split echo means
// the union inventory is being fed by streams that do not belong to the
// ranks they claim). The socket-rank == payload-rank wire check itself
// lives in the subscriber (KvWireReasonRankMismatch).
//
// Fixture discipline is shared with the vLLM adapter (committed files, sent
// verbatim, pinned by sha256) with one addition: SGLang fixture sets live
// in the engine-scoped subdirectory probefixtures/<profileId>/sglang, so
// one profile reused by Rules on different engine contracts (§16.9) never
// cross-loads another engine's probe payloads.

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// KvAttestReasonGeometryMismatch types a challenge-preflight failure where
// the engine's self-described geometry (page size, kv-events port base, DP
// rank count) disagrees with the rule's declaration.
const KvAttestReasonGeometryMismatch = "engine_geometry_mismatch"

const (
	kvSglangZmqPortDefault       = 5557
	kvSglangFixtureSub           = "sglang"
	kvSglangRankAttemptsPer      = 4 // challenge attempts budgeted per advertised rank
	kvSglangBootstrapPortDefault = 8998
)

// kvSglangChallengeRoom draws a bootstrap room id in the engine's accepted
// range [0, 2^63-1] (see sockproxy_pd_sglang.c: the datapath's rooms share it).
func kvSglangChallengeRoom() (int64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(b[:]) &^ (1 << 63)), nil
}

// kvSglangAttest implements kvAttestAdapter for the SGLang engine family.
type kvSglangAttest struct {
	client *http.Client
}

var (
	kvSglangAdapterOnce sync.Once
	kvSglangAdapterInst *kvSglangAttest
)

// kvSglangAdapter returns the process-wide SGLang attestation adapter.
func kvSglangAdapter() kvAttestAdapter {
	kvSglangAdapterOnce.Do(func() {
		kvSglangAdapterInst = newKvSglangAttest()
	})
	return kvSglangAdapterInst
}

func newKvSglangAttest() *kvSglangAttest {
	return &kvSglangAttest{
		client: &http.Client{
			Timeout: kvProbeTimeout(),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("kv-attest: probe redirect refused")
			},
		},
	}
}

// ---- identity / geometry ----

// kvSglangServerInfo pins the /get_server_info fields the adapter consumes.
// The response carries hundreds of launch-config fields; only these are
// contract-bearing, and each required one is a pointer so absence is a
// schema mismatch, not a zero value.
type kvSglangServerInfo struct {
	Version  *string `json:"version"`
	Revision *string `json:"revision"`
	PageSize *int    `json:"page_size"`
	KvEvents *struct {
		Publisher        *string `json:"publisher"`
		EndpointPortBase *int    `json:"endpoint_port_base"`
		DpSize           *int    `json:"dp_size"`
	} `json:"kv_events"`
}

// kvSglangModelInfo pins the /get_model_info fields used for the
// served-model check.
type kvSglangModelInfo struct {
	ModelPath       *string `json:"model_path"`
	ServedModelName *string `json:"served_model_name"`
}

func (a *kvSglangAttest) serverInfo(ep KvAttestEndpoint) (*kvSglangServerInfo, KvAttestFinding) {
	body, f := kvAttestGetCapped(a.client, fmt.Sprintf("http://%s:%d/get_server_info", ep.IP, ep.Port))
	if !f.OK {
		return nil, f
	}
	var si kvSglangServerInfo
	if err := json.Unmarshal(body, &si); err != nil {
		return nil, KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("/get_server_info unparseable: %v", err)}
	}
	if si.Version == nil {
		return nil, KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: "/get_server_info carries no version field"}
	}
	return &si, KvAttestFinding{OK: true}
}

// IdentityProbe checks the running endpoint's self-reported identity against
// the manifest (§6.4). SGLang serves no /version route; engine version and
// the pinned model revision both come from /get_server_info. A
// probe/manifest inconsistency is an attestation FAILURE, not a warning.
func (a *kvSglangAttest) IdentityProbe(ep KvAttestEndpoint, manifest *KvAttestManifest) KvAttestFinding {
	si, f := a.serverInfo(ep)
	if !f.OK {
		return f
	}
	if *si.Version != manifest.EngineVersion {
		return KvAttestFinding{Reason: KvAttestReasonIdentityMismatch,
			Detail: fmt.Sprintf("/get_server_info version %q != manifest engineVersion %q",
				*si.Version, manifest.EngineVersion)}
	}
	// SGLang self-reports the resolved model revision — when the manifest
	// pins one, a running snapshot from any other revision fails identity
	// (the vLLM adapter has no equivalent read-back; here it is free).
	if manifest.ModelRevision != "" {
		if si.Revision == nil || *si.Revision != manifest.ModelRevision {
			got := "<absent>"
			if si.Revision != nil {
				got = *si.Revision
			}
			return KvAttestFinding{Reason: KvAttestReasonIdentityMismatch,
				Detail: fmt.Sprintf("/get_server_info revision %q != manifest modelRevision %q",
					got, manifest.ModelRevision)}
		}
	}
	return KvAttestFinding{OK: true}
}

// kvSglangModelServed checks /get_model_info for the attested model. SGLang
// exposes both the model path and the served alias; the rule's modelName
// must match one of them (the alias is what /v1/models advertises and what
// clients address; the path is the identity the alias resolves to).
func (a *kvSglangAttest) kvSglangModelServed(ep KvAttestEndpoint, model string) KvAttestFinding {
	body, f := kvAttestGetCapped(a.client, fmt.Sprintf("http://%s:%d/get_model_info", ep.IP, ep.Port))
	if !f.OK {
		return f
	}
	var mi kvSglangModelInfo
	if err := json.Unmarshal(body, &mi); err != nil {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("/get_model_info unparseable: %v", err)}
	}
	if (mi.ServedModelName != nil && *mi.ServedModelName == model) ||
		(mi.ModelPath != nil && *mi.ModelPath == model) {
		return KvAttestFinding{OK: true}
	}
	return KvAttestFinding{Reason: KvAttestReasonIdentityMismatch,
		Detail: fmt.Sprintf("model %q not served by endpoint", model)}
}

// kvSglangGeometryCheck cross-checks the engine's self-described geometry
// against the rule declaration before a challenge is issued.
func kvSglangGeometryCheck(si *kvSglangServerInfo, info kvAttestRuleInfo) KvAttestFinding {
	wantBlock := info.blockSize
	if wantBlock == 0 {
		wantBlock = 16
	}
	if si.PageSize == nil || uint32(*si.PageSize) != wantBlock {
		got := -1
		if si.PageSize != nil {
			got = *si.PageSize
		}
		return KvAttestFinding{Reason: KvAttestReasonGeometryMismatch,
			Detail: fmt.Sprintf("engine page_size %d != rule kvBlockSize %d", got, wantBlock)}
	}
	if si.KvEvents == nil {
		return KvAttestFinding{Reason: KvAttestReasonGeometryMismatch,
			Detail: "engine advertises no kv_events publisher (--kv-events-config absent) — no event plane to attest"}
	}
	wantPort := int(info.zmqPort)
	if wantPort == 0 {
		wantPort = kvSglangZmqPortDefault
	}
	if si.KvEvents.EndpointPortBase == nil || *si.KvEvents.EndpointPortBase != wantPort {
		got := -1
		if si.KvEvents.EndpointPortBase != nil {
			got = *si.KvEvents.EndpointPortBase
		}
		return KvAttestFinding{Reason: KvAttestReasonGeometryMismatch,
			Detail: fmt.Sprintf("engine kv_events port base %d != rule kvZmqPort %d", got, wantPort)}
	}
	wantRanks := int(info.dpRanks)
	if wantRanks == 0 {
		wantRanks = 1
	}
	if si.KvEvents.DpSize == nil || *si.KvEvents.DpSize != wantRanks {
		got := -1
		if si.KvEvents.DpSize != nil {
			got = *si.KvEvents.DpSize
		}
		return KvAttestFinding{Reason: KvAttestReasonGeometryMismatch,
			Detail: fmt.Sprintf("engine kv_events dp_size %d != rule kvDpRankCount %d", got, wantRanks)}
	}
	return KvAttestFinding{OK: true}
}

// ---- token parity (§5, direct path) ----

// TokenParityProbe sends every committed SGLang fixture's request bytes
// verbatim to the endpoint's /v1/tokenize and compares the FULL token array.
// The response schema is the same pinned {count, tokens, max_model_len}
// triple the vLLM route serves (recon-verified on the candidate tuple).
func (a *kvSglangAttest) TokenParityProbe(ep KvAttestEndpoint, info kvAttestRuleInfo) KvAttestFinding {
	fixtures, err := kvProbeFixturesLoadDir("probefixtures/" + info.profileID + "/" + kvSglangFixtureSub)
	if err != nil {
		return KvAttestFinding{Reason: KvAttestReasonFixturesMissing, Detail: err.Error()}
	}
	if f := kvFixtureSurfaceCheck(fixtures, info); !f.OK {
		return f
	}
	url := fmt.Sprintf("http://%s:%d/v1/tokenize", ep.IP, ep.Port)
	for _, fx := range fixtures {
		if f := kvTokenizeFixtureProbe(a.client, url, fx); !f.OK {
			return f
		}
	}
	return KvAttestFinding{OK: true, Detail: fmt.Sprintf("%d fixtures byte-exact", len(fixtures))}
}

// ---- page-hash echo challenge (§6.2 machinery, §16.5 SGLang semantics) ----

// HashChallenge runs the page-hash echo against one endpoint. With DP>1 it
// keeps issuing nonce-unique challenges until every advertised rank has
// echoed one (rank attribution), within a bounded attempt budget.
func (a *kvSglangAttest) HashChallenge(ep KvAttestEndpoint, info kvAttestRuleInfo) KvAttestFinding {
	si, f := a.serverInfo(ep)
	if !f.OK {
		return f
	}
	if f := kvSglangGeometryCheck(si, info); !f.OK {
		return f
	}
	if f := a.kvSglangModelServed(ep, info.modelName); !f.OK {
		return f
	}
	hasher := kvChallengeHasherGet()
	if hasher == nil {
		return KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
			Detail: "no challenge hasher registered (datapath not initialized)"}
	}

	ranks := int(info.dpRanks)
	if ranks == 0 {
		ranks = 1
	}
	blockSize := info.blockSize
	if blockSize == 0 {
		blockSize = 16
	}

	echoed := make(map[int]bool, ranks)
	attempts := 0
	maxAttempts := ranks * kvSglangRankAttemptsPer
	for len(echoed) < ranks && attempts < maxAttempts {
		attempts++
		gotRanks, f := a.challengeOnce(ep, info, hasher, blockSize)
		if !f.OK {
			return f
		}
		for _, r := range gotRanks {
			if r < 0 || r >= ranks {
				return KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
					Detail: fmt.Sprintf("challenge echoed from undeclared rank %d (rule declares %d ranks)", r, ranks)}
			}
			echoed[r] = true
		}
	}
	if len(echoed) < ranks {
		return KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
			Detail: fmt.Sprintf("rank coverage %d/%d after %d challenges (missing ranks %v)",
				len(echoed), ranks, attempts, kvSglangMissingRanks(echoed, ranks))}
	}
	// Rank attribution belongs in the operator log too: receipts hold it,
	// but a live DP fleet being debugged needs the coverage visible without
	// correlating receipt digests (one line per successful challenge round).
	log.Infof("kv-attest: sglang echo ep %s: %d rank(s) echoed over %d challenge(s) (ranks %v)",
		ep.ID(), ranks, attempts, kvSglangSortedRanks(echoed))
	return KvAttestFinding{OK: true,
		Detail: fmt.Sprintf("%d rank(s) echoed over %d challenge(s) (ranks %v)",
			ranks, attempts, kvSglangSortedRanks(echoed))}
}

// challengeOnce issues one nonce-unique challenge and returns the rank
// attribution of its echo. One challenge answered from more than one rank
// stream fails typed (see file header).
func (a *kvSglangAttest) challengeOnce(ep KvAttestEndpoint, info kvAttestRuleInfo,
	hasher kvChallengeHasher, blockSize uint32) ([]int, KvAttestFinding) {

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, KvAttestFinding{Reason: KvAttestReasonChallengeFailed, Detail: "nonce: " + err.Error()}
	}
	nonceHex := hex.EncodeToString(nonce[:])

	prompt, wantTokens, err := kvChallengeBuildPrompt(info.modelName, nonceHex, blockSize)
	if err != nil {
		return nil, KvAttestFinding{Reason: KvAttestReasonChallengeFailed, Detail: err.Error()}
	}
	expected, ok := hasher(info.hashAlgo, blockSize, wantTokens)
	if !ok || len(expected) < 2 {
		return nil, KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
			Detail: fmt.Sprintf("expected-chain computation failed (algo=%s, %d hashes)", info.hashAlgo, len(expected))}
	}

	w := kvHashWatchRegister(info.svcID, ep.EpIdx, expected, wantTokens, blockSize)
	defer kvHashWatchUnregister(w)

	url := fmt.Sprintf("http://%s:%d/v1/completions", ep.IP, ep.Port)
	reqBody := fmt.Sprintf(`{"model":%q,"prompt":%q,"max_tokens":1,"temperature":0}`,
		info.modelName, prompt)
	var decodeDone chan KvAttestFinding
	if info.pdMode {
		// A disaggregation-mode prefill refuses bootstrap-less inference
		// outright, so the challenge dispatches as a (prefill, decode) pair
		// carrying the same bootstrap triple the datapath injects
		// (sockproxy_pd_sglang.c). The verdict still comes from the prefill's
		// event plane; the decode leg exists so the prefill's transfer
		// rendezvous completes instead of holding the room open to timeout.
		if len(info.decodeEPs) == 0 {
			return nil, KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
				Detail: "P/D rule has no decode endpoint to pair the challenge with"}
		}
		room, rErr := kvSglangChallengeRoom()
		if rErr != nil {
			return nil, KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
				Detail: "bootstrap room: " + rErr.Error()}
		}
		bootPort := info.pdBootstrapPort
		if bootPort == 0 {
			bootPort = kvSglangBootstrapPortDefault
		}
		reqBody = fmt.Sprintf(`{"model":%q,"prompt":%q,"max_tokens":1,"temperature":0,"bootstrap_host":%q,"bootstrap_port":%d,"bootstrap_room":%d}`,
			info.modelName, prompt, ep.IP, bootPort, room)
		dep := info.decodeEPs[0]
		durl := fmt.Sprintf("http://%s:%d/v1/completions", dep.IP, dep.Port)
		decodeDone = make(chan KvAttestFinding, 1)
		go func(body, id string) {
			dResp, dErr := a.client.Post(durl, "application/json", strings.NewReader(body))
			if dErr != nil {
				decodeDone <- KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
					Detail: fmt.Sprintf("decode counterpart %s: %v", id, dErr)}
				return
			}
			dResp.Body.Close()
			if dResp.StatusCode != http.StatusOK {
				decodeDone <- KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
					Detail: fmt.Sprintf("decode counterpart %s HTTP %d", id, dResp.StatusCode)}
				return
			}
			decodeDone <- KvAttestFinding{OK: true}
		}(reqBody, dep.ID())
	}
	resp, err := a.client.Post(url, "application/json", strings.NewReader(reqBody))
	if err != nil {
		return nil, KvAttestFinding{Reason: KvAttestReasonEndpointUnreach,
			Detail: "challenge inference: " + err.Error()}
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
			Detail: fmt.Sprintf("challenge inference HTTP %d", resp.StatusCode)}
	}
	if decodeDone != nil {
		if df := <-decodeDone; !df.OK {
			return nil, df
		}
	}

	select {
	case <-w.done:
		if reason, detail := w.result(); reason != "" {
			return nil, KvAttestFinding{Reason: reason, Detail: detail}
		}
		gotRanks := w.ranksEchoed()
		if len(gotRanks) != 1 {
			return nil, KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
				Detail: fmt.Sprintf("challenge %s echoed from %d rank streams %v — a nonce-unique prompt is served by exactly one rank",
					nonceHex[:8], len(gotRanks), gotRanks)}
		}
		return gotRanks, KvAttestFinding{OK: true}
	case <-time.After(kvChallengeTimeout()):
		return nil, KvAttestFinding{Reason: KvAttestReasonChallengeTimeout,
			Detail: fmt.Sprintf("expected hashes not observed within %v", kvChallengeTimeout())}
	}
}

func kvSglangMissingRanks(echoed map[int]bool, ranks int) []int {
	var out []int
	for r := 0; r < ranks; r++ {
		if !echoed[r] {
			out = append(out, r)
		}
	}
	return out
}

func kvSglangSortedRanks(echoed map[int]bool) []int {
	out := make([]int, 0, len(echoed))
	for r := range echoed {
		out = append(out, r)
	}
	sort.Ints(out)
	return out
}
