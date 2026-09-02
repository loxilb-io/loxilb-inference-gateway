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

// ai_kv_attest_sglang_test.go — GPU-free suite for the SGLang attestation
// adapter (§16.5 SGLang row): /get_server_info identity (version + model
// revision read-back), engine-scoped /v1/tokenize fixture probes, the
// geometry preflight (page_size / kv_events port base / dp_size coherence),
// and the DP-rank challenge semantics (per-rank coverage, rank attribution,
// split-echo and undeclared-rank red twins). The engine-neutral echo
// machinery itself is covered by ai_kv_attest_echo_test.go; this file
// reuses its harness (tokenizer/hasher seams, watch await helpers).
//
// NOTE: pkg/loxinet is a CGO package — these tests are AUTHORED here and
// validated on the remote GPU testbed; darwin-local verification is
// structural only (gofmt + grep).

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- harness ----

// kvSglTestConf parameterizes the fake SGLang endpoint.
type kvSglTestConf struct {
	model    string // served_model_name
	version  string
	revision string
	pageSize int
	portBase int
	dpSize   int
	// omitVersion / omitKvEvents serve schema-degraded responses.
	omitVersion  bool
	omitKvEvents bool
	// tokenize response tokens ([]int64) served at /v1/tokenize; nil => 404.
	tokenize []int64
	// completionsStatus for /v1/completions (0 => 200).
	completionsStatus int
	// pdRequireBootstrap mimics a --disaggregation-mode prefill server:
	// /v1/completions without a bootstrap triple is refused 400 before any
	// KV work happens, exactly like the live engine.
	pdRequireBootstrap bool
	// lastCompletionsBody, when non-nil, captures the most recent
	// /v1/completions request body.
	lastCompletionsBody *string
}

// kvSglTestServer serves the pinned SGLang API surface the adapter consumes.
func kvSglTestServer(t *testing.T, conf kvSglTestConf) (*httptest.Server, KvAttestEndpoint, *string) {
	t.Helper()
	lastTokenizePath := new(string)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/get_server_info":
			si := map[string]interface{}{
				"model_path": "org/" + conf.model,
				"revision":   conf.revision,
				"page_size":  conf.pageSize,
				// unconsumed launch-config noise the pinned decoder must
				// tolerate (the real response carries hundreds of fields)
				"mem_fraction_static": 0.8,
				"schedule_policy":     "fcfs",
			}
			if !conf.omitVersion {
				si["version"] = conf.version
			}
			if !conf.omitKvEvents {
				si["kv_events"] = map[string]interface{}{
					"publisher":          "zmq",
					"endpoint_host":      "*",
					"endpoint_port_base": conf.portBase,
					"topic":              "",
					"block_size":         conf.pageSize,
					"dp_size":            conf.dpSize,
				}
			}
			json.NewEncoder(w).Encode(si)
		case "/get_model_info":
			fmt.Fprintf(w, `{"model_path":%q,"served_model_name":%q,"is_generation":true}`,
				"org/"+conf.model, conf.model)
		case "/v1/tokenize":
			*lastTokenizePath = r.URL.Path
			if conf.tokenize == nil {
				w.WriteHeader(404)
				return
			}
			raw, _ := json.Marshal(conf.tokenize)
			fmt.Fprintf(w, `{"tokens":%s,"count":%d,"max_model_len":131072}`, raw, len(conf.tokenize))
		case "/v1/completions":
			body, _ := io.ReadAll(r.Body)
			if conf.lastCompletionsBody != nil {
				*conf.lastCompletionsBody = string(body)
			}
			if conf.pdRequireBootstrap && !strings.Contains(string(body), `"bootstrap_room"`) {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"object":"error","message":"Disaggregated request received without bootstrap room id"}`)
				return
			}
			st := conf.completionsStatus
			if st == 0 {
				st = 200
			}
			w.WriteHeader(st)
			fmt.Fprint(w, `{}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(ts.Close)
	return ts, kvTestEndpoint(t, ts), lastTokenizePath
}

// kvSglTestHasher accepts the SGLang algo (the echo harness fake pins
// sha256_cbor); same deterministic chaining shape.
func kvSglTestHasher(algo string, blockSize uint32, tokens []uint32) ([]uint64, bool) {
	if algo != "sha256_sglang" {
		return nil, false
	}
	nBlocks := len(tokens) / int(blockSize)
	out := make([]uint64, 0, nBlocks)
	var h uint64 = 88172645463325252
	for b := 0; b < nBlocks; b++ {
		for t := 0; t < int(blockSize); t++ {
			h = (h ^ uint64(tokens[b*int(blockSize)+t])) * 1099511628211
		}
		out = append(out, h)
	}
	return out, true
}

func kvSglTestSetup(t *testing.T) {
	t.Helper()
	prevTok := kvChallengeTokenizeFn
	kvChallengeTokenizeFn = kvEchoTestTokenizer
	KvRegisterChallengeHasher(kvSglTestHasher)
	prevTimeout := kvChallengeTimeoutV
	kvChallengeTimeoutV = 2 * time.Second
	t.Cleanup(func() {
		kvChallengeTokenizeFn = prevTok
		KvRegisterChallengeHasher(nil)
		kvChallengeTimeoutV = prevTimeout
	})
}

func kvSglInfo() kvAttestRuleInfo {
	return kvAttestRuleInfo{
		svcID: 41, ruleIdent: "rule-41", modelName: "m-sgl", engine: "sglang",
		hashAlgo: "sha256_sglang", blockSize: kvEchoTestBS, profileID: "prof-sgl",
		apiCompl: true,
	}
}

// kvSglGoodConf returns a server conf coherent with kvSglInfo defaults.
func kvSglGoodConf() kvSglTestConf {
	return kvSglTestConf{
		model: "m-sgl", version: "0.5.18", revision: "c1899de2",
		pageSize: kvEchoTestBS, portBase: kvSglangZmqPortDefault, dpSize: 1,
	}
}

// kvSglFeedRanks feeds successive armed challenges, challenge i answered
// entirely from ranks[i%len(ranks)]. It waits for each fed watch to retire
// before awaiting the next so one challenge is never double-fed.
func kvSglFeedRanks(t *testing.T, svcID uint32, epIdx int, ranks []int, times int) {
	t.Helper()
	go func() {
		var prev *kvHashWatch
		for i := 0; i < times; i++ {
			deadline := time.Now().Add(2 * time.Second)
			var w *kvHashWatch
			for time.Now().Before(deadline) {
				kvHashWatchMu.RLock()
				ws := kvHashWatches[kvHashWatchKey(svcID, epIdx)]
				kvHashWatchMu.RUnlock()
				if len(ws) > 0 && ws[0] != prev {
					w = ws[0]
					break
				}
				time.Sleep(2 * time.Millisecond)
			}
			if w == nil {
				return
			}
			hashes, tokens := kvEchoWatchExpectation(w)
			kvHashWatchObserve(svcID, epIdx, ranks[i%len(ranks)],
				kvEvent{Type: kvEventBlockStored, Hashes: hashes, Tokens: tokens})
			prev = w
		}
	}()
}

// ---- adapter selection ----

func TestKvSglangAdapterSelected(t *testing.T) {
	if kvAttestAdapterFor("sglang") == nil {
		t.Fatal("sglang adapter not selected — rules would hold fenced at adapter_unavailable")
	}
	if kvAttestAdapterFor("trtllm") != nil {
		t.Fatal("trtllm adapter must stay nil until implemented")
	}
}

// ---- identity ----

func TestKvSglangIdentityProbe(t *testing.T) {
	manifest := &KvAttestManifest{EngineVersion: "0.5.18", ModelRevision: "c1899de2"}

	t.Run("green", func(t *testing.T) {
		_, ep, _ := kvSglTestServer(t, kvSglGoodConf())
		if f := newKvSglangAttest().IdentityProbe(ep, manifest); !f.OK {
			t.Fatalf("identity probe failed: %s %s", f.Reason, f.Detail)
		}
	})
	t.Run("version-mismatch", func(t *testing.T) {
		conf := kvSglGoodConf()
		conf.version = "0.5.9"
		_, ep, _ := kvSglTestServer(t, conf)
		f := newKvSglangAttest().IdentityProbe(ep, manifest)
		if f.OK || f.Reason != KvAttestReasonIdentityMismatch {
			t.Fatalf("want identity_mismatch, got OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("revision-mismatch", func(t *testing.T) {
		conf := kvSglGoodConf()
		conf.revision = "deadbeef"
		_, ep, _ := kvSglTestServer(t, conf)
		f := newKvSglangAttest().IdentityProbe(ep, manifest)
		if f.OK || f.Reason != KvAttestReasonIdentityMismatch {
			t.Fatalf("want identity_mismatch on revision, got OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("revision-unpinned-manifest-passes", func(t *testing.T) {
		conf := kvSglGoodConf()
		conf.revision = "anything"
		_, ep, _ := kvSglTestServer(t, conf)
		if f := newKvSglangAttest().IdentityProbe(ep, &KvAttestManifest{EngineVersion: "0.5.18"}); !f.OK {
			t.Fatalf("unpinned revision must not fail identity: %s %s", f.Reason, f.Detail)
		}
	})
	t.Run("version-absent-is-schema-mismatch", func(t *testing.T) {
		conf := kvSglGoodConf()
		conf.omitVersion = true
		_, ep, _ := kvSglTestServer(t, conf)
		f := newKvSglangAttest().IdentityProbe(ep, manifest)
		if f.OK || f.Reason != KvAttestReasonProbeSchema {
			t.Fatalf("want probe_schema_mismatch, got OK=%v %s", f.OK, f.Reason)
		}
	})
}

// ---- token parity (engine-scoped fixtures, /v1/tokenize) ----

// kvWriteSglangProbeFixture writes a fixture pair into the SGLang-scoped
// subdirectory probefixtures/<profileID>/sglang.
func kvWriteSglangProbeFixture(t *testing.T, root, profileID, name string, request []byte, tokens []int64) {
	t.Helper()
	kvWriteProbeFixture(t, root, profileID+"/"+kvSglangFixtureSub, name, request, tokens)
}

func TestKvSglangTokenParityEngineScopedFixtures(t *testing.T) {
	info := kvSglInfo()
	req := []byte(`{"model":"m-sgl","prompt":"parity probe"}`)
	want := []int64{9707, 84648, 4734, 1879} // recon sglang-tokenize-prompt.json

	t.Run("vllm-flat-dir-does-not-satisfy-sglang", func(t *testing.T) {
		root := kvAttestFixtureRoot(t, info.profileID, info.modelName)
		kvWriteProbeFixture(t, root, info.profileID, "basic", req, want)
		conf := kvSglGoodConf()
		conf.tokenize = want
		_, ep, _ := kvSglTestServer(t, conf)
		f := newKvSglangAttest().TokenParityProbe(ep, info)
		if f.OK || f.Reason != KvAttestReasonFixturesMissing {
			t.Fatalf("vLLM flat-dir fixtures must not attest sglang parity: OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("green-on-v1-tokenize", func(t *testing.T) {
		root := kvAttestFixtureRoot(t, info.profileID, info.modelName)
		kvWriteSglangProbeFixture(t, root, info.profileID, "basic", req, want)
		conf := kvSglGoodConf()
		conf.tokenize = want
		_, ep, tokPath := kvSglTestServer(t, conf)
		f := newKvSglangAttest().TokenParityProbe(ep, info)
		if !f.OK {
			t.Fatalf("parity probe failed: %s %s", f.Reason, f.Detail)
		}
		if *tokPath != "/v1/tokenize" {
			t.Fatalf("probe hit %q, want /v1/tokenize", *tokPath)
		}
	})
	t.Run("token-mismatch", func(t *testing.T) {
		root := kvAttestFixtureRoot(t, info.profileID, info.modelName)
		kvWriteSglangProbeFixture(t, root, info.profileID, "basic", req, want)
		conf := kvSglGoodConf()
		conf.tokenize = []int64{9707, 84648, 4734, 9999}
		_, ep, _ := kvSglTestServer(t, conf)
		f := newKvSglangAttest().TokenParityProbe(ep, info)
		if f.OK || f.Reason != KvAttestReasonTokenMismatch {
			t.Fatalf("want token_mismatch, got OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("declared-chat-surface-uncovered-refused", func(t *testing.T) {
		root := kvAttestFixtureRoot(t, info.profileID, info.modelName)
		kvWriteSglangProbeFixture(t, root, info.profileID, "basic", req, want)
		chatInfo := info
		chatInfo.apiChat = true
		conf := kvSglGoodConf()
		conf.tokenize = want
		_, ep, _ := kvSglTestServer(t, conf)
		f := newKvSglangAttest().TokenParityProbe(ep, chatInfo)
		if f.OK || f.Reason != KvAttestReasonFixturesMissing {
			t.Fatalf("chat surface without chat fixtures must refuse: OK=%v %s", f.OK, f.Reason)
		}
	})
}

// ---- geometry preflight ----

func TestKvSglangGeometryCheck(t *testing.T) {
	base := kvSglInfo()
	si := func(conf kvSglTestConf) *kvSglangServerInfo {
		v := &kvSglangServerInfo{Version: &conf.version, Revision: &conf.revision, PageSize: &conf.pageSize}
		if !conf.omitKvEvents {
			pub := "zmq"
			v.KvEvents = &struct {
				Publisher        *string `json:"publisher"`
				EndpointPortBase *int    `json:"endpoint_port_base"`
				DpSize           *int    `json:"dp_size"`
			}{Publisher: &pub, EndpointPortBase: &conf.portBase, DpSize: &conf.dpSize}
		}
		return v
	}

	t.Run("coherent-defaults-pass", func(t *testing.T) {
		if f := kvSglangGeometryCheck(si(kvSglGoodConf()), base); !f.OK {
			t.Fatalf("coherent geometry refused: %s %s", f.Reason, f.Detail)
		}
	})
	t.Run("page-size-mismatch", func(t *testing.T) {
		conf := kvSglGoodConf()
		conf.pageSize = 64
		f := kvSglangGeometryCheck(si(conf), base)
		if f.OK || f.Reason != KvAttestReasonGeometryMismatch || !strings.Contains(f.Detail, "page_size") {
			t.Fatalf("want geometry mismatch on page_size, got OK=%v %s %s", f.OK, f.Reason, f.Detail)
		}
	})
	t.Run("no-event-plane", func(t *testing.T) {
		conf := kvSglGoodConf()
		conf.omitKvEvents = true
		f := kvSglangGeometryCheck(si(conf), base)
		if f.OK || f.Reason != KvAttestReasonGeometryMismatch || !strings.Contains(f.Detail, "kv_events") {
			t.Fatalf("want geometry mismatch on absent kv_events, got OK=%v %s %s", f.OK, f.Reason, f.Detail)
		}
	})
	t.Run("port-base-mismatch", func(t *testing.T) {
		conf := kvSglGoodConf()
		conf.portBase = 6000
		f := kvSglangGeometryCheck(si(conf), base)
		if f.OK || !strings.Contains(f.Detail, "port base") {
			t.Fatalf("want geometry mismatch on port base, got OK=%v %s", f.OK, f.Detail)
		}
	})
	t.Run("declared-zmq-port-honored", func(t *testing.T) {
		conf := kvSglGoodConf()
		conf.portBase = 6000
		declared := base
		declared.zmqPort = 6000
		if f := kvSglangGeometryCheck(si(conf), declared); !f.OK {
			t.Fatalf("declared kvZmqPort must match advertised base: %s %s", f.Reason, f.Detail)
		}
	})
	t.Run("dp-size-mismatch", func(t *testing.T) {
		conf := kvSglGoodConf()
		conf.dpSize = 2
		f := kvSglangGeometryCheck(si(conf), base) // rule declares 0 => 1
		if f.OK || !strings.Contains(f.Detail, "dp_size") {
			t.Fatalf("want geometry mismatch on dp_size, got OK=%v %s", f.OK, f.Detail)
		}
	})
}

// ---- page-hash echo challenge, DP-rank semantics ----

func TestKvSglangHashChallengeSingleRank(t *testing.T) {
	kvSglTestSetup(t)
	info := kvSglInfo()
	_, ep, _ := kvSglTestServer(t, kvSglGoodConf())
	kvSglFeedRanks(t, info.svcID, ep.EpIdx, []int{0}, 1)

	f := newKvSglangAttest().HashChallenge(ep, info)
	if !f.OK {
		t.Fatalf("challenge failed: %s %s", f.Reason, f.Detail)
	}
	if !strings.Contains(f.Detail, "ranks [0]") {
		t.Fatalf("receipt lacks rank attribution: %q", f.Detail)
	}
	kvHashWatchMu.RLock()
	left := len(kvHashWatches[kvHashWatchKey(info.svcID, ep.EpIdx)])
	kvHashWatchMu.RUnlock()
	if left != 0 {
		t.Fatalf("%d watches leaked after challenge", left)
	}
}

func TestKvSglangHashChallengeDpRankCoverage(t *testing.T) {
	kvSglTestSetup(t)
	info := kvSglInfo()
	info.dpRanks = 2
	conf := kvSglGoodConf()
	conf.dpSize = 2
	_, ep, _ := kvSglTestServer(t, conf)
	// Rank 1 answers first, then rank 0: coverage must be order-independent.
	kvSglFeedRanks(t, info.svcID, ep.EpIdx, []int{1, 0}, 2)

	f := newKvSglangAttest().HashChallenge(ep, info)
	if !f.OK {
		t.Fatalf("DP challenge failed: %s %s", f.Reason, f.Detail)
	}
	if !strings.Contains(f.Detail, "2 rank(s)") || !strings.Contains(f.Detail, "ranks [0 1]") {
		t.Fatalf("receipt lacks DP rank attribution: %q", f.Detail)
	}
}

func TestKvSglangHashChallengeRankSplitRefused(t *testing.T) {
	kvSglTestSetup(t)
	info := kvSglInfo()
	info.dpRanks = 2
	conf := kvSglGoodConf()
	conf.dpSize = 2
	_, ep, _ := kvSglTestServer(t, conf)

	// ONE challenge answered from TWO rank streams: hash 0 arrives from
	// rank 0's stream, the rest from rank 1's. A nonce-unique prompt is
	// served by exactly one rank — a split echo is a wiring lie.
	go func() {
		w := kvEchoAwaitWatch(info.svcID, ep.EpIdx)
		if w == nil {
			return
		}
		hashes, tokens := kvEchoWatchExpectation(w)
		kvHashWatchObserve(info.svcID, ep.EpIdx, 0,
			kvEvent{Type: kvEventBlockStored, Hashes: hashes[:1], Tokens: tokens[:kvEchoTestBS]})
		kvHashWatchObserve(info.svcID, ep.EpIdx, 1,
			kvEvent{Type: kvEventBlockStored, Hashes: hashes[1:], Tokens: tokens[kvEchoTestBS:]})
	}()

	f := newKvSglangAttest().HashChallenge(ep, info)
	if f.OK || f.Reason != KvAttestReasonChallengeFailed || !strings.Contains(f.Detail, "rank streams") {
		t.Fatalf("split echo must fail typed: OK=%v %s %s", f.OK, f.Reason, f.Detail)
	}
}

func TestKvSglangHashChallengeUndeclaredRankRefused(t *testing.T) {
	kvSglTestSetup(t)
	info := kvSglInfo() // declares 0 => 1 rank
	_, ep, _ := kvSglTestServer(t, kvSglGoodConf())
	kvSglFeedRanks(t, info.svcID, ep.EpIdx, []int{7}, 1)

	f := newKvSglangAttest().HashChallenge(ep, info)
	if f.OK || f.Reason != KvAttestReasonChallengeFailed || !strings.Contains(f.Detail, "undeclared rank 7") {
		t.Fatalf("undeclared rank must fail typed: OK=%v %s %s", f.OK, f.Reason, f.Detail)
	}
}

func TestKvSglangHashChallengeRankCoverageIncomplete(t *testing.T) {
	kvSglTestSetup(t)
	info := kvSglInfo()
	info.dpRanks = 2
	conf := kvSglGoodConf()
	conf.dpSize = 2
	_, ep, _ := kvSglTestServer(t, conf)
	// Rank 0 answers every challenge; rank 1 never echoes. The bounded
	// attempt budget must exhaust into a typed coverage failure, not hang.
	kvSglFeedRanks(t, info.svcID, ep.EpIdx, []int{0}, 2*kvSglangRankAttemptsPer)

	f := newKvSglangAttest().HashChallenge(ep, info)
	if f.OK || f.Reason != KvAttestReasonChallengeFailed ||
		!strings.Contains(f.Detail, "rank coverage 1/2") || !strings.Contains(f.Detail, "[1]") {
		t.Fatalf("incomplete rank coverage must fail typed: OK=%v %s %s", f.OK, f.Reason, f.Detail)
	}
}

func TestKvSglangHashChallengeGeometryRefusals(t *testing.T) {
	kvSglTestSetup(t)
	info := kvSglInfo()

	t.Run("model-not-served", func(t *testing.T) {
		conf := kvSglGoodConf()
		conf.model = "other-model"
		_, ep, _ := kvSglTestServer(t, conf)
		f := newKvSglangAttest().HashChallenge(ep, info)
		if f.OK || f.Reason != KvAttestReasonIdentityMismatch {
			t.Fatalf("want identity_mismatch, got OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("page-size-drift-refused-before-nonce", func(t *testing.T) {
		conf := kvSglGoodConf()
		conf.pageSize = 64
		_, ep, _ := kvSglTestServer(t, conf)
		f := newKvSglangAttest().HashChallenge(ep, info)
		if f.OK || f.Reason != KvAttestReasonGeometryMismatch {
			t.Fatalf("want engine_geometry_mismatch, got OK=%v %s", f.OK, f.Reason)
		}
	})
	t.Run("dp-advertisement-drift-refused", func(t *testing.T) {
		conf := kvSglGoodConf()
		conf.dpSize = 4
		_, ep, _ := kvSglTestServer(t, conf)
		f := newKvSglangAttest().HashChallenge(ep, info)
		if f.OK || f.Reason != KvAttestReasonGeometryMismatch {
			t.Fatalf("want engine_geometry_mismatch on dp_size, got OK=%v %s", f.OK, f.Reason)
		}
	})
}

// ---- P/D pair challenge (disagg prefill refuses bootstrap-less inference) ----

// kvSglPdInfo is kvSglInfo in P/D shape with one decode counterpart.
func kvSglPdInfo(dep KvAttestEndpoint) kvAttestRuleInfo {
	info := kvSglInfo()
	info.pdMode = true
	info.pdBootstrapPort = 9998
	info.decodeEPs = []KvAttestEndpoint{dep}
	return info
}

// kvSglDecodeMock is a decode-EP stand-in recording every completions body.
func kvSglDecodeMock(t *testing.T, status int) (KvAttestEndpoint, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/completions" {
			w.WriteHeader(404)
			return
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		fmt.Fprint(w, `{}`)
	}))
	t.Cleanup(ts.Close)
	return kvTestEndpoint(t, ts), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

// The challenge against a P/D rule must dispatch as a (prefill, decode)
// pair carrying the bootstrap triple: the prefill mock here refuses
// bootstrap-less bodies with the live engine's 400, so losing the pair
// dispatch turns this red on its own.
func TestKvSglangHashChallengePdPairDispatch(t *testing.T) {
	kvSglTestSetup(t)
	conf := kvSglGoodConf()
	conf.pdRequireBootstrap = true
	prefillBody := ""
	conf.lastCompletionsBody = &prefillBody
	_, ep, _ := kvSglTestServer(t, conf)
	dep, decodeBodies := kvSglDecodeMock(t, 200)

	info := kvSglPdInfo(dep)
	kvSglFeedRanks(t, info.svcID, ep.EpIdx, []int{0}, 1)
	f := newKvSglangAttest().HashChallenge(ep, info)
	if !f.OK {
		t.Fatalf("pd pair challenge refused: %s (%s)", f.Reason, f.Detail)
	}
	for _, want := range []string{`"bootstrap_host":`, `"bootstrap_port":9998`, `"bootstrap_room":`} {
		if !strings.Contains(prefillBody, want) {
			t.Fatalf("prefill challenge body lacks %s: %s", want, prefillBody)
		}
	}
	got := decodeBodies()
	if len(got) != 1 {
		t.Fatalf("decode counterpart saw %d requests, want exactly 1", len(got))
	}
	if got[0] != prefillBody {
		t.Fatalf("decode counterpart body diverges from prefill leg:\n  prefill: %s\n  decode:  %s",
			prefillBody, got[0])
	}
}

// A P/D rule with no decode-role endpoint cannot pair the challenge —
// typed refusal, not a timeout to debug.
func TestKvSglangHashChallengePdNoDecodeEndpoint(t *testing.T) {
	kvSglTestSetup(t)
	conf := kvSglGoodConf()
	conf.pdRequireBootstrap = true
	_, ep, _ := kvSglTestServer(t, conf)

	info := kvSglInfo()
	info.pdMode = true
	f := newKvSglangAttest().HashChallenge(ep, info)
	if f.OK || f.Reason != KvAttestReasonChallengeFailed || !strings.Contains(f.Detail, "decode") {
		t.Fatalf("want typed challenge_failed naming the missing decode counterpart, got OK=%v %s (%s)",
			f.OK, f.Reason, f.Detail)
	}
}

// A decode counterpart that errors fails the challenge typed with the
// counterpart's identity in the detail.
func TestKvSglangHashChallengePdDecodeCounterpartError(t *testing.T) {
	kvSglTestSetup(t)
	conf := kvSglGoodConf()
	conf.pdRequireBootstrap = true
	_, ep, _ := kvSglTestServer(t, conf)
	dep, _ := kvSglDecodeMock(t, 500)

	info := kvSglPdInfo(dep)
	f := newKvSglangAttest().HashChallenge(ep, info)
	if f.OK || f.Reason != KvAttestReasonChallengeFailed || !strings.Contains(f.Detail, "decode counterpart") {
		t.Fatalf("want typed challenge_failed naming the decode counterpart, got OK=%v %s (%s)",
			f.OK, f.Reason, f.Detail)
	}
	if !strings.Contains(f.Detail, "HTTP 500") {
		t.Fatalf("detail must carry the counterpart status: %s", f.Detail)
	}
}

// The converged challenge body must stay bootstrap-free — the pair
// machinery may not leak into single-role rules.
func TestKvSglangHashChallengeConvergedBodyHasNoBootstrap(t *testing.T) {
	kvSglTestSetup(t)
	conf := kvSglGoodConf()
	body := ""
	conf.lastCompletionsBody = &body
	_, ep, _ := kvSglTestServer(t, conf)

	info := kvSglInfo()
	kvSglFeedRanks(t, info.svcID, ep.EpIdx, []int{0}, 1)
	if f := newKvSglangAttest().HashChallenge(ep, info); !f.OK {
		t.Fatalf("converged challenge refused: %s (%s)", f.Reason, f.Detail)
	}
	if strings.Contains(body, "bootstrap_") {
		t.Fatalf("converged challenge body leaks bootstrap fields: %s", body)
	}
}
