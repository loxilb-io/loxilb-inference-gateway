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

// ai_kv_attest_echo.go — the §6.2 nonce-unique block-hash echo challenge
// (vLLM adapter half; the state machine that consumes it is engine-neutral).
//
// Correlation is deterministic by construction: the challenge prompt embeds
// a fresh 128-bit nonce in its FIRST block, so — hashes chaining — every
// block hash of every challenge is globally unique: never prefix-cached
// (the engine MUST store fresh blocks and publish events), never colliding
// with production traffic or a concurrent challenge. The gateway computes
// its own expected hash chain FIRST (profile-bound tokenize → the SAME
// C hash implementation the data plane scores with, via the registered
// hasher seam), registers the expected set with the endpoint's subscriber
// stream, and only then issues the 1-token inference. Either the exact
// expected hashes appear in that endpoint's BlockStored events within the
// timeout — with matching token_ids and empty extra_keys/lora (verifying
// extraKeyPolicy none_p0 on the wire) — or the endpoint fails attestation.
// No time-window or token-sequence joining exists anywhere in this path.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	tk "github.com/loxilb-io/loxilib"
)

// ---- challenge hasher seam ----

// kvChallengeHasher computes the expected chained block hashes for a token
// sequence — REQUIRED to be the same implementation the data plane scores
// with (production registers a CGO wrapper over kv_compute_block_hashes at
// datapath init; tests register fakes or the fixture-pinned reference).
// Returns the uint64 inventory forms (big-endian first 8 digest bytes, the
// cBlockHashesToUint64 rule) of every FULL block's hash.
type kvChallengeHasher func(hashAlgo string, blockSize uint32, tokens []uint32) ([]uint64, bool)

var (
	kvChallengeHasherMu sync.RWMutex
	kvChallengeHasherFn kvChallengeHasher
)

// KvRegisterChallengeHasher installs the challenge hasher (datapath init).
func KvRegisterChallengeHasher(fn kvChallengeHasher) {
	kvChallengeHasherMu.Lock()
	kvChallengeHasherFn = fn
	kvChallengeHasherMu.Unlock()
}

func kvChallengeHasherGet() kvChallengeHasher {
	kvChallengeHasherMu.RLock()
	defer kvChallengeHasherMu.RUnlock()
	return kvChallengeHasherFn
}

// ---- expected-hash watch registry (subscriber-side seam) ----

// kvHashWatch is one armed challenge: the expected hash set for one
// (service, endpoint) pair, resolved by the subscriber loop as BlockStored
// events arrive.
type kvHashWatch struct {
	svcID     uint32
	epIdx     int
	blockSize uint32

	mu        sync.Mutex
	hashIndex map[uint64]int // expected hash -> block index in wantTokens
	pending   int
	// wantTokens is the gateway's own tokenization of the challenge prompt
	// (full blocks only), for the §6.2 token_id cross-check.
	wantTokens []uint32
	failReason string
	failDetail string

	done chan struct{}
}

var (
	kvHashWatchMu sync.RWMutex
	kvHashWatches = make(map[uint64][]*kvHashWatch) // (svcID<<32|epIdx) -> watches
)

func kvHashWatchKey(svcID uint32, epIdx int) uint64 {
	return uint64(svcID)<<32 | uint64(uint32(epIdx))
}

// kvHashWatchRegister arms a watch for the expected hash chain.
func kvHashWatchRegister(svcID uint32, epIdx int, expected []uint64,
	wantTokens []uint32, blockSize uint32) *kvHashWatch {
	w := &kvHashWatch{
		svcID:      svcID,
		epIdx:      epIdx,
		blockSize:  blockSize,
		hashIndex:  make(map[uint64]int, len(expected)),
		pending:    len(expected),
		wantTokens: wantTokens,
		done:       make(chan struct{}),
	}
	for i, h := range expected {
		w.hashIndex[h] = i
	}
	k := kvHashWatchKey(svcID, epIdx)
	kvHashWatchMu.Lock()
	kvHashWatches[k] = append(kvHashWatches[k], w)
	kvHashWatchMu.Unlock()
	return w
}

// kvHashWatchUnregister retires a watch (each challenge's nonce retires its
// hash registration — §6.2).
func kvHashWatchUnregister(w *kvHashWatch) {
	k := kvHashWatchKey(w.svcID, w.epIdx)
	kvHashWatchMu.Lock()
	ws := kvHashWatches[k]
	for i, x := range ws {
		if x == w {
			ws = append(ws[:i], ws[i+1:]...)
			break
		}
	}
	if len(ws) == 0 {
		delete(kvHashWatches, k)
	} else {
		kvHashWatches[k] = ws
	}
	kvHashWatchMu.Unlock()
}

// kvHashWatchObserve is the subscriber-loop hook: called with every decoded
// BlockStored event AFTER it lands in the inventory. Cheap when no watch is
// armed (one RLock + map miss).
func kvHashWatchObserve(svcID uint32, epIdx int, ev kvEvent) {
	kvHashWatchMu.RLock()
	ws := kvHashWatches[kvHashWatchKey(svcID, epIdx)]
	if len(ws) == 0 {
		kvHashWatchMu.RUnlock()
		return
	}
	// Copy the slice header so observe can run without the registry lock.
	watches := append([]*kvHashWatch(nil), ws...)
	kvHashWatchMu.RUnlock()

	for _, w := range watches {
		w.observe(ev)
	}
}

func (w *kvHashWatch) observe(ev kvEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending == 0 || w.failReason != "" {
		return
	}
	bs := int(w.blockSize)
	for j, h := range ev.Hashes {
		idx, ok := w.hashIndex[h]
		if !ok {
			continue
		}
		// §6.2 wire checks on the event that carries an expected hash:
		// its token_id list must match the gateway's own tokens for that
		// block, and extra_keys/lora must be empty (extraKeyPolicy none_p0
		// verified on the wire).
		if ev.ExtraKeys || ev.Lora {
			w.fail(KvAttestReasonChallengeFailed, "BlockStored carries extra_keys/lora on a challenge block")
			return
		}
		if len(ev.Tokens) > 0 && bs > 0 {
			evStart := j * bs
			wantStart := idx * bs
			if evStart+bs > len(ev.Tokens) || wantStart+bs > len(w.wantTokens) {
				w.fail(KvAttestReasonChallengeFailed, "BlockStored token list shorter than its hash list")
				return
			}
			for t := 0; t < bs; t++ {
				if ev.Tokens[evStart+t] != w.wantTokens[wantStart+t] {
					w.fail(KvAttestReasonChallengeFailed,
						fmt.Sprintf("token mismatch in challenge block %d", idx))
					return
				}
			}
		} else if len(ev.Tokens) == 0 {
			// An event schema that omits token lists cannot satisfy the
			// §6.2 cross-check.
			w.fail(KvAttestReasonChallengeFailed, "BlockStored carries no token_ids")
			return
		}
		delete(w.hashIndex, h)
		w.pending--
	}
	if w.pending == 0 {
		close(w.done)
	}
}

func (w *kvHashWatch) fail(reason, detail string) {
	// Surface the wire-check verdict at the moment it happens: the receipt
	// carries it too, but a live operator debugging a held ladder needs the
	// detail without correlating receipt digests (bounded to one line per
	// challenge round by the pending/failReason guard in observe).
	tk.LogIt(tk.LogInfo, "kv-attest: echo challenge wire-check failed: %s (%s)\n", detail, reason)
	w.failReason = reason
	w.failDetail = detail
	close(w.done)
}

func (w *kvHashWatch) result() (string, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.failReason, w.failDetail
}

// ---- challenge construction ----

const (
	kvChallengeStem           = "loxilb kv exact attestation challenge nonce "
	kvChallengeFiller         = " the quick brown fox jumps over the lazy dog"
	kvChallengeTimeoutDefault = 15 * time.Second
	kvChallengeMaxTokens      = 4096
)

var (
	kvChallengeTimeoutOnce sync.Once
	kvChallengeTimeoutV    = kvChallengeTimeoutDefault
)

func kvChallengeTimeout() time.Duration {
	kvChallengeTimeoutOnce.Do(func() {
		if v := os.Getenv("LOXILB_KV_ATTEST_CHALLENGE_TIMEOUT_S"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				kvChallengeTimeoutV = time.Duration(n) * time.Second
			}
		}
	})
	return kvChallengeTimeoutV
}

// kvChallengeTokenizeFn is the tokenizer seam for the challenge prompt
// (default: the data-plane cache path — attesting parity with what scoring
// uses). Tests override.
var kvChallengeTokenizeFn = func(text, model string, max int) []uint32 {
	// The challenge inference posts to /v1/completions without an
	// add_special_tokens override, so the engine tokenizes it with the vLLM
	// default (true); the expected hash chain must be built the same way.
	return kvTokenizeWithCache(text, model, max, true)
}

// kvChallengeBuildPrompt builds the nonce-unique challenge prompt: the nonce
// lands in the FIRST block (the stem+nonce prefix tokenizes well inside any
// realistic block size) and filler repeats until the tokenization spans at
// least two FULL blocks. Returns the prompt and its full-block token
// sequence (len == nBlocks*blockSize).
func kvChallengeBuildPrompt(model, nonceHex string, blockSize uint32) (string, []uint32, error) {
	if blockSize == 0 {
		blockSize = 16
	}
	need := int(2 * blockSize)
	var sb strings.Builder
	sb.WriteString(kvChallengeStem)
	sb.WriteString(nonceHex)
	for i := 0; i < 64; i++ {
		toks := kvChallengeTokenizeFn(sb.String(), model, kvChallengeMaxTokens)
		if len(toks) == 0 {
			return "", nil, fmt.Errorf("challenge prompt tokenization failed for model %q", model)
		}
		if len(toks) >= need {
			full := (len(toks) / int(blockSize)) * int(blockSize)
			return sb.String(), toks[:full], nil
		}
		sb.WriteString(kvChallengeFiller)
	}
	return "", nil, fmt.Errorf("challenge prompt never reached %d tokens", need)
}

// HashChallenge runs one §6.2 echo challenge against one endpoint.
func (a *kvVllmAttest) HashChallenge(ep KvAttestEndpoint, info kvAttestRuleInfo) KvAttestFinding {
	if f := a.kvVllmModelServed(ep, info.modelName); !f.OK {
		return f
	}
	hasher := kvChallengeHasherGet()
	if hasher == nil {
		return KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
			Detail: "no challenge hasher registered (datapath not initialized)"}
	}

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return KvAttestFinding{Reason: KvAttestReasonChallengeFailed, Detail: "nonce: " + err.Error()}
	}
	nonceHex := hex.EncodeToString(nonce[:])

	blockSize := info.blockSize
	if blockSize == 0 {
		blockSize = 16
	}
	prompt, wantTokens, err := kvChallengeBuildPrompt(info.modelName, nonceHex, blockSize)
	if err != nil {
		return KvAttestFinding{Reason: KvAttestReasonChallengeFailed, Detail: err.Error()}
	}
	expected, ok := hasher(info.hashAlgo, blockSize, wantTokens)
	if !ok || len(expected) < 2 {
		return KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
			Detail: fmt.Sprintf("expected-chain computation failed (algo=%s, %d hashes)", info.hashAlgo, len(expected))}
	}

	// Register the expectation BEFORE issuing the inference (§6.2 step 2 —
	// the watch must be armed when the engine publishes).
	w := kvHashWatchRegister(info.svcID, ep.EpIdx, expected, wantTokens, blockSize)
	defer kvHashWatchUnregister(w)

	url := fmt.Sprintf("http://%s:%d/v1/completions", ep.IP, ep.Port)
	reqBody := fmt.Sprintf(`{"model":%q,"prompt":%q,"max_tokens":1,"temperature":0}`,
		info.modelName, prompt)
	resp, err := a.client.Post(url, "application/json", strings.NewReader(reqBody))
	if err != nil {
		return KvAttestFinding{Reason: KvAttestReasonEndpointUnreach,
			Detail: "challenge inference: " + err.Error()}
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return KvAttestFinding{Reason: KvAttestReasonChallengeFailed,
			Detail: fmt.Sprintf("challenge inference HTTP %d", resp.StatusCode)}
	}

	select {
	case <-w.done:
		if reason, detail := w.result(); reason != "" {
			return KvAttestFinding{Reason: reason, Detail: detail}
		}
		return KvAttestFinding{OK: true,
			Detail: fmt.Sprintf("%d challenge blocks echoed (nonce %s)", len(expected), nonceHex[:8])}
	case <-time.After(kvChallengeTimeout()):
		return KvAttestFinding{Reason: KvAttestReasonChallengeTimeout,
			Detail: fmt.Sprintf("expected hashes not observed within %v", kvChallengeTimeout())}
	}
}
