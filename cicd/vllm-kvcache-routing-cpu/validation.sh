#!/bin/bash
# validation.sh — KV-cache-aware AI routing exit gate (fast mock inner loop, functional checks 1..8).
#
# Asserts the four overlap scenarios + the functional checks against a live loxilb KV-exact P/D service
# (seeded by config.sh) fronting 6 reflect-echo backends (3 prefill at non-adjacent absolute indices +
# 3 decode). Every functional assert is HARD/FATAL under SKELETON_STRICT=1; only inherently
# non-deterministic timing sub-checks soft(). A single SCENARIO-vllm-kvcache-routing-cpu [OK]
# sentinel governs the run.
#
# Assertion map (four overlap scenarios + the functional checks):
#   (1) two-EP partial-overlap argmax + mutation flip — banner==serverP* AND tier15_hits{ep}
#            (dual proof, never metrics-only); re-publish to the loser FLIPS the re-issued prompt.
#   (2) non-contiguous prefill bitmask — best EP at a NON-ADJACENT abs prefill index still selected.
#   (3) excluded/CB-open winner -> 2nd-best PREFILL EP (NOT Tier-2 RR).
#   (4) warmup grace + tokenize/no-worker miss -> Tier-2 RR fallthrough + t15_miss_reason{reason}.
#   check 1  inventory-mutation flip (re-issued identical prompt changes winner).
#   check 2  argmax-overlap selection (the highest-overlap prefill EP serves).
#   check 4  kv_hash_parity.py against the PROMOTED golden vectors for BOTH sha256_cbor AND xxhash_cbor.
#   check 5  GET /metrics counter deltas for the 9 routing counters (miss-reason is ONE CounterVec{reason}).
#   check 6  publisher --kill/restart -> loxilb_kv_subscriber_connected transition + inventory clear + replay.
#   check 7  feature-enable verified live (kvExactMode active on the rule).
#   check 9  P/D lifecycle taxonomy — a decode-leg wedge must move
#            loxilb_ai_pd_requests_total{phase="decode",status="timeout"} and must leave
#            {phase="prefill",status="timeout"} flat, carrying the request's own model
#            label. Runs BEFORE check 8, whose collision pre-clean destroys the topology.
#   check 11 P/D decode-leg death — a decode backend closing with ZERO response bytes must move
#            loxilb_pd_decode_ep_died_total AND loxilb_pd_decode_zero_byte_eof_total by the same
#            amount as the client-visible pd_decode_backend_died receipts. died is a SIX-writer
#            family, so the stage asserts the zero-byte SITE fired and the other five (two
#            initiate-decode callers, mid-stream EOF, and both SGLang sites) stayed FLAT.
#            Runs BEFORE check 10, which ends with all three prefill breakers OPEN.
#   check 12 P/D prefill-leg death — a prefill backend dying mid-request must move
#            loxilb_pd_prefill_ep_died_total once per DEAD ENDPOINT (prefill re-dispatches, so
#            the oracle is Δcounter == Δ"Prefill backend died" log lines, not Δ == requests),
#            with the client receipt keyed on its DETAIL ("prefill backend connection dropped")
#            because three sites share the pd_pool_unavailable error code. The three SGLang
#            writers are asserted FLAT. Ends by PROVING the pool recovered, which is check 10's
#            precondition.
#   check 13 P/D proactive circuit-breaker heal — an OPEN breaker must be driven OPEN->HALF_OPEN
#            by the 1Hz health pass with NO traffic, moving loxilb_pd_cb_proactive_heal_total.
#            Single writer, so Δcounter == Δ its log line EXACTLY; loxilb_pd_cb_flips_total is
#            asserted only as a SUPERSET because one of its seven sites logs nothing at all.
#            Control gets the same request count AND the same trip+heal wall clock. Runs after
#            check 12 (clean, no breaker open) and before check 10.
#   check 14 P/D session stickiness gauge — loxilb_pd_sessions_active is HASH_COUNT of the
#            session map, not a request or concurrency count. Control = the IDENTICAL request
#            minus X-Conversation-Id (no key ⇒ no entry) so a flat control is not flat-for-lack-
#            of-traffic; 3 distinct keys must add EXACTLY 3; 4 requests on ONE key must add
#            EXACTLY 1 because pd_session_store is an UPSERT. One insert statement has FOUR
#            callers, so both failover callers are asserted flat. The gauge is NOT asserted to
#            return to baseline — entries live out a 300s TTL and that is correct.
#   check 15 P/D radix-trie gauge — loxilb_pd_trie_nodes is gated by the per-rule API field
#            pd_cache_aware_mode (an extended-mutable field, so the stage flips it by re-POSTing
#            the same rule). Gate closed ⇒ EXACTLY 0 while Tier-2 traffic still flows; gate open
#            with NO traffic ⇒ EXACTLY 1, isolating the config-time writer from the traffic-time
#            one; 3 distinct-first-byte prompts ⇒ EXACTLY 4 (radix insert off the root adds one
#            node per key); closing the gate ⇒ back to EXACTLY 0. Insert site attributed by an
#            independent family: tier_selected{tier="tier2"} moves, {tier="tier1"} stays flat.
#   check 10 P/D same-endpoint connect retry — a refused connect that SUCCEEDS on retry must
#            move loxilb_pd_connect_retry_same_ep_ok_total, with the ATTEMPT counter moving by
#            the same amount and failover flat. Its control is the branch itself (endpoints
#            refusing: attempts still move, only the success half declines), and its parity
#            fault is armed PER REQUEST because the stub port is shared with the gateway's own
#            /metrics scraper. Runs BEFORE check 8, whose collision pre-clean destroys the topology.
#   check 8  vllm-pd-disagg byte-for-byte re-run [PASS] AFTER the l3ep1/l3ep2 collision pre-clean.
#
# Metric source-of-truth (api/prometheus/sockproxy_metrics.go):
#   loxilb_pd_kv_tier15_hits_total{ep_idx}        loxilb_pd_kv_tier15_miss_reason_total{reason}
#   loxilb_pd_kv_tier15_fallthrough_total         loxilb_kv_subscriber_connected{service,ep}
#   loxilb_kv_subscriber_reconnect_total{...}     loxilb_kv_subscriber_recv_error_total{...}
# P/D lifecycle (api/prometheus/ai_metrics.go, RecordPDRequest):
#   loxilb_ai_pd_requests_total{model,phase,status} — phase/status are derived from the
#   error_phase the datapath passes to llb_ai_pd_record, so this family is the ONLY exported
#   signal naming which leg of a pair failed and how. A family-total oracle cannot see a
#   mislabel; check 9 therefore asserts per-{phase,status} child deltas, including flats.
# Inventory: GET /netlox/v1/config/ai/kv/inventory?service_id=<id>&ep_idx=<idx>.
#
# REST hits localhost:11111 (auth-off, CICD mode) and MUST run in the llb1 netns (the REST API lives on
# llb1; a client-netns curl returns HTTP 000). Routing requests are driven from l3h1 (the client).
#
# Run on the REMOTE testbed. macOS validates `bash -n` + `shellcheck -S error` only.
# Exit: prints SCENARIO-vllm-kvcache-routing-cpu [OK]/[FAILED]; exits non-zero on any HARD failure.

source ../common.sh

echo SCENARIO-vllm-kvcache-routing-cpu

# ── args: --fr <n> runs ONLY that check in isolation (the hash-parity selector) ─────
# The default (no --fr) runs the full mock scenario. `--fr 4` runs ONLY the
# hash-parity oracle for the model named by KV_MODEL (see the ONLY_FR block below):
# it needs neither a live loxilb container nor transformers — it drives the golden
# vectors' explicit token arrays through the reused cbor/hash core, so it can select
# a PRODUCTION-SIZE model's vector block and detect block-size/tokenizer hash-drift.
ONLY_FR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --fr) ONLY_FR="${2:?--fr needs a number}"; shift 2 ;;
        *) shift ;;   # tolerate other flags (config.sh-compat); unknowns are ignored here
    esac
done

# ── parameters (mirror config.sh) ──────────────────────────────────────────────
CFGDIR="$(cd "$(dirname "$0")" && pwd)"
VIP="10.10.10.254"
VPORT="8080"
LBBASE="http://localhost:11111/netlox/v1/config/loadbalancer"
METRICS="http://localhost:11111/netlox/v1/metrics"
KVINV="http://localhost:11111/netlox/v1/config/ai/kv/inventory"
KV_ZMQ_PORT=5557
KV_HASH_ALGO="sha256_cbor"
KV_BLOCK_SIZE=16
# Model identity carried in every routed request ("model" key). Slugifies (/ -> __) to the
# tokenizer dir config.sh stages: /etc/loxilb/tokenizers/<slug>/tokenizer.json.
# KV_MODEL is env-overridable: the mock scenario defaults to the small
# Qwen3-0.6B; `KV_MODEL=Qwen/Qwen2.5-7B-Instruct ... --fr 4` selects the
# PRODUCTION-SIZE model's tokenizer + golden-vector block (no hardcoded 2nd copy —
# the tokenizer dir is derived from the model slug, following the existing pattern).
KV_MODEL="${KV_MODEL:-Qwen/Qwen3-0.6B}"
KV_MODEL_SLUG="${KV_MODEL//\//__}"
TOKENIZER_SRC="${CFGDIR}/../common/kv_hash/fixtures/tokenizers/${KV_MODEL_SLUG}/tokenizer.json"
VECTORS_SRC="${CFGDIR}/../common/kv_hash/fixtures/kv_hash_vectors.json"
PUBLISHER="${CFGDIR}/kv_event_publisher.py"
CORPUS="${CFGDIR}/prompts/corpus.json"
PARITY="${CFGDIR}/../common/kv_hash/kv_hash_parity.py"
PUB_TAG="kvpub80"
# `$hexec` (sudo ip netns exec) runs python3 AS ROOT, which cannot see the ubuntu user's
# pip --user site-packages and sudo env-resets the caller env — resolve the user-site dir
# here (as the invoking user) and export it INSIDE every $hexec bash -c string (see config.sh).
PY_USER_SITE="$(python3 -m site --user-site 2>/dev/null || echo '')"
# Prefill EP IPs at non-adjacent absolute indices 0/2/4 (EP-A/EP-B/EP-C) and their tier15 ep_idx.
EP_A_IP="31.31.31.1"; EP_A_IDX=0   # serverP0
EP_B_IP="33.33.33.1"; EP_B_IDX=2   # serverP1
EP_C_IP="35.35.35.1"; EP_C_IDX=4   # serverP2

# chaos/cap knobs (mirror config.sh; defaulted here so a direct validation.sh re-run still
# resolves them when config.sh's exports are not in this shell's env).
KV_MAX_BLOCKS="${KV_MAX_BLOCKS:-1000}"            # per-EP cap = the Go FLOOR (kvResolveMaxBlocks
                                                  # rejects <1000 -> 1M default). >> any normal EP's ~4 blocks
                                                  # (overlap/baseline never cap); the cap-leg flood exceeds 1000.
CHAOS_EP_DOWN_IP="${CHAOS_EP_DOWN_IP:-${EP_C_IP}}"  # down leg: this EP's publisher is killed and never rebound
CHAOS_EP_LIVE_IP="${CHAOS_EP_LIVE_IP:-${EP_A_IP}}"  # partial-outage leg: this sibling stays up and keeps serving

# netns_for_ep_ip <ep-ip> — the netns (== docker host name) that OWNS the prefill EP IP. The publisher
# MUST bind its PUB socket from INSIDE this netns: each prefill EP IP (31/33/35.x.x.1) is a local
# address ONLY in its own l3epN netns. Binding 31.31.31.1 from the host/llb1 netns fails with
# EADDRNOTAVAIL (the address is not local there) and the publisher exits — which was the root cause
# of subscriber_connected=0 / tier15_hits=0 (the subscriber dials tcp://<ep-ip>:5557 correctly, but
# nothing was ever successfully bound at that address). `ip netns exec l3epN` runs the HOST python3
# (with its installed deps + the host-FS fixtures) while only swapping the network namespace, so the
# bind lands on the EP's real IP and the cross-veth subscriber Dial from llb1 connects.
netns_for_ep_ip() {
    case "$1" in
        "${EP_A_IP}") echo "l3ep1" ;;
        "${EP_B_IP}") echo "l3ep3" ;;
        "${EP_C_IP}") echo "l3ep5" ;;
        *) echo "" ;;
    esac
}

# idx_for_ep_ip <ep-ip> — the EP's absolute index (tier15/inventory ep_idx key).
idx_for_ep_ip() {
    case "$1" in
        "${EP_A_IP}") echo "${EP_A_IDX}" ;;
        "${EP_B_IP}") echo "${EP_B_IDX}" ;;
        "${EP_C_IP}") echo "${EP_C_IDX}" ;;
        *) echo "" ;;
    esac
}

# inv_total <ep_idx> — current inventory block count for one prefill EP (0 if unreachable).
inv_total() {
    local v
    v=$(llb_curl "${KVINV}?service_id=${SERVICE_ID}&ep_idx=$1" 2>/dev/null \
        | grep -Eo '"total":[0-9]+' | grep -Eo '[0-9]+' | head -1)
    echo "${v:-0}"
}

# SKELETON_STRICT gate (default 1 = enforcing). assert = HARD; soft = non-fatal (timing windows only).
SKELETON_STRICT="${SKELETON_STRICT:-1}"

assert() {
    local name="$1" ok="$2"
    if [[ "$ok" == 1 ]]; then
        echo "  ${name} [OK]"
    elif [[ "$SKELETON_STRICT" == 1 ]]; then
        echo "  ${name} [FAILED]"
        code=1
    else
        echo "  ${name} [PENDING] (SKELETON_STRICT=0 dev dry-run — would have FAILED)"
    fi
}

soft() {
    local name="$1" ok="$2"
    if [[ "$ok" == 1 ]]; then
        echo "  ${name} [OK] (soft)"
    else
        echo "  ${name} [SKIP] (soft — non-fatal)"
    fi
}

# REST helper runs on llb1 (control plane); routing requests run from l3h1 (the client).
llb_curl() { $hexec llb1 curl -s --max-time 10 --retry 2 "$@"; }
client_get() { $hexec l3h1 curl -s --max-time 10 "$@"; }

# kill_publisher — resolve this suite's publisher PIDs by the unique anchored tag and kill exactly
# those PIDs (scoped per-PID, NOT a host-wide process-name killall).
kill_publisher() {
    local pid
    for pid in $(pgrep -f "${PUB_TAG}" 2>/dev/null); do
        kill "${pid}" >/dev/null 2>&1 || true
    done
}

#################################################################################
# (HASH-PARITY ISOLATED — drift oracle) `--fr 4`: run ONLY the hash-parity
# self-check for KV_MODEL against the golden vectors, then EXIT. Needs neither a
# live loxilb container nor transformers (the golden vectors carry explicit token
# arrays; the publisher --self-check drives them through the reused cbor/hash core).
#
# Model selection (no hardcoded 2nd copy — parameterized by KV_MODEL):
#   * KV_MODEL == the root default (Qwen3-0.6B) -> use VECTORS_SRC directly (its
#     root-level `fixtures`/`none_hash_*` ARE that model's block, unchanged).
#   * KV_MODEL == a production-size model -> extract models[<id>] from VECTORS_SRC
#     into a self-check-shaped temp doc (its fixtures/none_hash_* promoted to root),
#     and run --self-check against THAT.
#
# FAIL-LOUD (never silently pass): the model block MUST exist AND its fixtures
# MUST be fully populated (non-null token arrays + expected hashes). If the block is
# missing or still carries null/_todo placeholders, the check FAILS — a production-model
# tokenizer/block-size drift (or an ungenerated vector) must break the gate, not skip.
#################################################################################
if [[ "${ONLY_FR}" == "4" ]]; then
    echo "=== (hash-parity isolated, --fr 4) drift oracle for KV_MODEL=${KV_MODEL} ==="
    fr4_code=0
    if [[ ! -f "${TOKENIZER_SRC}" ]]; then
        echo "  NOTE: tokenizer.json for ${KV_MODEL} not found at ${TOKENIZER_SRC} (self-check needs only vectors, not the tokenizer — informational)."
    fi
    # Build the self-check doc: default model uses VECTORS_SRC as-is; a non-default
    # model has its models[<id>] block extracted+promoted to a temp doc.
    SELFCHECK_VECTORS="${VECTORS_SRC}"
    if [[ "${KV_MODEL}" != "Qwen/Qwen3-0.6B" ]]; then
        SELFCHECK_VECTORS="${CFGDIR}/.fr4-vectors-${KV_MODEL_SLUG}.json"
        if ! KV_MODEL="${KV_MODEL}" python3 - "${VECTORS_SRC}" "${SELFCHECK_VECTORS}" <<'PYEXTRACT'
import json, os, sys
src, dst = sys.argv[1], sys.argv[2]
model = os.environ["KV_MODEL"]
doc = json.load(open(src))
mb = (doc.get("models") or {}).get(model)
if mb is None:
    sys.stderr.write(f"hash-parity FAIL: no golden-vector block for model {model!r} in {src} "
                     f"(models keys: {list((doc.get('models') or {}).keys())}).\n")
    sys.exit(1)
fixtures = mb.get("fixtures") or []
if not fixtures:
    sys.stderr.write(f"hash-parity FAIL: model {model!r} block has no fixtures.\n")
    sys.exit(1)
# fail-loud: reject unfilled (null/_todo) fixtures — an ungenerated production
# vector must break the gate, never silently pass.
unfilled = [
    fx.get("name", "<unnamed>")
    for fx in fixtures
    if fx.get("tokens") is None
    or fx.get("expected_hash_uint64") is None
    or fx.get("parent_hash_hex") is None
    or fx.get("expected_digest_hex") is None
]
if unfilled:
    sys.stderr.write(
        "hash-parity FAIL: model {m!r} has UNFILLED golden fixtures (null/_todo): {u}.\n"
        "  These require live generation with the {m} tokenizer on the fleet controller\n"
        "  (transformers present). Fill tokens+parent_hash_hex+expected_digest_hex+\n"
        "  expected_hash_uint64 via the repo generator, then re-run. NOT skippable.\n"
        .format(m=model, u=unfilled)
    )
    sys.exit(1)
# Promote the model block to a root-level self-check-shaped doc.
out = {
    "none_hash_seed": mb.get("none_hash_seed", "0"),
    "none_hash_sha256_hex": mb.get("none_hash_sha256_hex"),
    "none_hash_xxhash_hex": mb.get("none_hash_xxhash_hex"),
    "block_size": mb.get("block_size", 16),
    "reference": mb.get("reference", ""),
    "fixtures": fixtures,
}
json.dump(out, open(dst, "w"), indent=2)
print(f"  extracted {len(fixtures)} golden fixtures for {model} -> {dst}")
PYEXTRACT
        then
            echo "  (hash-parity vector extraction for ${KV_MODEL} FAILED — see reason above) [FAILED]"
            echo "=== SCENARIO-vllm-kvcache-routing-cpu [FAILED] ==="
            exit 1
        fi
    fi
    # NB: the publisher prints its "SELF-CHECK PASS" report to stdout; suppress it inside
    # the capture so fr4_sha/fr4_xxh hold ONLY the 1/0 verdict (else the slurped report
    # text makes the `== 1` compare never match and the check falsely reports [FAILED]).
    fr4_sha=$(PYTHONHASHSEED=0 python3 "${PUBLISHER}" --self-check --algo sha256_cbor \
        --vectors "${SELFCHECK_VECTORS}" >/dev/null 2>&1 && echo 1 || echo 0)
    fr4_xxh=$(PYTHONHASHSEED=0 python3 "${PUBLISHER}" --self-check --algo xxhash_cbor \
        --vectors "${SELFCHECK_VECTORS}" >/dev/null 2>&1 && echo 1 || echo 0)
    echo "  parity sha256_cbor=${fr4_sha} ; xxhash_cbor=${fr4_xxh} (--vectors ${SELFCHECK_VECTORS})"
    if [[ "${fr4_sha}" == 1 && "${fr4_xxh}" == 1 ]]; then
        echo "  hash parity GREEN for ${KV_MODEL} (both algos) [OK]"
        echo "=== SCENARIO-vllm-kvcache-routing-cpu [OK] ==="
        exit 0
    fi
    echo "  hash parity FAILED for ${KV_MODEL} — block-size/tokenizer drift or bad vectors [FAILED]"
    echo "=== SCENARIO-vllm-kvcache-routing-cpu [FAILED] ==="
    exit 1
fi

# ── corpus helpers (python3 — already a runner dep; jq-free) ─────────────────────────────────────────
# prompt_text <id> — extract a prompt string from prompts/corpus.json by id.
prompt_text() {
    python3 -c "import json,sys
d=json.load(open('${CORPUS}'))
for p in d['prompts']:
    if p['id']==sys.argv[1]:
        sys.stdout.write(p['prompt']); break" "$1"
}

# resolve the KV-exact rule's serviceID ordinal (== r.ruleNum). The GET /loadbalancer surface
# does NOT expose ruleNum, and ordinals do NOT start at 0 (the first rule on a fresh container
# is ordinal 1 — the prior 'first rule is 0' assumption made every inventory probe 404). Probe
# the inventory Admin API (the authoritative keyspace: KvSubscriberStart creates the per-EP
# inventory at rule-create, even before any event arrives) for the prefill EP_A index.
SERVICE_ID=""
for _sid in 0 1 2 3 4 5 6 7 8; do
    if llb_curl "${KVINV}?service_id=${_sid}&ep_idx=${EP_A_IDX}" 2>/dev/null | grep -q '"service_id"'; then
        SERVICE_ID="${_sid}"
        break
    fi
done
SERVICE_ID="${SERVICE_ID:-1}"
echo "  resolved KV serviceID=${SERVICE_ID} (inventory-API probe)"

# publish_prompt_to_ep <prompt-id> <ep-ip> [<extra publisher args...>] — single-prompt publish to one
# prefill EP's ZMQ inventory. Binds on the EP's private IP — FROM INSIDE THAT EP's netns (see
# netns_for_ep_ip) — so the per-EP subscriber (dialing tcp://<ep-ip>:5557 across the veth from llb1)
# receives ONLY this prompt's blocks => deterministic per-EP overlap.
publish_prompt_to_ep() {
    local pid="$1" ep_ip="$2"; shift 2
    local one="${CFGDIR}/.kvpub-${pid}-${ep_ip}.json"
    python3 -c "import json,sys
d=json.load(open('${CORPUS}'))
for p in d['prompts']:
    if p['id']==sys.argv[1]:
        json.dump([{'prompt':p['prompt']}], open(sys.argv[2],'w')); break" "$pid" "$one" 2>/dev/null
    local ns; ns="$(netns_for_ep_ip "${ep_ip}")"
    if [[ -z "${ns}" ]]; then
        echo "  WARN: no netns owns prefill EP ${ep_ip} — publisher bind would fail (skipping publish)"
        return
    fi
    # $hexec ns = `sudo ip netns exec <ns>` — runs host python3 in the EP netns so bind(ep_ip) is local.
    # --repeat keeps the PUB bound across the subscriber's 5s redial backoff (a single
    # 2s publish-and-exit pass is usually missed); --no-vocabulary because a LIVE
    # subscriber would receive the trailing AllBlocksCleared and wipe the inventory
    # this publish just seeded. Callers' extra args ($*) append after, so explicit
    # liveness flags (--seq-base/--seq-jump/--kill) compose with the resident lifecycle.
    local ep_i; ep_i="$(idx_for_ep_ip "${ep_ip}")"
    local before_total; before_total="$(inv_total "${ep_i}")"
    # Scoped pre-kill: a still-RESIDENT prior publisher (baseline --repeat, or the previous
    # leg's) holding this EP's :5557 would make the new bind fail "Address already in use"
    # and the new publisher exit silently. Kill ONLY our anchored tag, then settle.
    for _pp in $(pgrep -f "${PUB_TAG}" 2>/dev/null); do kill "${_pp}" >/dev/null 2>&1 || true; done
    sleep 1
    local pub_log="${CFGDIR}/.kvpub-d05-${pid}-${ep_ip}.log"
    setsid $hexec "${ns}" bash -c "export PYTHONPATH='${PY_USER_SITE}' PYTHONHASHSEED=0; exec -a ${PUB_TAG} python3 '${PUBLISHER}' \
        --corpus '${one}' --tokenizer '${TOKENIZER_SRC}' --vectors '${VECTORS_SRC}' \
        --bind '${ep_ip}' --port ${KV_ZMQ_PORT} --algo ${KV_HASH_ALGO} \
        --block-size ${KV_BLOCK_SIZE} --repeat 3 --repeat-interval 6 --no-vocabulary $*" >"${pub_log}" 2>&1 &
    # liveness (--kill) publishes REPLACE an equal-sized set (reconnect-clear + same prompt),
    # so the growth predicate below would stall — use a fixed connect+first-pass window.
    if [[ "$*" == *--kill* ]]; then
        sleep 8
        return
    fi
    # Convergence wait: the subscriber redials a fresh publisher within ~5.5s, the
    # reconnect CLEARS the EP inventory, then the next repeat pass re-populates it.
    # A publish REPLACES the inventory (clear + ingest), so the new total may EQUAL
    # the old one — "grows past before" would stall. Converged = the total CHANGED
    # from its pre-publish value at any sample (incl. the 0-dip after the clear) AND
    # is now non-zero. Asserting before this would race the ingest.
    local _w cur seen_change=0
    for _w in $(seq 1 24); do
        cur="$(inv_total "${ep_i}")"
        [[ "${cur}" != "${before_total}" ]] && seen_change=1
        if [[ "${seen_change}" == 1 && "${cur}" -gt 0 ]]; then return; fi
        sleep 1
    done
    echo "  WARN: ep ${ep_ip} (idx ${ep_i}) inventory change not observed (before=${before_total}, now=$(inv_total "${ep_i}")) within 24s"
    sleep 4   # let the SUB ingest before the next action
}

# tier15_hits <ep_idx> — current loxilb_pd_kv_tier15_hits_total for an EP index (0 if absent).
tier15_hits() {
    llb_curl "${METRICS}" 2>/dev/null \
        | grep -E "loxilb_pd_kv_tier15_hits_total\{[^}]*ep_idx=\"$1\"" \
        | awk '{print $NF}' | tail -1 | grep -Eo '^[0-9]+' || echo 0
}

# metric_val <full-grep-pattern> — sum the value column of all matching metric lines (0 if none).
metric_val() {
    local v
    v=$(llb_curl "${METRICS}" 2>/dev/null | grep -E "$1" | awk '{s+=$NF} END{printf "%d", s}')
    echo "${v:-0}"
}

# metric_series <family> <label> <value> — the value of the ONE series of <family>
# carrying <label>="<value>" (0 if that series is absent).
#
# metric_val above sums the whole FAMILY, which cannot see a wrong LABEL: a write
# attributed to the wrong endpoint moves the family by exactly as much as a correct
# one, so a family-level delta passes while the attribution is broken. Every
# per-endpoint claim here reads ONE series and asserts the siblings stayed FLAT —
# the flats are the half that makes the attribution real.
#
# Exactly-one-series discipline: the count of matching lines is checked, so a
# second series appearing under the same label value (a relabelling regression)
# fails loudly instead of being silently summed away. More than one match yields
# -1, which is NUMERIC on purpose: a non-numeric sentinel would make the caller's
# `[[ x -eq y ]]` a syntax error rather than a failed assert (the `grep -c` "0\n0"
# trap in one more disguise). -1 can never equal a counter or a delta.
metric_series() {
    local fam="$1" lab="$2" val="$3" lines n
    lines=$(llb_curl "${METRICS}" 2>/dev/null \
        | grep -E "^${fam}\{[^}]*${lab}=\"${val}\"")
    n=$(printf '%s' "${lines}" | grep -c .)
    if [[ "${n:-0}" -gt 1 ]]; then
        echo "-1"
        return
    fi
    printf '%s' "${lines}" | awk '{printf "%d", $NF} END{if(NR==0) printf "0"}'
}

# loxilb_log_count <ANCHORED-EXTENDED-REGEX> — count matching lines in the in-container loxilb log.
# Log-marker discipline: the prompt corpus text flows through the SAME container (request bodies, debug
# echoes), so a bare word like `AllBlocksCleared` can self-satisfy a grep against arbitrary log text
# and mask a missing clear. Every clear/eviction assertion MUST pass a STRUCTURED marker here — the
# real Go log lines carry a field shape no prompt text reproduces:
#     [KV_INV] ClearAll cleared=<N> total=0                       (kvInventory.ClearAll)
#     [KV_INV] AddBlocks cap-evicted=<N> (... cap-hit ...)        (eviction site)
#     kv-subscriber: ep <N> resync CLEAR — ... clearing stale ... (reconnect CLEAR)
#     kv-subscriber: AllBlocksCleared received for ep <N> — clearing inventory  (event handler)
# The `=<digits>` / `ep <digits>` field anchors are what make these robust; NEVER grep the bare word.
loxilb_log_count() {
    # NOTE: `grep -c` PRINTS "0" *and* exits 1 on zero matches, so a trailing `|| echo 0`
    # appends a SECOND "0" -> the caller captures "0\n0" and `[[ 0\n0 -gt .. ]]` is a syntax
    # error (the actual gate failure). Capture grep -c's own count (already "0" on no match).
    local n
    n=$(docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' 2>/dev/null | grep -cE "$1")
    echo "${n:-0}"
}

# request_and_banner <prompt-id> — issue the prompt to the VIP from l3h1 and echo the serving banner.
# The reflect-echo backend answers with its ECHO_NAME (serverP0/P1/P2/D0/D1/D2) — the delivery
# surface. We POST the raw prompt text so the C tokenize path sees the same bytes the publisher hashed.
request_and_banner() {
    # OpenAI /v1/completions JSON shape — REQUIRED by the KV-T15 selector. The C-side
    # prefix extractor (sockproxy_json.c) fills prefix_key.model from the body's "model"
    # and prefix_key.prefix from "prompt" (verbatim — the SAME bytes the publisher
    # tokenized; corpus prompts are JSON-escape-clean and <= MAX_PREFIX_LEN 512). A bare
    # text/plain POST left BOTH model sources empty -> model_empty guard on EVERY
    # request (miss_reason{model_empty}=5, tier15_hits=0) and the routing was silent RR.
    # The model name maps to the staged tokenizer via slug = ReplaceAll(model,"/","__")
    # -> Qwen__Qwen3-0.6B (config.sh stages /etc/loxilb/tokenizers/Qwen__Qwen3-0.6B/).
    local pid="$1" body
    body=$(python3 -c "
import json,sys
d=json.load(open('${CORPUS}'))
for p in d['prompts']:
    if p['id']==sys.argv[1]:
        print(json.dumps({'model':'${KV_MODEL}','prompt':p['prompt'],'max_tokens':8})); break" "$pid")
    client_get -o - -w '' -X POST "http://${VIP}:${VPORT}/v1/completions" \
        -H 'Content-Type: application/json' --data-binary "${body}" 2>/dev/null \
        | grep -Eo 'server[PD][0-9]' | head -1
}

sleep 3
code=0

# Repo root so the layer-1/2 builds run from the right cwd.
# CFGDIR == cicd/vllm-kvcache-routing-cpu ; repo root is two levels up.
REPO_ROOT="$(cd "${CFGDIR}/../.." && pwd)"

#################################################################################
# (layer 1) make test_kv — C CBOR/hash parity, BOTH sha256_cbor + xxhash_cbor,
#     INCLUDING the guards F/G. This is LAYER 1 of the single
#     SCENARIO-[OK] sentinel: its exit status is wired directly into `code` so a
#     guard-F/G (or any C-parity) failure flips the sentinel to [FAILED]
#     (guards-in-sentinel). Skippable ONLY for a pure dev dry-run via SKIP_C_LAYERS=1;
#     on the real gate it MUST run and MUST pass before any routing assert is trusted.
#################################################################################
echo "=== (layer 1) make test_kv — C CBOR/hash parity + guards F/G (layer 1 of the sentinel) ==="
if [[ "${SKIP_C_LAYERS:-0}" == 1 ]]; then
    soft "(layer 1) make test_kv skipped (SKIP_C_LAYERS=1 dev dry-run)" 1
else
    testkv_log="${CFGDIR}/.test_kv.log"
    if ( cd "${REPO_ROOT}/loxilb-ebpf/common" && make test_kv ) >"${testkv_log}" 2>&1; then
        testkv_ok=1
    else
        testkv_ok=0
        echo "  --- make test_kv tail ---"; tail -20 "${testkv_log}" 2>/dev/null || true
    fi
    echo "  make test_kv exit ok=${testkv_ok} (guards F/G are part of this C unit)"
    # HARD: a non-zero make test_kv exit (incl. a guard-F/G regression) MUST reach code=1.
    assert "(layer 1) make test_kv C parity + guards F/G GREEN (sentinel layer 1)" "$testkv_ok"
fi

#################################################################################
# (layer 2) go test ./pkg/loxinet KV units — the Go-side KV inventory/subscriber/
#     best-worker unit tests, bound into the SAME sentinel as layer 2 (ahead of the
#     container integration + the backward-compat re-run). Scoped to the KV tests so the
#     full loxinet suite (which needs eBPF/CGO) does not gate this layer.
#################################################################################
echo "=== (layer 2) go test ./pkg/loxinet KV units (layer 2 of the sentinel) ==="
if [[ "${SKIP_GO_LAYER:-0}" == 1 ]]; then
    soft "(layer 2) go test ./pkg/loxinet KV units skipped (SKIP_GO_LAYER=1 dev dry-run)" 1
else
    gotest_log="${CFGDIR}/.go_test_kv.log"
    # Non-login shells (detached CICD runs) often lack the Go toolchain on PATH —
    # a missing binary must not read as a product FAIL (false-negative).
    command -v go >/dev/null 2>&1 || export PATH=/usr/local/go/bin:$PATH
    # PREREQUISITE: pkg/loxinet is a cgo package that links the eBPF datapath static
    # archive (`-l:libloxilbdp.a`, produced by loxilb-ebpf/kernel). On a freshly-cloned or
    # `make clean`-ed tree that archive does not exist and the go LINKER fails with
    #   /usr/bin/ld: cannot find -l:libloxilbdp.a
    # — which reads as a KV unit-test FAIL but is really a missing build artifact (the
    # containers under test come from the prebuilt image, so nothing else in this suite
    # needs the host tree built). Build the prerequisite ONCE when absent; a FAILED
    # prerequisite build is still a HARD sentinel failure — never a silent skip.
    DP_ARCHIVE="${REPO_ROOT}/loxilb-ebpf/kernel/libloxilbdp.a"
    if [[ ! -f "${DP_ARCHIVE}" ]]; then
        echo "  prerequisite: ${DP_ARCHIVE} absent — building loxilb-ebpf (one-off, needed to LINK the cgo test binary)..."
        if ( cd "${REPO_ROOT}/loxilb-ebpf" && make ) >"${CFGDIR}/.ebpf_build.log" 2>&1 && [[ -f "${DP_ARCHIVE}" ]]; then
            echo "  prerequisite: libloxilbdp.a built [OK]"
        else
            echo "  prerequisite: loxilb-ebpf build FAILED — layer 2 cannot link (tail below)"
            tail -20 "${CFGDIR}/.ebpf_build.log" 2>/dev/null | sed 's/^/    /' || true
        fi
    fi
    if ( cd "${REPO_ROOT}" && go test ./pkg/loxinet -run 'Kv|KV' -count=1 ) >"${gotest_log}" 2>&1; then
        gotest_ok=1
    else
        gotest_ok=0
        echo "  --- go test tail ---"; tail -20 "${gotest_log}" 2>/dev/null || true
    fi
    echo "  go test ./pkg/loxinet -run 'Kv|KV' exit ok=${gotest_ok}"
    assert "(layer 2) go test ./pkg/loxinet KV units GREEN (sentinel layer 2)" "$gotest_ok"
fi

#################################################################################
# feature-enable verified live — kvExactMode active on the rule
#################################################################################
echo "=== feature-enable: kvExactMode=1 active on the KV-exact P/D rule ==="
fr7_ok=$(llb_curl "${LBBASE}/all" 2>/dev/null | grep -qiE '"kvExactMode" *: *1|kvExactMode.*1' && echo 1 || echo 0)
echo "  serviceID(ordinal)=${SERVICE_ID} kvExactMode active=${fr7_ok}"
assert "feature-enable: kvExactMode=1 live on the rule" "$fr7_ok"

#################################################################################
# hash parity — kv_hash_parity.py against the PROMOTED golden vectors, BOTH algos
#     The promoted vectors live at cicd/common/kv_hash/fixtures/kv_hash_vectors.json. Run the
#     publisher self-check (which asserts the reused hash core reproduces the golden vectors) for BOTH
#     sha256_cbor and xxhash_cbor against --vectors <promoted path> — proving the C/Go/Python hash core
#     is byte-identical to vLLM v0.17.0 for both algos (layered parity).
#################################################################################
echo "=== hash parity: BOTH algos vs the promoted cicd/common/kv_hash/fixtures/kv_hash_vectors.json ==="
fr4_sha=$(PYTHONHASHSEED=0 python3 "${PUBLISHER}" --self-check --algo sha256_cbor \
    --vectors "${VECTORS_SRC}" >/dev/null 2>&1 && echo 1 || echo 0)
fr4_xxh=$(PYTHONHASHSEED=0 python3 "${PUBLISHER}" --self-check --algo xxhash_cbor \
    --vectors "${VECTORS_SRC}" >/dev/null 2>&1 && echo 1 || echo 0)
echo "  parity sha256_cbor=${fr4_sha} ; xxhash_cbor=${fr4_xxh} (--vectors ${VECTORS_SRC})"
fr4_ok=$([[ "$fr4_sha" == 1 && "$fr4_xxh" == 1 ]] && echo 1 || echo 0)
assert "hash parity: kv_hash_parity sha256_cbor + xxhash_cbor vs promoted vectors" "$fr4_ok"
# Reference the parity script path so the GPU harness consumer is documented (also drivable via it).
[[ -f "${PARITY}" ]] && echo "  (kv_hash_parity.py present at ${PARITY} for the live Admin-API parity diff)"

#################################################################################
# (scenario 1) two-EP partial-overlap argmax + inventory-mutation flip
#     EP-A holds the divergent partner — a STRICT-SUBSET overlap with shared-prefix-base (only the
#     shared-prefix blocks match). The issued base prompt argmax-selects EP-A (banner==serverP0 AND
#     tier15_hits{0} delta — dual proof, never metrics-only) because nobody else holds ANY of
#     its blocks. Then publish the FULL base prompt to EP-B (mutation): EP-B's overlap now STRICTLY
#     exceeds EP-A's subset; re-issuing the IDENTICAL prompt must FLIP the winner to EP-B (serverP1).
#
#     SEEDING NOTE (live-proven semantics): the Go argmax is `score > best` over a RANDOMIZED map
#     iteration — a tie is nondeterministic, so the flip target must STRICTLY exceed the prior
#     winner. And each new publisher process triggers the subscriber's reconnect-CLEAR, so a
#     publish REPLACES that EP's inventory (it does not accumulate). EP-A therefore gets the
#     DIVERGENT prompt (subset overlap=shared blocks only), never the full base — publishing base
#     to A first would tie 4-4 with B after the mutation and the flip could never assert.
#################################################################################
echo "=== (scenario 1) partial-overlap argmax + inventory-mutation flip (dual proof) ==="
publish_prompt_to_ep "shared-prefix-divergent" "${EP_A_IP}"   # EP-A: shared-prefix SUBSET overlap only
# P/D-FLOW BANNER SEMANTICS (applies to every dual-proof below): with a valid OpenAI JSON
# body the FULL P/D orchestration engages — loxilb sends the rewritten request to the
# Tier-1.5-SELECTED prefill EP (internal leg), then the decode leg answers the client. The
# client-visible banner is therefore a DECODE echo (serverD*) — the prefill choice is NOT
# client-observable BY DESIGN. Dual proof = banner==serverD* (the request traversed the full
# P/D flow, not simple-proxy/RR) AND tier15_hits{expected_prefill_idx} delta (THE selection
# proof). The original serverP* expectations dated from the text/plain era, when the
# unparseable body bypassed P/D orchestration entirely and simple-proxied to a prefill.
hits_a_before=$(tier15_hits "${EP_A_IDX}")
banner1=$(request_and_banner "shared-prefix-base")
hits_a_after=$(tier15_hits "${EP_A_IDX}")
s1_deliver=$([[ "$banner1" == server"D"* ]] && echo 1 || echo 0)
s1_decision=$([[ "$hits_a_after" -gt "$hits_a_before" ]] && echo 1 || echo 0)
echo "  argmax: banner=${banner1} (want serverD* — P/D flow) ; tier15_hits{0} ${hits_a_before}->${hits_a_after} (want delta — EP-A selected)"
s1_ok=$([[ "$s1_deliver" == 1 && "$s1_decision" == 1 ]] && echo 1 || echo 0)
assert "(scenario 1) argmax selects EP-A (banner==serverD* P/D flow AND tier15_hits{0} delta — dual proof)" "$s1_ok"

# mutation: publish the FULL base prompt to EP-B — its overlap (all blocks) now STRICTLY
# exceeds EP-A's shared-prefix subset. Re-issuing the SAME prompt must FLIP the winner to EP-B
# (serverP1) AND increment tier15_hits{2}.
publish_prompt_to_ep "shared-prefix-base" "${EP_B_IP}"   # EP-B: the FULL base prompt (strict winner)
hits_b_before=$(tier15_hits "${EP_B_IDX}")
banner2=$(request_and_banner "shared-prefix-base")
hits_b_after=$(tier15_hits "${EP_B_IDX}")
flip_deliver=$([[ "$banner2" == server"D"* ]] && echo 1 || echo 0)
flip_decision=$([[ "$hits_b_after" -gt "$hits_b_before" ]] && echo 1 || echo 0)
echo "  flip: banner=${banner2} (want serverD* — P/D flow) ; tier15_hits{2} ${hits_b_before}->${hits_b_after} (want delta — flipped to EP-B)"
fr1_ok=$([[ "$flip_deliver" == 1 && "$flip_decision" == 1 ]] && echo 1 || echo 0)
assert "(scenario 1) inventory-mutation FLIPS the re-issued prompt to EP-B (banner==serverD* AND tier15_hits{2} delta)" "$fr1_ok"

#################################################################################
# (scenario 2) non-contiguous prefill bitmask — best EP at a NON-ADJACENT abs index still selected
#     noncontiguous-bitmask-target's blocks are published ONLY to EP-C (abs idx 4, the highest prefill
#     index). The request must route to EP-C (serverP2) — proving the C<->Go bitmask correctly
#     maps a winning prefill EP at a non-contiguous absolute index. Dual proof: banner AND tier15_hits{4}.
#################################################################################
echo "=== (scenario 2) non-contiguous prefill bitmask: best EP at abs idx 4 (EP-C) selected ==="
publish_prompt_to_ep "noncontiguous-bitmask-target" "${EP_C_IP}"
hits_c_before=$(tier15_hits "${EP_C_IDX}")
banner3=$(request_and_banner "noncontiguous-bitmask-target")
hits_c_after=$(tier15_hits "${EP_C_IDX}")
s2_deliver=$([[ "$banner3" == server"D"* ]] && echo 1 || echo 0)
s2_decision=$([[ "$hits_c_after" -gt "$hits_c_before" ]] && echo 1 || echo 0)
echo "  bitmask: banner=${banner3} (want serverD* — P/D flow) ; tier15_hits{4} ${hits_c_before}->${hits_c_after} (want delta — EP-C selected)"
s2_ok=$([[ "$s2_deliver" == 1 && "$s2_decision" == 1 ]] && echo 1 || echo 0)
assert "(scenario 2) non-adjacent prefill index EP-C selected (banner==serverD* AND tier15_hits{4} delta — dual proof)" "$s2_ok"

#################################################################################
# (scenario 3) excluded / circuit-broken overlap-winner -> 2nd-best PREFILL EP (NOT Tier-2 RR)
#     With EP-B (the shared-prefix-base overlap WINNER after the scenario-1 flip) DEAD, the request
#     must fall to the 2nd-best PREFILL EP with base-overlap: EP-A (serverP0, subset overlap from
#     the divergent publish). NOT a decode EP and NOT Tier-2 RR.
#     Exclusion mechanism = the architecture's REAL one: mid-cycle failover. EP-B's :80 is made
#     to RST every connect, so the prefill-leg TCP connect FAILS and the retry passes
#     excluded_mask(1<<EP_B) into pd_select_prefill — the kv-exact argmax picks the genuine
#     2nd-best. Two prior variants were live-disproven on the 2026-06-11 gate/verify:
#       - probe-misdirection (probe -> tcp:9, REST state nok): probe state never propagates
#         into the sockproxy data plane's tepval->eps[].inv — the "down" EP-B kept serving.
#       - docker pause: the freezer stops the server PROCESS but the netns kernel still
#         completes the TCP handshake (listen backlog) — connect SUCCEEDS, no failover, the
#         request just stalls to the client timeout (banner empty, no hits delta).
#################################################################################
echo "=== (scenario 3) excluded/CB-open winner falls to 2nd-best PREFILL EP (not Tier-2 RR) ==="
# RST-reject EP-B's :80 INSIDE ITS NETNS via the HOST iptables binary (the alpine container
# image has no iptables; `ip netns exec` sidesteps that). Connect -> instant RST -> mid-cycle
# failover. The netns + ZMQ publisher (:5557, host process) stay up, so EP-B's KV inventory
# stays warm and the argmax still ranks it FIRST: exactly the excluded-winner scenario.
EP_B_CONT="$(netns_for_ep_ip "${EP_B_IP}")"
$hexec "${EP_B_CONT}" iptables -A INPUT -p tcp --dport 80 -j REJECT --reject-with tcp-reset
sleep 2   # settle: in-flight accepts drain; next connect gets RST
echo "  EP-B (${EP_B_CONT}) :80 now RST-rejecting (winner dead -> prefill connect must fail over)"
# 2nd-best proof under P/D-flow semantics: EP-A (idx 0) is the only remaining prefill holding
# base blocks (EP-C holds only the noncontiguous prompt — overlap 0, not selectable), so the
# Go argmax (which SKIPS excluded EPs via the inv/CB-seeded mask) must pick EP-A:
# tier15_hits{0} delta. Banner = serverD*.
hits_a3_before=$(tier15_hits "${EP_A_IDX}")
banner4=$(request_and_banner "shared-prefix-base")
hits_a3_after=$(tier15_hits "${EP_A_IDX}")
s3_deliver=$([[ "$banner4" == server"D"* ]] && echo 1 || echo 0)
s3_decision=$([[ "$hits_a3_after" -gt "$hits_a3_before" ]] && echo 1 || echo 0)
echo "  excluded EP-B (winner): banner=${banner4} (want serverD*) ; tier15_hits{0} ${hits_a3_before}->${hits_a3_after} (want delta — 2nd-best EP-A)"
s3_ok=$([[ "$s3_deliver" == 1 && "$s3_decision" == 1 ]] && echo 1 || echo 0)
assert "(scenario 3) excluded winner -> 2nd-best PREFILL EP (banner==serverD* AND tier15_hits{0} delta)" "$s3_ok"
# Restore EP-B (drop the RST rule) so later legs see the full prefill set.
$hexec "${EP_B_CONT}" iptables -D INPUT -p tcp --dport 80 -j REJECT --reject-with tcp-reset 2>/dev/null || true
sleep 3   # let EP-B's probes/CB settle back to UP before the next leg

#################################################################################
# (scenario 4) warmup grace + tokenize/no-worker miss -> Tier-2 RR fallthrough + miss-reason{reason}
#     warmup-miss-fresh is NEVER pre-published (zero overlap). KV selection must FALL THROUGH to Tier-2
#     RR and the corresponding loxilb_pd_kv_tier15_miss_reason_total{reason} + fallthrough counter must
#     increment. The exact warmup-expiry moment is timing-sensitive -> soft(); the miss-reason +
#     fallthrough increment is HARD.
#################################################################################
echo "=== (scenario 4) fresh no-overlap prompt -> Tier-2 RR fallthrough + miss-reason increments ==="
miss_before=$(metric_val "loxilb_pd_kv_tier15_miss_reason_total")
fall_before=$(metric_val "loxilb_pd_kv_tier15_fallthrough_total")
banner5=$(request_and_banner "warmup-miss-fresh")
# BRIDGE LATENCY: tier15_hits increments in Go instantly, but miss_reason/fallthrough are
# C-side atomics bridged into prometheus by a 10s TICKER (StartKvMetricsBridge) — an
# immediate read sees the pre-tick value (live-proven: read 0->0 while the evidence dump
# seconds later showed fallthrough=1). Poll past the tick for the delta (cap 15s).
miss_after="${miss_before}"; fall_after="${fall_before}"
for _ in $(seq 1 15); do
    miss_after=$(metric_val "loxilb_pd_kv_tier15_miss_reason_total")
    fall_after=$(metric_val "loxilb_pd_kv_tier15_fallthrough_total")
    [[ "$miss_after" -gt "$miss_before" && "$fall_after" -gt "$fall_before" ]] && break
    sleep 1
done
s4_miss=$([[ "$miss_after" -gt "$miss_before" ]] && echo 1 || echo 0)
s4_fall=$([[ "$fall_after" -gt "$fall_before" ]] && echo 1 || echo 0)
echo "  fresh-prompt: banner=${banner5} ; miss_reason ${miss_before}->${miss_after} ; fallthrough ${fall_before}->${fall_after}"
s4_ok=$([[ "$s4_miss" == 1 && "$s4_fall" == 1 ]] && echo 1 || echo 0)
assert "(scenario 4) no-overlap -> Tier-2 RR fallthrough + tier15_miss_reason{reason} increments" "$s4_ok"
# MISS ATTRIBUTION (was: `fall_after -ge fall_before`, a TAUTOLOGY — a prometheus counter can
# only ever go up, so that sub-check passed unconditionally and proved nothing). What actually
# matters is WHICH guard the miss is attributed to: a no-overlap prompt must miss on
# `no_worker` (no EP inventory matches) or `warmup` (guard B window). A miss attributed to
# model_empty / text_empty / tokenize / hashes means the request never reached the selector
# with a usable prefix key — the silent-Tier-2-RR failure mode documented at request_and_banner
# (a bare text/plain POST produced miss_reason{model_empty}=5, tier15_hits=0, and every routing
# number below then measured RR instead of KV routing). That is a real regression -> HARD.
s4_expected=$(( $(metric_val 'loxilb_pd_kv_tier15_miss_reason_total\{reason="no_worker"') \
              + $(metric_val 'loxilb_pd_kv_tier15_miss_reason_total\{reason="warmup"') ))
s4_shape=$(( $(metric_val 'loxilb_pd_kv_tier15_miss_reason_total\{reason="model_empty"') \
            + $(metric_val 'loxilb_pd_kv_tier15_miss_reason_total\{reason="text_empty"') \
            + $(metric_val 'loxilb_pd_kv_tier15_miss_reason_total\{reason="tokenize"') \
            + $(metric_val 'loxilb_pd_kv_tier15_miss_reason_total\{reason="hashes"') ))
echo "  miss attribution: expected-guard(no_worker+warmup)=${s4_expected} ; request-shape(model_empty+text_empty+tokenize+hashes)=${s4_shape}"
s4_attr_ok=$([[ "$s4_expected" -gt 0 && "$s4_shape" == 0 ]] && echo 1 || echo 0)
assert "(scenario 4) miss attributed to an EXPECTED guard (no_worker/warmup), NOT a request-shape guard" "$s4_attr_ok"

#################################################################################
# /metrics counter deltas for the 9 routing counters (miss-reason is ONE CounterVec{reason})
#     The 9 counters: tier15_hits{ep_idx}, t15_miss_reason_total{reason} (one CounterVec), t15_fallthrough_total,
#     kv_subscriber_connected{service,ep}, kv_subscriber_reconnect_total{...}, kv_subscriber_recv_error_total{...}.
#     Assert the routing-decision counters MOVED across the scenarios above (non-zero hits + fallthrough).
#################################################################################
echo "=== /metrics surfaces the routing counters with non-zero deltas ==="
m_hits=$(metric_val "loxilb_pd_kv_tier15_hits_total")
m_fall=$(metric_val "loxilb_pd_kv_tier15_fallthrough_total")
m_conn=$(llb_curl "${METRICS}" 2>/dev/null | grep -cE "loxilb_kv_subscriber_connected")
echo "  tier15_hits(sum)=${m_hits} ; tier15_fallthrough=${m_fall} ; subscriber_connected lines=${m_conn}"
# PRESENCE, not just values: the previous form claimed "9 routing counters present" but only
# ever read 3 numbers — a renamed/unregistered metric family surfaced as a 0 value, never as a
# missing family. Enumerate the families that MUST exist by this point (the scenarios above
# have exercised every one) and NAME the missing ones on failure.
metrics_snapshot=$(llb_curl "${METRICS}" 2>/dev/null)
fr5_missing=""
for _fam in loxilb_pd_kv_tier15_hits_total loxilb_pd_kv_tier15_miss_reason_total \
            loxilb_pd_kv_tier15_fallthrough_total loxilb_kv_subscriber_connected \
            loxilb_pd_kv_blocks; do
    echo "${metrics_snapshot}" | grep -qE "^${_fam}[ {]" || fr5_missing="${fr5_missing} ${_fam}"
done
[[ -n "${fr5_missing}" ]] && echo "  MISSING metric families:${fr5_missing}"
fr5_ok=$([[ "$m_hits" -gt 0 && "$m_fall" -gt 0 && "$m_conn" -ge 1 && -z "${fr5_missing}" ]] && echo 1 || echo 0)
assert "routing counters: all 5 pre-chaos families present + non-zero tier15_hits/fallthrough deltas" "$fr5_ok"

#################################################################################
# (scenario 5) LONG-CONTEXT / coding-assistant suite — escape parity, TCP
#     fragmentation, deep-context truncation parity, oversize fail-open, and
#     long-response integrity. These legs exist because the base corpus was
#     deliberately "JSON-escape-clean and <= MAX_PREFIX_LEN" — i.e. it DODGED the
#     regime a real coding assistant lives in (kilobytes of \n/\t/\"-laden code).
#     Detection provenance (A/B-proven against the pre-fix image):
#       5a/5b/5c FAIL without the escape-parity fix (selector tokenized RAW
#                escaped bytes -> zero block parity -> silent Tier-2 RR on every
#                code prompt);
#       5a-resp FAILS without the prefill-response-buffer fix (a >=64KB response
#                overflowed the 64KB PREFILL
#                response buffer -> completion check could never fire -> the flow
#                sat in PREFILL_WAITING forever; client got NOTHING, http=000.
#                Live-proven threshold: resp<=32KB fine, >=64KB total wedge);
#       5d      FAILS without the oversize-JSON stream fallback (>1MB JSON hit
#                the 95% rcvbuf guard -> the
#                connection was RESET instead of served).
#################################################################################
echo "=== (scenario 5) long-context coding-assistant suite (escape parity + fragmentation + fail-open) ==="
LONGCTX_CORPUS="${CFGDIR}/.corpus-longctx.json"
python3 "${CFGDIR}/prompts/gen_longctx.py" --emit-corpus "${CORPUS}" "${LONGCTX_CORPUS}" >/dev/null
CORPUS_SAVED="${CORPUS}"
CORPUS="${LONGCTX_CORPUS}"   # publish/request helpers read ${CORPUS} at call time

# longctx_body_file <prompt-id> <outfile> — full /v1/completions request body as a
# FILE: the long prompts (12KB/40KB) stay off argv, and curl --data-binary @file
# is byte-exact (no shell mangling of the code text).
longctx_body_file() {
    python3 - "$1" "$2" "${CORPUS}" "${KV_MODEL}" <<'PYBODY'
import json, sys
pid, out, corpus, model = sys.argv[1:5]
d = json.load(open(corpus))
for p in d["prompts"]:
    if p["id"] == pid:
        json.dump({"model": model, "prompt": p["prompt"], "max_tokens": 8},
                  open(out, "w"))
        break
PYBODY
}

# ── (5a) 12KB real-code prompt (escapes everywhere) -> published EP-B wins the
#        argmax over a request body spanning many TCP segments, AND a 256KB
#        response rides back byte-exact (?resp_bytes long-response canary). ──
publish_prompt_to_ep "longctx-code-review" "${EP_B_IP}"
lc5a_hits_before=$(tier15_hits "${EP_B_IDX}")
lc5a_body="${CFGDIR}/.longctx-req-5a.json"
lc5a_resp="${CFGDIR}/.longctx-resp-5a.bin"
longctx_body_file "longctx-code-review" "${lc5a_body}"
LC5A_FILL=262144
lc5a_stat=$($hexec l3h1 curl -s -o "${lc5a_resp}" -w '%{http_code} %{size_download}' \
    --max-time 30 -X POST "http://${VIP}:${VPORT}/v1/completions?resp_bytes=${LC5A_FILL}" \
    -H 'Content-Type: application/json' --data-binary @"${lc5a_body}" 2>/dev/null)
lc5a_code="${lc5a_stat%% *}"; lc5a_dl="${lc5a_stat##* }"
lc5a_banner=$(head -c 200 "${lc5a_resp}" 2>/dev/null | grep -Eo 'server[PD][0-9]' | head -1)
sleep 2
lc5a_hits_after=$(tier15_hits "${EP_B_IDX}")
echo "  5a: http=${lc5a_code} banner=${lc5a_banner} tier15_hits{${EP_B_IDX}} ${lc5a_hits_before}->${lc5a_hits_after} dl=${lc5a_dl}B"
lc5a_ok=$([[ "${lc5a_code}" == "200" && "${lc5a_banner}" == serverD* && \
             "${lc5a_hits_after}" -gt "${lc5a_hits_before}" ]] && echo 1 || echo 0)
assert "(scenario 5a) 12KB code prompt (\\n/\\t/\\\" escapes) routes Tier-1.5 to the published EP-B" "$lc5a_ok"
# Long-response integrity: full filler arrived AND the trailing 26 bytes are the
# exact cycle the backend generates (a truncated/torn response breaks both).
lc5a_tail_want=$(python3 -c "n=${LC5A_FILL}; print(''.join(chr(ord('A')+i%26) for i in range(n-26,n)))")
lc5a_tail_got=$(tail -c 26 "${lc5a_resp}" 2>/dev/null)
lc5a_resp_ok=$([[ "${lc5a_dl}" -ge "${LC5A_FILL}" && "${lc5a_tail_got}" == "${lc5a_tail_want}" ]] && echo 1 || echo 0)
echo "  5a-resp: size_download=${lc5a_dl} (want >=${LC5A_FILL}) tail26=$([[ ${lc5a_resp_ok} == 1 ]] && echo match || echo MISMATCH)"
assert "(scenario 5a) 256KB response through the fullproxy arrives byte-exact (count + tail)" "$lc5a_resp_ok"

# ── (5b) SAME 12KB prompt via a slow fragmented writer (--limit-rate 8k => the
#        body dribbles in over ~1.5s across many reads) -> identical routing.
#        Pins the multi-read rcvbuf accumulation + parse-after-complete path. ──
lc5b_hits_before=$(tier15_hits "${EP_B_IDX}")
lc5b_banner=$($hexec l3h1 curl -s --max-time 60 --limit-rate 8k \
    -X POST "http://${VIP}:${VPORT}/v1/completions" \
    -H 'Content-Type: application/json' --data-binary @"${lc5a_body}" 2>/dev/null \
    | grep -Eo 'server[PD][0-9]' | head -1)
sleep 2
lc5b_hits_after=$(tier15_hits "${EP_B_IDX}")
echo "  5b: banner=${lc5b_banner} tier15_hits{${EP_B_IDX}} ${lc5b_hits_before}->${lc5b_hits_after} (slow fragmented writer)"
lc5b_ok=$([[ "${lc5b_banner}" == serverD* && "${lc5b_hits_after}" -gt "${lc5b_hits_before}" ]] && echo 1 || echo 0)
assert "(scenario 5b) slow fragmented delivery (multi-read assembly) routes identically" "$lc5b_ok"

# ── (5c) 40KB deep-context prompt -> truncation parity: the publisher hashes the
#        FULL chain (~10K tokens), loxilb only the MAX_PREFIX_LEN-truncated head —
#        the leading blocks must still match and route to the publisher EP-C. ──
publish_prompt_to_ep "longctx-deep-context" "${EP_C_IP}"
lc5c_hits_before=$(tier15_hits "${EP_C_IDX}")
lc5c_body="${CFGDIR}/.longctx-req-5c.json"
longctx_body_file "longctx-deep-context" "${lc5c_body}"
lc5c_banner=$($hexec l3h1 curl -s --max-time 30 \
    -X POST "http://${VIP}:${VPORT}/v1/completions" \
    -H 'Content-Type: application/json' --data-binary @"${lc5c_body}" 2>/dev/null \
    | grep -Eo 'server[PD][0-9]' | head -1)
sleep 2
lc5c_hits_after=$(tier15_hits "${EP_C_IDX}")
echo "  5c: banner=${lc5c_banner} tier15_hits{${EP_C_IDX}} ${lc5c_hits_before}->${lc5c_hits_after} (40KB deep context)"
lc5c_ok=$([[ "${lc5c_banner}" == serverD* && "${lc5c_hits_after}" -gt "${lc5c_hits_before}" ]] && echo 1 || echo 0)
assert "(scenario 5c) 40KB deep-context prompt: truncated-head parity still selects the publisher EP" "$lc5c_ok"

# ── (5d) ~1.3MB oversize JSON (beyond the 1MB rcvbuf) -> MUST be served
#        fail-open via the stream fallback, NEVER connection-reset. Dual proof:
#        HTTP 200 + banner (served) AND the structured [JSON_STREAM_FALLBACK]
#        marker in the loxilb log (the specific code path, not incidental RR). ──
lc5d_body="${CFGDIR}/.longctx-req-5d.json"
python3 "${CFGDIR}/prompts/gen_longctx.py" --emit-oversize-body 1258291 "${lc5d_body}" \
    --model "${KV_MODEL}" >/dev/null
lc5d_stat=$($hexec l3h1 curl -s -o "${CFGDIR}/.longctx-resp-5d.bin" -w '%{http_code}' \
    --max-time 60 -X POST "http://${VIP}:${VPORT}/v1/completions" \
    -H 'Content-Type: application/json' --data-binary @"${lc5d_body}" 2>/dev/null)
lc5d_banner=$(head -c 200 "${CFGDIR}/.longctx-resp-5d.bin" 2>/dev/null | grep -Eo 'server[PD][0-9]' | head -1)
# NB: the log dir holds MULTIPLE loxilb*.log files (rotation) — `grep -c` on a
# multi-file glob prints per-file `path:count` lines, which breaks the numeric
# compare below. `grep -h | wc -l` yields one plain total across all files.
lc5d_marker=$(docker exec llb1 sh -c \
    'grep -h "JSON_STREAM_FALLBACK" /var/log/loxilb*.log 2>/dev/null | wc -l' 2>/dev/null | tr -dc 0-9)
lc5d_marker="${lc5d_marker:-0}"
echo "  5d: http=${lc5d_stat} banner=${lc5d_banner} JSON_STREAM_FALLBACK markers=${lc5d_marker} (1.3MB oversize)"
lc5d_ok=$([[ "${lc5d_stat}" == "200" && -n "${lc5d_banner}" && "${lc5d_marker}" -ge 1 ]] && echo 1 || echo 0)
assert "(scenario 5d) oversize (1.3MB) JSON served fail-open via stream fallback (200 + marker), not reset" "$lc5d_ok"

CORPUS="${CORPUS_SAVED}"   # later legs read the base corpus again

#################################################################################
# publisher --kill/restart -> subscriber_connected transition + inventory clear + replay
#     Kill the publisher (socket close) so the subscriber detects a dead connection and rebuilds
#     (inventory clears, reconnect_total++). A fresh publisher then re-publishes from a known seq base
#     with a deliberate seq-jump (replay path). connected gauge + reconnect counter prove liveness; exact
#     reconnect latency is timing-sensitive -> soft.
#################################################################################
echo "=== publisher kill/restart -> subscriber_connected transition + reconnect + replay ==="
reconn_before=$(metric_val "loxilb_kv_subscriber_reconnect_total")
# Kill the running publisher(s) by anchored tag (scoped per-PID — never a host-wide sweep).
kill_publisher
sleep 6   # subscriber detects dead socket + rebuilds (clears inventory)
# Re-publish with --kill + --seq-jump to exercise the rebuild/replay path.
publish_prompt_to_ep "shared-prefix-base" "${EP_A_IP}" --seq-base 100 --seq-jump 5 --kill
sleep 6
reconn_after=$(metric_val "loxilb_kv_subscriber_reconnect_total")
conn_now=$(metric_val "loxilb_kv_subscriber_connected")
fr6_reconn=$([[ "$reconn_after" -gt "$reconn_before" ]] && echo 1 || echo 0)
echo "  reconnect_total ${reconn_before}->${reconn_after} ; connected(sum)=${conn_now}"
fr6_ok=$([[ "$fr6_reconn" == 1 ]] && echo 1 || echo 0)
assert "publisher restart drives subscriber rebuild (reconnect_total increments)" "$fr6_ok"
# Exact reconnect latency is inherently non-deterministic -> soft. (`conn_now -ge 0` was a
# TAUTOLOGY: metric_val floors at 0, so it could never be false. The real signal is that the
# subscriber came back UP within the settle window — connected gauge sum >= 1.)
soft "subscriber reconnected within the settle window (connected gauge sum >= 1)" \
     "$([[ "$conn_now" -ge 1 ]] && echo 1 || echo 0)"

#################################################################################
# (chaos matrix + cap/eviction + resync) — the final validation stage for the
#     memory-safety and reconnect-resync Go work. Extends the reconnect leg with
#     the core invariant of the whole scenario: under ANY publisher failure the data plane
#     never breaks — it degrades to Tier-2 min-load. Every assert below is HARD under
#     SKELETON_STRICT=1 and lives under the SAME single SCENARIO-vllm-kvcache-routing-cpu sentinel.
#     Helpers reused verbatim (NO new harness): metric_val, publish_prompt_to_ep, kill_publisher,
#     inv_total (== KVINV Size), tier15_hits, request_and_banner, loxilb_log_count.
#################################################################################

# ── (chaos: down-at-startup) publisher down at startup → empty inventory → EP drops out of argmax → Tier-2 ──
#    A down EP must end with an EMPTY inventory, no longer win argmax (no tier15_hits{down} delta), and
#    the request must still be SERVED via Tier-2 min-load (non-empty banner — the data plane never
#    breaks). best_worker returning -1 for the empty EP is the in-Go expression of this.
#    NOTE: reconnect is now KEEP-on-blip — a dead publisher NO LONGER auto-empties the inventory
#    (the CLEAR is deferred to a first post-reconnect message that never arrives for a down publisher).
#    So drive the down EP to a genuinely empty state through the AllBlocksCleared event path: a RESIDENT
#    publisher (emit-vocabulary ON) whose every pass ends BlockStored -> BlockRemoved -> AllBlocksCleared.
#    It must stay resident long enough for the subscriber to redial after the pre-kill and ingest a full
#    pass; its final emitted event is AllBlocksCleared, so the EP settles at Size 0. (Verified live: 5->0.)
echo "=== (chaos: down-at-startup) publisher-down-at-startup -> empty inventory -> EP out of argmax -> Tier-2 (fail-open) ==="
CHAOS_DOWN_IDX="$(idx_for_ep_ip "${CHAOS_EP_DOWN_IP}")"
kill_publisher                       # drop ALL anchored publishers
sleep 1
D08A_CLEAR_CORPUS="${CFGDIR}/.kvpub-d08a-clear.json"
# FLAT LIST [{"prompt":..}] — the publisher reads 0 prompts from a {"prompts":[..]} object.
python3 -c "import json,sys
json.dump([{'prompt':'d08a transient block then cleared filler '*8}], open(sys.argv[1],'w'))" "${D08A_CLEAR_CORPUS}" 2>/dev/null
D08A_CLEAR_LOG="${CFGDIR}/.kvpub-d08a-clear.log"
setsid $hexec "$(netns_for_ep_ip "${CHAOS_EP_DOWN_IP}")" bash -c "export PYTHONPATH='${PY_USER_SITE}' PYTHONHASHSEED=0; exec -a ${PUB_TAG} python3 '${PUBLISHER}' \
    --corpus '${D08A_CLEAR_CORPUS}' --tokenizer '${TOKENIZER_SRC}' --vectors '${VECTORS_SRC}' \
    --bind '${CHAOS_EP_DOWN_IP}' --port ${KV_ZMQ_PORT} --algo ${KV_HASH_ALGO} \
    --block-size ${KV_BLOCK_SIZE} --seq-base 7000 --repeat 3 --repeat-interval 4" >"${D08A_CLEAR_LOG}" 2>&1 &
sleep 20                             # redial + add->BlockRemoved->AllBlocksCleared ingested; passes end at Size 0
kill_publisher                       # stop the down EP's publisher -> it stays down (empty + unbound)
sleep 2
# Re-bind ONLY the live sibling (NOT the down EP) so the rest of the matrix has a live inventory.
publish_prompt_to_ep "shared-prefix-base" "${CHAOS_EP_LIVE_IP}"
down_size="$(inv_total "${CHAOS_DOWN_IDX}")"
down_hits_before="$(tier15_hits "${CHAOS_DOWN_IDX}")"
# Issue the noncontiguous prompt — the ONLY prompt whose blocks lived on the (now-down) EP-C. With its
# inventory empty it can no longer win argmax; the request must fall through to Tier-2 and still serve.
d08a_banner="$(request_and_banner "noncontiguous-bitmask-target")"
down_hits_after="$(tier15_hits "${CHAOS_DOWN_IDX}")"
d08a_empty=$([[ "${down_size}" -eq 0 ]] && echo 1 || echo 0)
d08a_not_sel=$([[ "${down_hits_after}" -le "${down_hits_before}" ]] && echo 1 || echo 0)   # no delta on the down EP
d08a_served=$([[ -n "${d08a_banner}" ]] && echo 1 || echo 0)                                # Tier-2 still answers
echo "  down EP idx ${CHAOS_DOWN_IDX}: KVINV Size=${down_size} (want 0) ; tier15_hits ${down_hits_before}->${down_hits_after} (want no delta) ; banner=${d08a_banner} (want non-empty Tier-2)"
d08a_ok=$([[ "${d08a_empty}" == 1 && "${d08a_not_sel}" == 1 && "${d08a_served}" == 1 ]] && echo 1 || echo 0)
assert "(chaos: down-at-startup) empty inventory -> EP out of argmax -> Tier-2 fail-open (served)" "$d08a_ok"

# ── (chaos: mid-stream death) mid-stream publisher death → reconnect_total++ AND requests stay served during the gap ──
#    Publish to a LIVE EP, then --kill mid-run. The subscriber must detect the dead socket and rebuild
#    (loxilb_kv_subscriber_reconnect_total increments) WHILE a concurrent request keeps being served
#    via Tier-2 during the inventory gap (fail-open — no data-plane break).
echo "=== (chaos: mid-stream death) mid-stream publisher death -> reconnect_total++ + requests served during the gap (fail-open) ==="
d08b_reconn_before="$(metric_val "loxilb_kv_subscriber_reconnect_total")"
publish_prompt_to_ep "shared-prefix-base" "${CHAOS_EP_LIVE_IP}" --seq-base 200 --seq-jump 7 --kill
# During/after the kill-induced reconnect gap, a request MUST still be answered (Tier-2 fail-open).
d08b_banner="$(request_and_banner "warmup-miss-fresh")"
d08b_reconn_after="${d08b_reconn_before}"
for _ in $(seq 1 15); do
    d08b_reconn_after="$(metric_val "loxilb_kv_subscriber_reconnect_total")"
    [[ "${d08b_reconn_after}" -gt "${d08b_reconn_before}" ]] && break
    sleep 1
done
d08b_reconn=$([[ "${d08b_reconn_after}" -gt "${d08b_reconn_before}" ]] && echo 1 || echo 0)
d08b_served=$([[ -n "${d08b_banner}" ]] && echo 1 || echo 0)
echo "  reconnect_total ${d08b_reconn_before}->${d08b_reconn_after} (want delta) ; gap banner=${d08b_banner} (want non-empty — served during gap)"
d08b_ok=$([[ "${d08b_reconn}" == 1 && "${d08b_served}" == 1 ]] && echo 1 || echo 0)
assert "(chaos: mid-stream death) reconnect_total++ AND request served via Tier-2 during the gap" "$d08b_ok"

# ── (chaos: partial outage) kill ONE EP's publisher, siblings up → down EP stops winning, sibling serves ─
#    Seed BOTH the down candidate and a sibling with the SAME base prompt so both could win argmax;
#    then kill ONLY the down EP's publisher (PID-scoped via the anchored tag) and let its inventory
#    drain. Re-issuing the base prompt must now route to the SIBLING (tier15_hits{sibling} delta) — the
#    down EP no longer wins. Graceful degradation: one publisher down, the service keeps serving.
echo "=== (chaos: partial outage) one EP's publisher down, a sibling keeps winning argmax (graceful degradation) ==="
CHAOS_LIVE_IDX="$(idx_for_ep_ip "${CHAOS_EP_LIVE_IP}")"
# Re-seed the live sibling with the base prompt so it holds the winning overlap once the down EP drains.
publish_prompt_to_ep "shared-prefix-base" "${CHAOS_EP_LIVE_IP}"
# Kill ONLY this suite's publishers (PID-scoped) then re-bind ONLY the sibling — the down EP stays empty.
kill_publisher
sleep 8
publish_prompt_to_ep "shared-prefix-base" "${CHAOS_EP_LIVE_IP}"
live_hits_before="$(tier15_hits "${CHAOS_LIVE_IDX}")"
d08c_banner="$(request_and_banner "shared-prefix-base")"
live_hits_after="$(tier15_hits "${CHAOS_LIVE_IDX}")"
d08c_sibling_wins=$([[ "${live_hits_after}" -gt "${live_hits_before}" ]] && echo 1 || echo 0)
d08c_served=$([[ -n "${d08c_banner}" ]] && echo 1 || echo 0)
echo "  partial outage: sibling idx ${CHAOS_LIVE_IDX} tier15_hits ${live_hits_before}->${live_hits_after} (want delta — sibling wins) ; banner=${d08c_banner}"
d08c_ok=$([[ "${d08c_sibling_wins}" == 1 && "${d08c_served}" == 1 ]] && echo 1 || echo 0)
assert "(chaos: partial outage) down EP stops winning argmax, a sibling keeps serving (graceful degradation)" "$d08c_ok"

# ── (cap/eviction) the conservation identity across the cap, driven from BOTH sides ────────────────────
#
#    config.sh injected LOXILB_KV_MAX_BLOCKS=${KV_MAX_BLOCKS} into llb1. The subscriber's eviction
#    arithmetic (kvInventory.AddBlocks) is not a rate or a rounding: inserting N distinct hashes into an
#    EMPTY inventory capped at C evicts exactly max(0, N-C) and leaves exactly min(N, C) resident. So
#    ONE identity covers both sides of the cap:
#
#        Δ loxilb_kv_inv_cap_evictions_total{ep}  +  KVINV Size{ep}  ==  N
#
#    and the two arms below differ in exactly ONE field — the size of the published corpus:
#
#        UNDER the cap (EP-C, N < C):  Δ == 0 EXACTLY and Size == N
#        OVER  the cap (EP-B, N > C):  Δ == N-C EXACTLY and Size == C
#
#    Why an exact delta and not the previous "moved > 0": a counter held at a nonzero value by anything
#    at all satisfies "> 0", and the family's own writer note says one AddBlocks call can record MANY
#    evictions, so a per-call count is not the oracle either. N is. The under-cap arm is the control the
#    leg previously had none of: same publisher, same flood machinery, same EP lifecycle, corpus smaller
#    than the cap — and the counter must not move AT ALL.
#
#    N is read from the drive side rather than assumed: the publisher reports blocks_total=<distinct
#    published uint64 hashes>. An arm that guesses N from a prompt count is guessing the tokenizer's
#    block split as well.
#
#    Drive shape is proven, not hoped for. --repeat 1 --settle-sec means the publisher binds, waits out
#    loxilb's redial backoff, emits exactly ONE pass and exits; a repeating publisher would re-add the
#    hashes it just had evicted and evict the same count again on every pass, so Δ would be a multiple
#    of N-C with no way to tell which multiple. A partial pass and a double pass BOTH fail the exact
#    equality, which is what makes the identity self-checking. The large --seq-base (>> the EP's
#    lastSeq) makes the subscriber's first post-reconnect message a CLEAR, so the pass fills an EMPTY
#    inventory — the precondition the arithmetic above needs. --no-vocabulary keeps the trailing
#    AllBlocksCleared from wiping the result.
#
#    Attribution is proven, not assumed. The family carries {service,ep}: a mis-attributed eviction
#    moves the FAMILY by exactly as much as a correct one, so each arm reads the ONE series for the EP
#    it flooded and asserts the other two prefill EPs' series stayed FLAT. The flats are the half that
#    makes the attribution real.
#
#    Observability here is the counter + the KVINV Size, NOT a log grep: the Go subscriber logs via
#    logrus to stderr, which loxilb's `docker exec -dt` launch discards (/var/log/loxilb*.log is the
#    loxilib tk-logger only).
#
#    EP choice: EP-C is left EMPTY by the down-at-startup chaos leg above, which is exactly the fresh
#    inventory the under-cap arm wants; the over-cap flood goes to EP-B so neither arm perturbs the
#    EP-A state the resync leg below depends on.

CAP_FAMILY="loxilb_kv_inv_cap_evictions_total"

# cap_publish_one_pass <corpus-file> <ep-ip> <seq-base> <log-file> — bind a publisher on one EP, emit
# EXACTLY one pass after the settle window, wait for it to finish, and echo the blocks_total it
# reported (empty on failure — the caller treats that as FATAL, never as zero).
cap_publish_one_pass() {
    local corpus="$1" ep_ip="$2" seq_base="$3" log="$4" _w
    for _pp in $(pgrep -f "${PUB_TAG}" 2>/dev/null); do kill "${_pp}" >/dev/null 2>&1 || true; done
    sleep 1
    rm -f "${log}"
    setsid $hexec "$(netns_for_ep_ip "${ep_ip}")" bash -c "export PYTHONPATH='${PY_USER_SITE}' PYTHONHASHSEED=0; exec -a ${PUB_TAG} python3 '${PUBLISHER}' \
        --corpus '${corpus}' --tokenizer '${TOKENIZER_SRC}' --vectors '${VECTORS_SRC}' \
        --bind '${ep_ip}' --port ${KV_ZMQ_PORT} --algo ${KV_HASH_ALGO} \
        --block-size ${KV_BLOCK_SIZE} --seq-base ${seq_base} --repeat 1 --settle-sec 20 \
        --no-vocabulary" >"${log}" 2>&1 &
    # Wait on the MECHANISM (the publisher's own completion line), never on a clock: the settle window
    # alone says nothing about whether the pass was emitted.
    for _w in $(seq 1 90); do
        grep -q '^PUBLISH done:' "${log}" 2>/dev/null && break
        sleep 1
    done
    sed -n 's/^PUBLISH done:.*blocks_total=\([0-9][0-9]*\).*/\1/p' "${log}" 2>/dev/null | head -1
}

# cap_settled_size <ep_idx> — the EP's KVINV Size once it has stopped moving (3 equal consecutive
# samples). Ingest of a ~2000-block pass is not instantaneous and a single read can catch it mid-flight.
cap_settled_size() {
    local idx="$1" prev="" cur stable=0 _w
    for _w in $(seq 1 60); do
        cur="$(inv_total "${idx}")"
        if [[ "${cur}" == "${prev}" ]]; then
            stable=$((stable + 1))
            [[ "${stable}" -ge 2 ]] && { echo "${cur}"; return; }
        else
            stable=0
        fi
        prev="${cur}"
        sleep 1
    done
    echo "${prev:-0}"
}

echo "=== (cap/eviction) conservation across the cap (${KV_MAX_BLOCKS}): evictions{ep} + Size{ep} == distinct published ==="

# The publisher consumes a FLAT LIST [{"prompt":..}], NOT {"prompts":[..]} (same shape config.sh's
# baseline + publish_prompt_to_ep write). A {"prompts":[..]} object makes it read 0 prompts (silent).
# Block hashes are CONTENT-derived, NOT seq-derived: re-publishing one corpus at a different --seq-base
# yields IDENTICAL hashes and never grows the inventory. Each synthetic prompt carries its own index so
# the prefix chains — and therefore every block hash — differ across prompts.
CAP_UNDER_CORPUS="${CFGDIR}/.kvpub-cap-under.json"
CAP_FLOOD_CORPUS="${CFGDIR}/.kvpub-cap-flood.json"
python3 -c "import json,sys
json.dump([{'prompt':('cap under distinct filler block number %03d '%i)*48} for i in range(8)],
  open(sys.argv[1],'w'))" "${CAP_UNDER_CORPUS}" 2>/dev/null
python3 -c "import json,sys
json.dump([{'prompt':('cap flood distinct filler block number %03d '%i)*48} for i in range(60)],
  open(sys.argv[1],'w'))" "${CAP_FLOOD_CORPUS}" 2>/dev/null

# ---- arm 1: UNDER the cap (control) — same machinery, smaller corpus, counter must not move ----------
cap_u_a_before="$(metric_series "${CAP_FAMILY}" ep "${EP_A_IDX}")"
cap_u_b_before="$(metric_series "${CAP_FAMILY}" ep "${EP_B_IDX}")"
cap_u_c_before="$(metric_series "${CAP_FAMILY}" ep "${EP_C_IDX}")"
CAP_UNDER_LOG="${CFGDIR}/.kvpub-cap-under.log"
cap_u_n="$(cap_publish_one_pass "${CAP_UNDER_CORPUS}" "${EP_C_IP}" 8000 "${CAP_UNDER_LOG}")"
cap_u_size="$(cap_settled_size "${EP_C_IDX}")"
cap_u_a_after="$(metric_series "${CAP_FAMILY}" ep "${EP_A_IDX}")"
cap_u_b_after="$(metric_series "${CAP_FAMILY}" ep "${EP_B_IDX}")"
cap_u_c_after="$(metric_series "${CAP_FAMILY}" ep "${EP_C_IDX}")"
# An unread blocks_total is a LOST MEASUREMENT, never a zero: score it as a hard failure.
cap_u_shape=$([[ -n "${cap_u_n}" && "${cap_u_n}" -gt 0 && "${cap_u_n}" -lt "${KV_MAX_BLOCKS}" ]] && echo 1 || echo 0)
cap_u_delta=$((cap_u_c_after - cap_u_c_before))
cap_u_flat=$([[ "${cap_u_a_after}" -eq "${cap_u_a_before}" && "${cap_u_b_after}" -eq "${cap_u_b_before}" ]] && echo 1 || echo 0)
echo "  under-cap arm (EP-C idx ${EP_C_IDX}): published N=${cap_u_n:-<UNREAD>} (want 0<N<${KV_MAX_BLOCKS}) ; evictions{ep=${EP_C_IDX}} ${cap_u_c_before}->${cap_u_c_after} (want +0 EXACT) ; Size=${cap_u_size} (want ==N) ; siblings ep=${EP_A_IDX} ${cap_u_a_before}->${cap_u_a_after} ep=${EP_B_IDX} ${cap_u_b_before}->${cap_u_b_after} (want FLAT)"
cap_u_ok=$([[ "${cap_u_shape}" == 1 && "${cap_u_delta}" -eq 0 && "${cap_u_size}" -eq "${cap_u_n}" && "${cap_u_flat}" == 1 ]] && echo 1 || echo 0)
assert "(cap control) a corpus UNDER the cap evicts EXACTLY nothing: delta 0, Size == N published, siblings flat" "$cap_u_ok"

# ---- arm 2: OVER the cap (drive) — one field changed, the counter must move by EXACTLY N-cap ---------
cap_o_a_before="${cap_u_a_after}"
cap_o_b_before="${cap_u_b_after}"
cap_o_c_before="${cap_u_c_after}"
CAP_FLOOD_LOG="${CFGDIR}/.kvpub-cap-flood.log"
cap_o_n="$(cap_publish_one_pass "${CAP_FLOOD_CORPUS}" "${EP_B_IP}" 9000 "${CAP_FLOOD_LOG}")"
cap_o_size="$(cap_settled_size "${EP_B_IDX}")"
cap_o_a_after="$(metric_series "${CAP_FAMILY}" ep "${EP_A_IDX}")"
cap_o_b_after="$(metric_series "${CAP_FAMILY}" ep "${EP_B_IDX}")"
cap_o_c_after="$(metric_series "${CAP_FAMILY}" ep "${EP_C_IDX}")"
cap_o_shape=$([[ -n "${cap_o_n}" && "${cap_o_n}" -gt "${KV_MAX_BLOCKS}" ]] && echo 1 || echo 0)
cap_o_delta=$((cap_o_b_after - cap_o_b_before))
cap_o_want=$((${cap_o_n:-0} - KV_MAX_BLOCKS))
cap_o_flat=$([[ "${cap_o_a_after}" -eq "${cap_o_a_before}" && "${cap_o_c_after}" -eq "${cap_o_c_before}" ]] && echo 1 || echo 0)
echo "  over-cap arm (EP-B idx ${EP_B_IDX}): published N=${cap_o_n:-<UNREAD>} (want N>${KV_MAX_BLOCKS}) ; evictions{ep=${EP_B_IDX}} ${cap_o_b_before}->${cap_o_b_after} delta=${cap_o_delta} (want ${cap_o_want} EXACT) ; Size=${cap_o_size} (want ==${KV_MAX_BLOCKS}) ; siblings ep=${EP_A_IDX} ${cap_o_a_before}->${cap_o_a_after} ep=${EP_C_IDX} ${cap_o_c_before}->${cap_o_c_after} (want FLAT)"
cap_o_ok=$([[ "${cap_o_shape}" == 1 && "${cap_o_delta}" -eq "${cap_o_want}" && "${cap_o_size}" -eq "${KV_MAX_BLOCKS}" && "${cap_o_flat}" == 1 ]] && echo 1 || echo 0)
assert "(cap drive) a corpus OVER the cap evicts EXACTLY N-cap, Size pins at the cap, siblings flat" "$cap_o_ok"

# ---- the identity itself, stated once over both arms -------------------------------------------------
# evicted + resident == published, on both sides of the cap. This is the claim the two arms above make
# jointly; asserting it separately means a future change that breaks the invariant while keeping each
# arm's individual numbers self-consistent still goes red.
cap_id_u=$([[ $((cap_u_delta + cap_u_size)) -eq "${cap_u_n:-0}" ]] && echo 1 || echo 0)
cap_id_o=$([[ $((cap_o_delta + cap_o_size)) -eq "${cap_o_n:-0}" ]] && echo 1 || echo 0)
echo "  conservation: under-cap ${cap_u_delta}+${cap_u_size}==${cap_u_n:-<UNREAD>} -> ${cap_id_u} ; over-cap ${cap_o_delta}+${cap_o_size}==${cap_o_n:-<UNREAD>} -> ${cap_id_o}"
cap_ok=$([[ "${cap_id_u}" == 1 && "${cap_id_o}" == 1 ]] && echo 1 || echo 0)
assert "(cap) evictions{ep} + KVINV Size{ep} == distinct blocks published, on BOTH sides of the cap" "$cap_ok"

# ── (resync KEEP/CLEAR) transient blip KEEPs the warm inventory; a low-seq restart CLEARs it ───────────
#    The seq-reset discriminator replaced the unconditional reconnect ClearAll: a --kill where
#    seq RESUMES near lastSeq is a transient blip => KEEP (KVINV Size preserved); a restart
#    where seq RESETS low => CLEAR (Size drops to the post-restart set). Prove BOTH on EP-A. The CLEAR
#    half is anchored to the STRUCTURED resync-CLEAR log marker, never the bare AllBlocksCleared.
echo "=== (resync) transient blip KEEPs warm inventory ; low-seq restart CLEARs (structured-marker-anchored) ==="
# Seed EP-A and record its warm Size at a known high seq base.
publish_prompt_to_ep "shared-prefix-base" "${EP_A_IP}" --seq-base 5000
resync_warm_size="$(inv_total "${EP_A_IDX}")"
# KEEP: a --kill blip whose seq RESUMES just past the warm lastSeq (within the kvSeqResumeWindow) — the
# warm inventory must be PRESERVED (Size stays >= the warm set; the blip did not wipe it).
publish_prompt_to_ep "shared-prefix-base" "${EP_A_IP}" --seq-base 5008 --kill
sleep 8
publish_prompt_to_ep "shared-prefix-base" "${EP_A_IP}" --seq-base 5016
resync_keep_size="$(inv_total "${EP_A_IDX}")"
# CLEAR: a restart whose seq RESETS to a LOW base must DROP the stale warm inventory. A real restart =
# a socket DROP (subscriber rebuild) FOLLOWED BY a first post-reconnect message whose seq RESET low. An
# external SIGTERM does NOT surface the go-zeromq connection-lost error (ZMQ transparently reconnects),
# so the rebuild — and thus the resync decision — only fires on a publisher --kill (pub.close => clean
# EOF). Mirror the KEEP leg: a --kill blip forces the rebuild, then a LOW-seq publish of a DISJOINT,
# SMALLER prompt (warmup-miss-fresh ~2 blocks vs base ~4) is the first post-reconnect message =>
# kvResyncDecision(seq=1, lastSeq~5024) => CLEAR. Signal: the warm base is dropped, so Size falls to the
# fresh-only set (< warm). Were it NOT cleared, Size would be union(base,fresh) > warm. (No log grep —
# the Go resync marker logs to discarded stderr; the observable contract is the inventory Size.)
publish_prompt_to_ep "shared-prefix-base" "${EP_A_IP}" --seq-base 5024 --kill
sleep 8
publish_prompt_to_ep "warmup-miss-fresh" "${EP_A_IP}" --seq-base 1
sleep 6   # let the first-post-reconnect CLEAR + fresh ingest settle
resync_clear_size="$(inv_total "${EP_A_IDX}")"
resync_keep_ok=$([[ "${resync_keep_size}" -ge "${resync_warm_size}" && "${resync_warm_size}" -gt 0 ]] && echo 1 || echo 0)
# CLEAR proven: stale base dropped => Size fell BELOW the warm set (to the disjoint fresh-only set), and
# is still > 0 (the fresh set was ingested). union(base,fresh) would be > warm — the not-cleared case.
resync_clear_ok=$([[ "${resync_clear_size}" -gt 0 && "${resync_clear_size}" -lt "${resync_warm_size}" ]] && echo 1 || echo 0)
echo "  KEEP: warm Size=${resync_warm_size} -> after blip Size=${resync_keep_size} (want preserved >= warm)"
echo "  CLEAR: warm Size=${resync_warm_size} -> after low-seq restart Size=${resync_clear_size} (want < warm: stale base dropped, fresh-only)"
resync_ok=$([[ "${resync_keep_ok}" == 1 && "${resync_clear_ok}" == 1 ]] && echo 1 || echo 0)
assert "(resync) transient blip KEEPs warm inventory AND a low-seq restart CLEARs (Size drops to fresh-only)" "$resync_ok"

# ── (spill) the load-aware selector leaves the affinity winner when that winner is in flight ───────────
#
#    loxilb_pd_kv_tier15_spills_total{ep_idx} has ONE writer repo-wide (ai_kv_subscriber.go, inside
#    llb_ai_kv_best_worker) and fires when the bounded-load arm moves the choice OFF the pure-overlap
#    argmax. Reading the gate rather than the family name matters here: every term is drivable on this
#    CPU bed and NONE of them needs a GPU or an engine.
#
#      * the arm is live      — kvLbMode() is "hard" unless LOXILB_KV_LB_MODE / the legacy
#                               LOXILB_KV_UNIFIED_MODE says otherwise, which this scenario does not set.
#      * the candidate set    — only endpoints with POSITIVE overlap are candidates. A prefix published
#                               to exactly one endpoint is a SINGLETON candidate set, and a singleton's
#                               self-referential cap can never be exceeded, so it can never spill. That
#                               is why the setup publishes the SAME prompt to all three prefill EPs.
#      * the load             — load_i is loxilb's OWN tepval->pd_ep_loads[i].active_conns, incremented
#                               at endpoint selection and released at pd_cleanup. It is NOT a scraped
#                               engine metric (the kvCandidate comment still says "KVCacheUsagePerc +
#                               QueuedRequests"; that describes the dead scraper path, not this one).
#                               One in-flight request is therefore the whole fault injection.
#      * the capacity         — cap_i = ceil((1+eps)*totalLoad*cap_i/totalCap) with eps from the default
#                               mean-load factor, and every clamped capacity equal here. With one
#                               request in flight on the argmax EP and none elsewhere, the argmax is AT
#                               its cap and the siblings are under it: the spill is arithmetic, not luck.
#
#    The two arms differ in exactly ONE field — whether the two requests OVERLAP IN TIME:
#
#      control: two SEQUENTIAL requests, nothing ever in flight -> spills +0 EXACTLY, both land argmax
#      drive:   the first request held open on the argmax EP, the second issued while it is in flight
#               -> spills{sibling} +1 EXACTLY, and the second request lands on the SIBLING
#
#    Attribution: spills carries {ep_idx} and it labels the SPILL TARGET. A per-family delta could not
#    tell a spill to the right endpoint from a spill to the wrong one, so each arm reads the three
#    series individually and requires the two that must not move to be FLAT.
#
#    Confound excluded by construction, not by hope: the cold-start seeder diverts every Nth hit to an
#    EMPTY-inventory prefill EP, which would move hits to an endpoint without any spill. It can only
#    target an endpoint below its warm floor, so the setup warms ALL THREE and the stage asserts both
#    the sizes and a flat cold-seed counter. A moved cold-seed counter means the arm degraded into a
#    different arm and the spill numbers below are not about spilling.
echo "=== (spill) load-aware selector: one in-flight request on the affinity winner must spill the next ==="
SPILL_FAMILY="loxilb_pd_kv_tier15_spills_total"
SPILL_WARM_FLOOR=16     # kvColdSeedMinBlocksDefault — at/above this an EP is not a cold-seed target
CORPUS_BEFORE_SPILL="${CORPUS}"
CORPUS="${LONGCTX_CORPUS}"   # a prompt long enough to warm every EP past the cold-seed floor

# Setup: the SAME long prompt on all three prefill EPs. Identical inventories mean identical overlap,
# so the pure-overlap argmax is decided by the deterministic lowest-index tie-break — EP-A.
publish_prompt_to_ep "longctx-code-review" "${EP_A_IP}"
publish_prompt_to_ep "longctx-code-review" "${EP_B_IP}"
publish_prompt_to_ep "longctx-code-review" "${EP_C_IP}"
spill_size_a="$(inv_total "${EP_A_IDX}")"
spill_size_b="$(inv_total "${EP_B_IDX}")"
spill_size_c="$(inv_total "${EP_C_IDX}")"
spill_setup_ok=$([[ "${spill_size_a}" -ge "${SPILL_WARM_FLOOR}" && \
                   "${spill_size_b}" -ge "${SPILL_WARM_FLOOR}" && \
                   "${spill_size_c}" -ge "${SPILL_WARM_FLOOR}" && \
                   "${spill_size_a}" -eq "${spill_size_b}" ]] && echo 1 || echo 0)
echo "  setup: KVINV Size A=${spill_size_a} B=${spill_size_b} C=${spill_size_c} (want all >= ${SPILL_WARM_FLOOR} so no EP is a cold-seed target, and A == B so the argmax tie-break decides)"
assert "(spill setup) all three prefill EPs warm past the cold-seed floor with A and B carrying the SAME prefix" "$spill_setup_ok"

spill_body="${CFGDIR}/.spill-req.json"
longctx_body_file "longctx-code-review" "${spill_body}"
spill_post() {   # spill_post <outfile> — one probe through the VIP, body from the file above
    $hexec l3h1 curl -s -o "$1" --max-time 40 -X POST "http://${VIP}:${VPORT}/v1/completions" \
        -H 'Content-Type: application/json' --data-binary @"${spill_body}" >/dev/null 2>&1
}

# ---- arm 1: CONTROL — the same two requests, never overlapping -> the selector must not spill --------
sp_c_s0="$(metric_series "${SPILL_FAMILY}" ep_idx "${EP_A_IDX}")"
sp_c_s2="$(metric_series "${SPILL_FAMILY}" ep_idx "${EP_B_IDX}")"
sp_c_s4="$(metric_series "${SPILL_FAMILY}" ep_idx "${EP_C_IDX}")"
sp_c_h0="$(tier15_hits "${EP_A_IDX}")"; sp_c_h2="$(tier15_hits "${EP_B_IDX}")"; sp_c_h4="$(tier15_hits "${EP_C_IDX}")"
sp_c_seed_before="$(metric_val "loxilb_pd_kv_tier15_cold_seeds_total")"
spill_post "${CFGDIR}/.spill-ctl-1.out"
spill_post "${CFGDIR}/.spill-ctl-2.out"
sleep 3
sp_c_s0a="$(metric_series "${SPILL_FAMILY}" ep_idx "${EP_A_IDX}")"
sp_c_s2a="$(metric_series "${SPILL_FAMILY}" ep_idx "${EP_B_IDX}")"
sp_c_s4a="$(metric_series "${SPILL_FAMILY}" ep_idx "${EP_C_IDX}")"
sp_c_h0a="$(tier15_hits "${EP_A_IDX}")"; sp_c_h2a="$(tier15_hits "${EP_B_IDX}")"; sp_c_h4a="$(tier15_hits "${EP_C_IDX}")"
sp_c_seed_after="$(metric_val "loxilb_pd_kv_tier15_cold_seeds_total")"
echo "  control: spills{0,2,4} ${sp_c_s0}->${sp_c_s0a} ${sp_c_s2}->${sp_c_s2a} ${sp_c_s4}->${sp_c_s4a} (want ALL +0) ; hits{0,2,4} ${sp_c_h0}->${sp_c_h0a} ${sp_c_h2}->${sp_c_h2a} ${sp_c_h4}->${sp_c_h4a} (want +2/+0/+0) ; cold_seeds ${sp_c_seed_before}->${sp_c_seed_after} (want +0)"
sp_ctl_ok=$([[ "${sp_c_s0a}" -eq "${sp_c_s0}" && "${sp_c_s2a}" -eq "${sp_c_s2}" && "${sp_c_s4a}" -eq "${sp_c_s4}" && \
               $((sp_c_h0a - sp_c_h0)) -eq 2 && "${sp_c_h2a}" -eq "${sp_c_h2}" && "${sp_c_h4a}" -eq "${sp_c_h4}" && \
               "${sp_c_seed_after}" -eq "${sp_c_seed_before}" ]] && echo 1 || echo 0)
assert "(spill control) two SEQUENTIAL requests never spill: spills +0 on every ep_idx, both hits land on the argmax EP" "$sp_ctl_ok"

# ---- arm 2: DRIVE — hold the first request open on the argmax EP, then issue the second -------------
# slowok is `ok` with a guaranteed silent window: it reads the whole request, stays quiet, then answers
# a normal 200. `hang` would also hold the connection but ends in a zero-byte close, which moves the
# decode/prefill death counters — a fault, when what this arm needs is load.
SPILL_HOLD_SEC=10
# `sudo`, and the env assignment INSIDE it. pd-fault-swap.sh enters the netns
# with a bare `ip netns exec`, so it only works when it is already root: every
# other call site in this file runs it as `sudo ${PD_SWAP} ...`, and this one
# did not, so the swap answered "setting the network namespace failed:
# Operation not permitted" and the slowok stub never started. The spill arm
# then measured an EP that was never held and reported a product failure that
# had not happened.
#
# STUB_DELAY has to ride inside sudo: sudo does not pass the caller's
# environment through, so leaving the assignment outside would start the stub
# with the default hold and break the arm a second way, silently.
sudo STUB_DELAY="${SPILL_HOLD_SEC}" "${CFGDIR}/pd-fault-swap.sh" "$(netns_for_ep_ip "${EP_A_IP}")" slowok \
    | sed 's/^/  /' || true
sp_d_s0="$(metric_series "${SPILL_FAMILY}" ep_idx "${EP_A_IDX}")"
sp_d_s2="$(metric_series "${SPILL_FAMILY}" ep_idx "${EP_B_IDX}")"
sp_d_s4="$(metric_series "${SPILL_FAMILY}" ep_idx "${EP_C_IDX}")"
sp_d_h0="$(tier15_hits "${EP_A_IDX}")"; sp_d_h2="$(tier15_hits "${EP_B_IDX}")"; sp_d_h4="$(tier15_hits "${EP_C_IDX}")"
sp_d_seed_before="$(metric_val "loxilb_pd_kv_tier15_cold_seeds_total")"
# The holder, in the background. It is NOT scored for latency — its only job is to occupy one
# active_conns unit on the argmax EP while the probe is selected.
( spill_post "${CFGDIR}/.spill-hold.out" ) &
spill_hold_pid=$!
# Wait on the MECHANISM, not on a clock: the holder is only useful once the SELECTOR has run for it and
# chosen EP-A, which is exactly what its hits{A} increment says. A sleep here would score a probe that
# raced ahead of the holder's selection and report a product failure that never happened.
sp_held=0
for _w in $(seq 1 25); do
    [[ "$(tier15_hits "${EP_A_IDX}")" -gt "${sp_d_h0}" ]] && { sp_held=1; break; }
    sleep 1
done
sp_d_h0_held="$(tier15_hits "${EP_A_IDX}")"
spill_post "${CFGDIR}/.spill-probe.out"
sleep 2
sp_d_s0a="$(metric_series "${SPILL_FAMILY}" ep_idx "${EP_A_IDX}")"
sp_d_s2a="$(metric_series "${SPILL_FAMILY}" ep_idx "${EP_B_IDX}")"
sp_d_s4a="$(metric_series "${SPILL_FAMILY}" ep_idx "${EP_C_IDX}")"
sp_d_h0a="$(tier15_hits "${EP_A_IDX}")"; sp_d_h2a="$(tier15_hits "${EP_B_IDX}")"; sp_d_h4a="$(tier15_hits "${EP_C_IDX}")"
sp_d_seed_after="$(metric_val "loxilb_pd_kv_tier15_cold_seeds_total")"
wait "${spill_hold_pid}" 2>/dev/null || true
# sudo here for the same reason as the slowok above, and this half matters
# more than it looks: while the set was silently failing, this restore was a
# no-op that could not be seen failing. Once the set works, a restore that
# does not leaves EP-A answering with the 10s slowok delay for the REST of
# the run - which reads as a latency regression (median 10001ms against a
# 2000ms ceiling) and drags the whole scenario past the runner's budget.
sudo "${CFGDIR}/pd-fault-swap.sh" "$(netns_for_ep_ip "${EP_A_IP}")" off | sed 's/^/  /' || true
echo "  drive: holder selected EP-A=${sp_held} (hits{${EP_A_IDX}} ${sp_d_h0}->${sp_d_h0_held}) ; spills{0,2,4} ${sp_d_s0}->${sp_d_s0a} ${sp_d_s2}->${sp_d_s2a} ${sp_d_s4}->${sp_d_s4a} (want +0/+1/+0) ; hits{0,2,4} ${sp_d_h0}->${sp_d_h0a} ${sp_d_h2}->${sp_d_h2a} ${sp_d_h4}->${sp_d_h4a} (want +1/+1/+0) ; cold_seeds ${sp_d_seed_before}->${sp_d_seed_after} (want +0)"
sp_drv_ok=$([[ "${sp_held}" == 1 && \
               "${sp_d_s0a}" -eq "${sp_d_s0}" && $((sp_d_s2a - sp_d_s2)) -eq 1 && "${sp_d_s4a}" -eq "${sp_d_s4}" && \
               $((sp_d_h0a - sp_d_h0)) -eq 1 && $((sp_d_h2a - sp_d_h2)) -eq 1 && "${sp_d_h4a}" -eq "${sp_d_h4}" && \
               "${sp_d_seed_after}" -eq "${sp_d_seed_before}" ]] && echo 1 || echo 0)
assert "(spill drive) one in-flight request on the argmax EP spills the next to the sibling: spills{${EP_B_IDX}} +1 EXACT, siblings flat" "$sp_drv_ok"
CORPUS="${CORPUS_BEFORE_SPILL}"

#################################################################################
# KV-T15 EVIDENCE DUMP (non-assert) — capture the selector's per-request decisions BEFORE
# any later (destructive) stage replaces llb1. The C selector logs [KV_T15] guard outcomes
# to the in-container loxilb log, and the per-reason miss breakdown distinguishes "selector
# never ran" from "ran and missed (which guard)". This evidence was lost on prior runs.
#################################################################################
echo "=== KV-T15 evidence (selector decisions + per-reason miss breakdown) ==="
docker exec llb1 sh -c 'grep -h "KV_T15" /var/log/loxilb*.log 2>/dev/null | tail -20' \
    | sed 's/^/  [KV_T15] /' || echo "  (no in-container loxilb log access)"
llb_curl "${METRICS}" 2>/dev/null | grep -E "tier15_miss_reason|tier15_fallthrough|tier15_hits" \
    | grep -v '^#' | sed 's/^/  [metric] /' || true
for _pl in "${CFGDIR}"/.kvpub-d05-*.log; do
    [[ -e "${_pl}" ]] || continue
    echo "  [publisher ${_pl##*/}] $(tail -2 "${_pl}" | head -1)"
done

#################################################################################
# FULL routing/liveness metric-family presence — the LAZY families only exist once
#     exercised, so this must run AFTER the reconnect + cap/eviction legs (a check placed
#     earlier could only ever assert the eager subset). This is the gate that catches a
#     metric being renamed or dropped from registration: a family that vanishes reads as a
#     value of 0 everywhere else in this file, which is exactly how the whole
#     loxilb_pd_kv_t15_* -> loxilb_pd_kv_tier15_* rename went unnoticed.
#################################################################################
echo "=== metric-family registration gate (all 8 KV routing/liveness families) ==="
fam_snapshot=$(llb_curl "${METRICS}" 2>/dev/null)
fam_missing=""
for _fam in loxilb_pd_kv_tier15_hits_total loxilb_pd_kv_tier15_miss_reason_total \
            loxilb_pd_kv_tier15_fallthrough_total loxilb_pd_kv_blocks \
            loxilb_kv_subscriber_connected loxilb_kv_subscriber_reconnect_total \
            loxilb_kv_subscriber_recv_error_total loxilb_kv_inv_cap_evictions_total; do
    if echo "${fam_snapshot}" | grep -qE "^${_fam}[ {]"; then
        echo "  [family] ${_fam} present"
    else
        fam_missing="${fam_missing} ${_fam}"
    fi
done
[[ -n "${fam_missing}" ]] && echo "  MISSING metric families:${fam_missing}"
fam_ok=$([[ -z "${fam_missing}" ]] && echo 1 || echo 0)
assert "all 8 KV routing/liveness metric families registered + emitted on /metrics" "$fam_ok"

# NOTE: the backward-compat re-run is DELIBERATELY the LAST stage (after the exit gate): it
# docker-rm's THIS scenario's llb1/l3ep* (collision pre-clean) and replaces the topology
# with vllm-pd-disagg's — every assert that needs the KV-exact rule/topology (incl. the exit gate's
# warm-route) must run BEFORE it. Early runs had the backward-compat re-run before the exit gate, so it polled
# a topology whose loxilb had NO KV rule (ready=0 / tier15 forever 0 were partly THIS).

#################################################################################
# AUTHORITATIVE EXIT GATE — real-CPU-vLLM v0.17.0 contract-drift + warm-route.
#     GATED behind RUN_FR9=1 (alias EXIT_GATE=1) so it stays OFF the
#     fast inner loop: the inner loop (the functional checks above) produces SCENARIO-[OK] in seconds
#     WITHOUT this stage; when the flag is set, the phase CANNOT go green unless the exit gate's
#     TWO halves both pass:
#       (a) live hash-stream parity — the real vLLM's ZMQ-emitted BlockStored uint64s
#           INTERSECT loxilb's computed block-hash uint64s for the SAME warmed prompt
#           (contract parity against a real v0.17.0 emitter, not the mock).
#       (b) end-to-end warm-worker routing — a real follow-up request ROUTES to the
#           warmed worker (observed via loxilb_pd_kv_tier15_hits_total{ep} + which
#           backend served the banner).
#     The exit gate is HARD under SKELETON_STRICT=1; ONLY the inherent CPU-vLLM
#     warmup/latency timing sub-checks soft(). The real vLLM is Qwen3-0.6B on a vLLM
#     v0.17.0 CPU build per the confirmed boot recipe: float32,
#     --enforce-eager, --prefix-caching-hash-algo sha256_cbor,
#     VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=1, PYTHONHASHSEED=0, --kv-events-config endpoint
#     tcp://*:5557 (the PUB must bind). The PAID image build is
#     pre-staged by setup-runner.sh (NOT in this gate); here we only run it.
#
#     SCOPE NOTE: This block is the WRITE of the exit-gate logic. The PAID live
#     RUN_FR9=1 execution on the AWS runner is a human checkpoint.
#################################################################################
RUN_FR9="${RUN_FR9:-${EXIT_GATE:-0}}"
if [[ "${RUN_FR9}" == 1 ]]; then
    echo "=== EXIT GATE: real CPU vLLM v0.17.0 — live hash INTERSECT + warm-route ==="
    VLLM_IMG="${VLLM_IMG:-vllm-cpu}"
    VLLM_MODEL="${VLLM_MODEL:-Qwen/Qwen3-0.6B}"
    VLLM_KV_PORT="${VLLM_KV_PORT:-5557}"
    VLLM_API_PORT="${VLLM_API_PORT:-8000}"
    FR9_PROMPT_ID="${FR9_PROMPT_ID:-shared-prefix-base}"
    FR9_WARMUP_S="${FR9_WARMUP_S:-600}"   # CPU vLLM model-load + first inference is slow
    fr9_cap="${CFGDIR}/.fr9-vllm-capture.json"
    fr9_loxilb="${CFGDIR}/.fr9-loxilb-hashes.txt"

    # FAITHFUL TOPOLOGY: the REAL vLLM that backs prefill EP_A must publish on
    # EP_A's own IP (31.31.31.1), which is local ONLY inside l3ep1's netns — and that is
    # exactly the address loxilb's subscriber dials (tcp://<ep.xIP>:5557, rules.go:3407).
    # So vllm-fr9 SHARES l3ep1's network namespace (`--network container:l3ep1`); its
    # tcp://*:5557 PUB then binds 31.31.31.1 and loxilb reaches it across the llb1<->l3ep1
    # veth. (The prior `--network host` bound *:5557 in the HOST netns, where 31.31.31.1 is
    # NOT an interface — so the subscriber's Dial never connected: the SAME root cause as
    # the mock path, just with the real emitter.)
    FR9_EP_NS="$(netns_for_ep_ip "${EP_A_IP}")"   # l3ep1 — the netns/container owning EP_A
    if [[ -z "${FR9_EP_NS}" ]]; then
        echo "  WARN: no netns owns EP_A ${EP_A_IP} — cannot place vllm-fr9; the exit gate will be soft-only"
    fi
    FR9_HF_VOL="${FR9_HF_VOL:-kvfr9-hfcache}"
    docker rm -f vllm-fr9 >/dev/null 2>&1 || true
    # l3ep1's netns has NO internet egress, so the model can't be pulled at boot there
    # (the prior --network host run relied on host egress to download Qwen3-0.6B). Pre-stage
    # the model into a shared HF-cache volume via a HOST-net puller, then serve OFFLINE from
    # that volume. (Reused across re-runs; harmless if the image already baked the weights.)
    docker volume create "${FR9_HF_VOL}" >/dev/null 2>&1 || true
    echo "  pre-staging ${VLLM_MODEL} into volume ${FR9_HF_VOL} (host-net puller; l3ep1 has no egress)..."
    docker run --rm --network host -e HF_HOME=/hf-cache -v "${FR9_HF_VOL}:/hf-cache" \
        --entrypoint python3 "${VLLM_IMG}" -c \
        "from huggingface_hub import snapshot_download; snapshot_download('${VLLM_MODEL}')" \
        >/dev/null 2>&1 || echo "  WARN: model pre-pull failed (relying on any image-baked cache)"
    # --block-size ${KV_BLOCK_SIZE} below is REQUIRED: vLLM's CPU backend defaults to
    # block_size=128, so a <128-token prompt fills ZERO full blocks and emits NOTHING
    # (live-proven: two 200 completions with a capture attached from boot -> hashes=[]),
    # and even a long prompt's 128-token block hashes can never intersect the 16-token
    # harness/rule blocks. With 16, the real vLLM's emitted uint64s matched loxilb's
    # computation FOUR-FOR-FOUR on the live probe. (A "~2KB completion" silently
    # masked this: ~500 tokens / 128 = the 3 captured hashes.)
    docker run -d --name vllm-fr9 --network "container:${FR9_EP_NS:-host}" \
        --security-opt seccomp=unconfined --cap-add SYS_NICE --shm-size=4g \
        -e VLLM_CPU_KVCACHE_SPACE=4 -e PYTHONHASHSEED=0 -e VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=1 \
        -e HF_HOME=/hf-cache -e HF_HUB_OFFLINE=1 -v "${FR9_HF_VOL}:/hf-cache" \
        "${VLLM_IMG}" "${VLLM_MODEL}" --dtype=float32 --max-model-len 4096 --enforce-eager \
        --port "${VLLM_API_PORT}" --block-size "${KV_BLOCK_SIZE}" \
        --prefix-caching-hash-algo "${KV_HASH_ALGO}" \
        --kv-events-config "{\"enable_kv_cache_events\":true,\"publisher\":\"zmq\",\"endpoint\":\"tcp://*:${VLLM_KV_PORT}\"}" \
        || echo "  WARN: docker run vllm-fr9 FAILED (rc=$?) — ready poll will time out"

    # Wait for the OpenAI-compatible server to accept completions (model loaded). vllm-fr9
    # shares l3ep1's netns, so its API binds EP_A's IP — poll it from llb1 across the veth.
    vllm_ready=0
    for _ in $(seq 1 "${FR9_WARMUP_S}"); do
        rc=$($hexec llb1 curl -s -m 3 -o /dev/null -w "%{http_code}" \
            "http://${EP_A_IP}:${VLLM_API_PORT}/v1/models" 2>/dev/null || echo 000)
        if [[ "$rc" == "200" ]]; then vllm_ready=1; break; fi
        sleep 1
    done
    echo "  real vLLM ready=${vllm_ready} (image=${VLLM_IMG} model=${VLLM_MODEL} netns=${FR9_EP_NS:-host} ep=${EP_A_IP})"
    if [[ "${vllm_ready}" != 1 ]]; then
        # Diagnosability: a swallowed docker-run failure or a crashed/slow boot are
        # indistinguishable without this (an early run lost the evidence).
        echo "  -- vllm-fr9 state: $(docker ps -a --filter name=vllm-fr9 --format '{{.Status}}' 2>/dev/null || echo absent)"
        docker logs vllm-fr9 2>&1 | tail -15 | sed 's/^/  [vllm-fr9] /' || true
    fi

    # Concurrently capture the vLLM-emitted BlockStored uint64s (the publisher script doubles
    # as a SUB-side capture tool via --capture; it subscribes and dumps the emitted uint64
    # hashes to a JSON file). vllm-fr9 publishes inside l3ep1's netns, so the capture SUB runs
    # IN THAT NETNS and connects to 127.0.0.1:PORT (co-located with the PUB). `ip netns exec`
    # runs the host python3 (deps + host-FS) so the --capture-out path is the same host file
    # validation.sh reads below.
    fr9_prompt="$(prompt_text "${FR9_PROMPT_ID}")"
    # --capture-secs 90: CPU vLLM's FIRST inference (prefill of a ~400-char prompt) can take
    # tens of seconds; the prior default 15s window expired before any BlockStored was emitted
    # (fr9a INTERSECT=0 with an empty capture). The capture file is rewritten per batch, so a
    # longer window costs nothing on the fast path.
    setsid $hexec "${FR9_EP_NS:-llb1}" bash -c "export PYTHONPATH='${PY_USER_SITE}' PYTHONHASHSEED=0; exec -a ${PUB_TAG}-fr9cap python3 '${PUBLISHER}' \
        --capture --connect 127.0.0.1 --port ${VLLM_KV_PORT} \
        --algo ${KV_HASH_ALGO} --block-size ${KV_BLOCK_SIZE} --capture-secs 90 \
        --capture-out '${fr9_cap}'" >"${CFGDIR}/.fr9-capture.log" 2>&1 &

    # Warm the prompt on the REAL vLLM so it emits BlockStored for that prompt's full blocks.
    # vllm-fr9's API is on EP_A's IP (shared l3ep1 netns) — reach it from llb1 across the veth.
    fr9_warm_rc=$($hexec llb1 curl -s -m 120 -o /dev/null -w "%{http_code}" -X POST "http://${EP_A_IP}:${VLLM_API_PORT}/v1/completions" \
        -H 'Content-Type: application/json' \
        -d "{\"model\":\"${VLLM_MODEL}\",\"prompt\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "${fr9_prompt}"),\"max_tokens\":1}" \
        2>/dev/null || echo 000)
    echo "  fr9 warm completion HTTP ${fr9_warm_rc}"
    # Wait for the capture to actually collect hashes (file rewritten per batch) — up to 60s.
    fr9_caplen=0
    for _ in $(seq 1 60); do
        fr9_caplen=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1])).get('hashes',[])))" "${fr9_cap}" 2>/dev/null || echo 0)
        [[ "${fr9_caplen}" -gt 0 ]] && break
        sleep 1
    done
    echo "  fr9 captured ${fr9_caplen} BlockStored uint64(s) from the real vLLM stream"
    if [[ "${fr9_caplen}" -eq 0 ]]; then
        # Publisher-silent forensics (captured nothing => vLLM likely never started its ZMQ
        # publisher, or prefix-caching/events are off in THIS boot): preserve the decisive
        # boot lines before the teardown below destroys the container.
        echo "  -- vllm-fr9 kv-events boot evidence:"
        docker logs vllm-fr9 2>&1 | grep -iE "kv_?event|zmq|publisher|prefix.?caching" | tail -8 | sed 's/^/  [vllm-fr9] /' || true
        docker logs vllm-fr9 2>&1 | tail -6 | sed 's/^/  [vllm-fr9 tail] /' || true
    fi

    # loxilb's computed uint64s for the SAME prompt (publisher --emit-hashes prints the block
    # uint64s loxilb's request-side would compute — same tokenizer.json + same cbor/hash core).
    PYTHONHASHSEED=0 python3 "${PUBLISHER}" --emit-hashes \
        --prompt "${fr9_prompt}" --tokenizer "${TOKENIZER_SRC}" \
        --algo "${KV_HASH_ALGO}" --block-size "${KV_BLOCK_SIZE}" \
        >"${fr9_loxilb}" 2>/dev/null || true

    # (a) INTERSECT: the real vLLM's emitted uint64s must share >=1 hash with loxilb's set.
    fr9_intersect=$(python3 -c "
import json,sys
try:
    cap=json.load(open(sys.argv[1]))
    vllm=set(int(h) for h in cap.get('hashes', []))
except Exception:
    vllm=set()
try:
    lox=set(int(x) for x in open(sys.argv[2]).read().split())
except Exception:
    lox=set()
inter=vllm & lox
print(1 if (vllm and lox and inter) else 0)
" "${fr9_cap}" "${fr9_loxilb}" 2>/dev/null || echo 0)
    echo "  (a) live hash-stream parity: real-vLLM uint64s INTERSECT loxilb's = ${fr9_intersect} (loxilb side: $(wc -w < "${fr9_loxilb}" 2>/dev/null || echo 0) uint64s)"
    fr9a_ok=$([[ "$vllm_ready" == 1 && "$fr9_intersect" == 1 ]] && echo 1 || echo 0)
    assert "(exit gate a) real vLLM uint64s INTERSECT loxilb's computed block hashes (live contract parity)" "$fr9a_ok"

    # (b) WARM-ROUTE: a real follow-up request for the warmed prompt must route to the warmed
    # worker (the EP whose inventory the real vLLM populated). Dual proof: tier15_hits delta AND
    # a prefill banner (never decode / Tier-2 RR). EP_A's inventory must by now hold the REAL
    # vLLM's hashes (the ep0 subscriber redialed 31.31.31.1:5557 when vllm-fr9 bound it and
    # ingested the warm completion's BlockStored events) — echo it for evidence.
    echo "  (b) EP_A inventory (idx ${EP_A_IDX}) total=$(inv_total "${EP_A_IDX}") before warm-route request"
    warm_hits_before=$(tier15_hits "${EP_A_IDX}")
    fr9_banner=$(request_and_banner "${FR9_PROMPT_ID}")
    warm_hits_after=$(tier15_hits "${EP_A_IDX}")
    # P/D-flow semantics (see scenario 1): the client-visible banner is the DECODE echo; the
    # warmed-worker (EP_A) selection is proven by the tier15_hits{0} delta.
    fr9_route_deliver=$([[ "$fr9_banner" == server"D"* ]] && echo 1 || echo 0)
    fr9_route_hit=$([[ "$warm_hits_after" -gt "$warm_hits_before" ]] && echo 1 || echo 0)
    echo "  (b) warm-route: banner=${fr9_banner} (want serverD* — P/D flow) ; tier15_hits{${EP_A_IDX}} ${warm_hits_before}->${warm_hits_after} (want delta — warmed EP-A selected)"
    fr9b_ok=$([[ "$fr9_route_deliver" == 1 && "$fr9_route_hit" == 1 ]] && echo 1 || echo 0)
    assert "(exit gate b) follow-up request routes to the warmed worker (banner==serverD* P/D flow AND tier15_hits{0} delta)" "$fr9b_ok"

    # Inherent CPU-vLLM warmup/latency timing is non-deterministic -> soft ONLY.
    soft "(exit gate) real-vLLM warmup/inference latency window (CPU, inherent)" "$vllm_ready"

    # Scoped teardown of the exit-gate emitter + its capture SUB (anchored tag; never a host-wide sweep).
    for pid in $(pgrep -f "${PUB_TAG}-fr9cap" 2>/dev/null); do kill "${pid}" >/dev/null 2>&1 || true; done
    docker rm -f vllm-fr9 >/dev/null 2>&1 || true
    rm -f "${fr9_cap}" "${fr9_loxilb}" >/dev/null 2>&1 || true
else
    echo "=== EXIT GATE skipped — RUN_FR9 unset (fast inner loop) ==="
    echo "  set RUN_FR9=1 (or EXIT_GATE=1) for the authoritative paid real-CPU-vLLM exit gate."
fi

#################################################################################
# (hot-path instrumentation captures) — per-stage hot-path instrumentation evidence
#
#   Three captures live under the SAME single SCENARIO sentinel (no new harness):
#     (A) A/B overhead microbench — per-stage tokenize/hash/CGO breakdown on BOTH a
#         hit-heavy and a miss-heavy corpus + a bounded instrumentation-overhead delta.
#     (B) load-skew distribution — N shared-prefix clients vs ONE hot preamble; the
#         per-EP routing distribution is EMITTED (not pass/fail) and the argmax-EP-dominant
#         imbalance is asserted (the load-blind overlap-argmax flaw, CPU-side).
#     (C) Head-of-line-blocking — concurrent N-client per-client tail latency vs the
#         single-client baseline; both emitted so the worker-thread stall is measurable.
#
#   PARITY: the rig already runs with LLB_KV_NONE_HASH_SEED=0 +
#   PYTHONHASHSEED=0 (config.sh) + KV_BLOCK_SIZE=16 (the publishers); these captures
#   assert tier15_hits_total advances + the no_worker miss stays flat on the hit corpus
#   BEFORE trusting any number, so we never silently measure Tier-2 RR.
#
#   DELIBERATELY BEFORE the backward-compat collision pre-clean (which DESTROYS this topology).
#
#   OBSERVABILITY NOTE (deviation): the always-on per-stage
#   µs histograms (record_kv_stage, sockproxy_metrics.c) are NOT yet bridged to /metrics
#   (the Go proxy_metrics_snapshot bridge is out of scope here). Until that bridge
#   lands, the per-stage breakdown surface is the flag-gated [KV_T15_STAGE] in-container
#   log line (LLB_KV_HASH_DEBUG=1, set in config.sh), and the per-EP load-skew signal is
#   loxilb_pd_kv_tier15_hits_total{ep_idx} (the truthful available per-EP routing counter —
#   the plan's idealized per_ep_active_conns{ep} gauge does not exist on /metrics today).
#################################################################################

# stage_log_count <STAGE-FIELD-REGEX> — count [KV_T15_STAGE] structured records in the
# in-container loxilb log matching a field anchor (e.g. outcome=hit). Field-anchored per
# the loxilb_log_count discipline (never a bare word — the record shape is content-free:
#   [KV_T15_STAGE] fd=<n> outcome=<hit|miss> tok_us=<n> hash_us=<n> cgo_us=<n>).
stage_log_count() {
    docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' 2>/dev/null \
        | grep -cE "\[KV_T15_STAGE\] .*$1" || true
}

# req_latency_ms <prompt-id> — issue one prompt from l3h1 and echo the total wall time in
# milliseconds (curl %{time_total}, seconds*1000, integer). Empty/err -> 0.
req_latency_ms() {
    local pid="$1" body t
    body=$(python3 -c "
import json,sys
d=json.load(open('${CORPUS}'))
for p in d['prompts']:
    if p['id']==sys.argv[1]:
        print(json.dumps({'model':'${KV_MODEL}','prompt':p['prompt'],'max_tokens':8})); break" "$pid")
    t=$($hexec l3h1 curl -s -o /dev/null --max-time 10 -w '%{time_total}' \
        -X POST "http://${VIP}:${VPORT}/v1/completions" \
        -H 'Content-Type: application/json' --data-binary "${body}" 2>/dev/null)
    awk -v s="${t:-0}" 'BEGIN{printf "%d", s*1000}'
}

echo "=== per-stage hot-path instrumentation captures ==="

# ── RE-WARM EP_A before the captures (ordering fix) ──────────────────────────────────
# This block runs AFTER the chaos suite (publisher-down, kill/
# restart, resync-CLEAR, cap-eviction). Those legs DELIBERATELY tear
# down / evict EP_A's shared-prefix-base inventory (the resync leg ends on a --kill replace;
# the cap leg evicts thousands of blocks pinned at the lowered cap). So EP_A is NOT warm by
# the time we get here — the earlier "pre-published (config.sh)" assumption no longer holds.
# Re-publish the hit corpus to EP_A (resident, NO --kill) and wait for the subscriber to
# re-converge BEFORE the parity gate, so the precheck is deterministic regardless of
# the chaos state it inherits. publish_prompt_to_ep blocks until the inventory changes + is
# non-zero, so the subsequent drive lands on a freshly-ingested EP_A (not a Tier-2 no_worker).
echo "  (re-warm) re-publishing shared-prefix-base to EP_A after the chaos/cap suite..."
publish_prompt_to_ep "shared-prefix-base" "${EP_A_IP}"

# ── parity precheck: the hit corpus MUST route Tier-1.5 (not silent Tier-2 RR) ──
# shared-prefix-base is now freshly re-published to EP_A (above) so it is the hit corpus; drive
# a few and require tier15_hits to advance while no_worker stays flat. If parity is broken
# every number below would measure RR, so this is a HARD precondition.
w1_hits_before=$(metric_val "loxilb_pd_kv_tier15_hits_total")
w1_nowork_before=$(metric_val "loxilb_pd_kv_tier15_miss_reason_total\{reason=\"no_worker\"")
for _ in 1 2 3 4; do request_and_banner "shared-prefix-base" >/dev/null; done
w1_hits_after="${w1_hits_before}"; w1_nowork_after="${w1_nowork_before}"
for _ in $(seq 1 15); do
    w1_hits_after=$(metric_val "loxilb_pd_kv_tier15_hits_total")
    w1_nowork_after=$(metric_val "loxilb_pd_kv_tier15_miss_reason_total\{reason=\"no_worker\"")
    [[ "$w1_hits_after" -gt "$w1_hits_before" ]] && break
    sleep 1
done
echo "  (parity) tier15_hits ${w1_hits_before}->${w1_hits_after} ; no_worker ${w1_nowork_before}->${w1_nowork_after}"
w1_parity_ok=$([[ "$w1_hits_after" -gt "$w1_hits_before" && "$w1_nowork_after" == "$w1_nowork_before" ]] && echo 1 || echo 0)
assert "parity: hit corpus advances tier15_hits + no_worker flat (not Tier-2 RR)" "$w1_parity_ok"

#################################################################################
# (A) A/B overhead microbench — per-stage breakdown on hit + miss; bounded overhead delta
#################################################################################
echo "=== (A) A/B overhead microbench — per-stage tokenize/hash/CGO on hit + miss ==="
# Per-stage breakdown surface = the flag-gated [KV_T15_STAGE] records (LLB_KV_HASH_DEBUG=1,
# config.sh). Drive a HIT-heavy batch (shared-prefix-base, pre-published) and a MISS-heavy
# batch (warmup-miss-fresh, never published -> no_worker guard -> Tier-2 fallthrough). Both
# paths flush the SAME 3 measured stages (tokenize/hash/CGO) via KV_T15_FLUSH,
# so the per-stage records advance on hit AND miss — that is the hit/miss breakdown.
ab_hit_before=$(stage_log_count "outcome=hit")
ab_miss_before=$(stage_log_count "outcome=miss")
# Timers-ON aggregate latency: median of an instrumented hit batch (the per-request record
# IS being written — LLB_KV_HASH_DEBUG=1). This is the perturbed measurement.
ab_on_lats=""
for _ in $(seq 1 8); do
    request_and_banner "shared-prefix-base" >/dev/null
    ab_on_lats="${ab_on_lats} $(req_latency_ms "shared-prefix-base")"
done
for _ in $(seq 1 6); do request_and_banner "warmup-miss-fresh" >/dev/null; done
sleep 2
ab_hit_after=$(stage_log_count "outcome=hit")
ab_miss_after=$(stage_log_count "outcome=miss")
echo "  per-stage [KV_T15_STAGE] records: hit ${ab_hit_before}->${ab_hit_after} ; miss ${ab_miss_before}->${ab_miss_after}"
# Emit a representative per-stage breakdown line (content-free: stage µs only) for the paper.
docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' 2>/dev/null \
    | grep -E "\[KV_T15_STAGE\]" | tail -3 | sed 's/^/    /' || true
# Aggregate timers-on latency median (sorted middle) — the overhead-ceiling number.
ab_on_median=$(echo "${ab_on_lats}" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -n \
    | awk '{a[NR]=$1} END{if(NR>0) print a[int((NR+1)/2)]; else print 0}')
# (i): per-stage counts advance on BOTH hit-heavy and miss-heavy corpora.
ab_break_ok=$([[ "$ab_hit_after" -gt "$ab_hit_before" && "$ab_miss_after" -gt "$ab_miss_before" ]] && echo 1 || echo 0)
assert "per-stage tokenize/hash/CGO records advance on hit-heavy AND miss-heavy corpora" "$ab_break_ok"
# (ii): the instrumentation-on aggregate latency stays under a documented ceiling
# (perturbation bound). Mock reflect-echo backends answer in low single-digit ms; the
# routing ladder (tokenize+hash+CGO) adds the routing overhead under test. Ceiling chosen
# generously (mock-rig) so the timers themselves are proven non-dominating; the GPU campaign
# refines the absolute number. RECORD the delta regardless.
AB_OVERHEAD_CEILING_MS="${AB_OVERHEAD_CEILING_MS:-2000}"
echo "  timers-ON aggregate hit-path latency: median=${ab_on_median}ms (ceiling=${AB_OVERHEAD_CEILING_MS}ms)"
ab_ceiling_ok=$([[ "${ab_on_median:-99999}" -le "${AB_OVERHEAD_CEILING_MS}" ]] && echo 1 || echo 0)
assert "instrumentation-on aggregate latency bounded under documented ceiling" "$ab_ceiling_ok"

#################################################################################
# (B) load-skew distribution — N shared-prefix clients -> ONE hot preamble -> EP imbalance
#################################################################################
echo "=== (B) load-skew distribution capture (overlap-argmax herds to one EP) ==="
# Re-publish the single hot preamble (shared-prefix-base) to EXACTLY ONE prefill EP (EP_A),
# leaving the siblings (EP_B/EP_C) without that corpus. Pure overlap-argmax then routes EVERY
# shared-prefix client to EP_A — the load-blind flaw. We CAPTURE the full per-EP distribution
# (tier15_hits delta per ep_idx) rather than a bare pass/fail (must-have: emit the distribution).
publish_prompt_to_ep "shared-prefix-base" "${EP_A_IP}"
declare -A skew_before skew_after
for _ip in "${EP_A_IP}" "${EP_B_IP}" "${EP_C_IP}"; do
    skew_before[$_ip]=$(tier15_hits "$(idx_for_ep_ip "$_ip")")
done
SKEW_CLIENTS="${SKEW_CLIENTS:-12}"
for _ in $(seq 1 "${SKEW_CLIENTS}"); do request_and_banner "shared-prefix-base" >/dev/null; done
sleep 3
skew_total=0; skew_argmax=0; skew_argmax_ip=""
echo "  per-EP Tier-1.5 routing distribution under ONE hot preamble (the load-skew capture):"
for _ip in "${EP_A_IP}" "${EP_B_IP}" "${EP_C_IP}"; do
    skew_after[$_ip]=$(tier15_hits "$(idx_for_ep_ip "$_ip")")
    _d=$(( ${skew_after[$_ip]} - ${skew_before[$_ip]} ))
    [[ "$_d" -lt 0 ]] && _d=0
    echo "    EP ${_ip} (ep_idx=$(idx_for_ep_ip "$_ip")): +${_d} routed (${skew_before[$_ip]}->${skew_after[$_ip]})"
    skew_total=$(( skew_total + _d ))
    if [[ "$_d" -gt "$skew_argmax" ]]; then skew_argmax="$_d"; skew_argmax_ip="$_ip"; fi
done
echo "  argmax EP=${skew_argmax_ip} carried ${skew_argmax}/${skew_total} routed (the herd); siblings near-idle"
# Imbalance assert: the argmax EP must carry a DOMINANT share (> 60% of routed traffic) — the
# overlap-argmax herd. (Strictly the single-published-EP design drives ~100% to EP_A; 60% is a
# robust floor against the publisher convergence races.)
skew_ok=0
if [[ "$skew_total" -gt 0 ]]; then
    _pct=$(( skew_argmax * 100 / skew_total ))
    echo "  argmax share = ${_pct}% (dominance floor 60%)"
    [[ "$_pct" -ge 60 ]] && skew_ok=1
fi
assert "load-skew: per-EP distribution emitted + argmax-EP dominant (overlap-argmax herd)" "$skew_ok"

#################################################################################
# (C) Head-of-line-blocking — concurrent N-client per-client tail vs single-client baseline
#################################################################################
echo "=== (C) head-of-line-blocking tail-latency (concurrent vs single-client) ==="
# Single-client baseline: sequential per-request latency p-tail.
hol_base_lats=""
for _ in $(seq 1 8); do hol_base_lats="${hol_base_lats} $(req_latency_ms "shared-prefix-base")"; done
hol_base_p99=$(echo "${hol_base_lats}" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -n | tail -1)
# Concurrent N-client drive: many connections multiplexed on the same sockproxy worker thread;
# a multi-ms tokenize on one stalls the others (the architecturally important HOL
# effect). Launch background curls, collect each one's %{time_total}.
HOL_CLIENTS="${HOL_CLIENTS:-12}"
hol_tmp="${CFGDIR}/.hol-lat.$$"
: > "${hol_tmp}"
hol_body=$(python3 -c "
import json,sys
d=json.load(open('${CORPUS}'))
for p in d['prompts']:
    if p['id']=='shared-prefix-base':
        print(json.dumps({'model':'${KV_MODEL}','prompt':p['prompt'],'max_tokens':8})); break")
for _ in $(seq 1 "${HOL_CLIENTS}"); do
    ( t=$($hexec l3h1 curl -s -o /dev/null --max-time 15 -w '%{time_total}' \
            -X POST "http://${VIP}:${VPORT}/v1/completions" \
            -H 'Content-Type: application/json' --data-binary "${hol_body}" 2>/dev/null)
      awk -v s="${t:-0}" 'BEGIN{printf "%d\n", s*1000}' >> "${hol_tmp}" ) &
done
wait
hol_conc_p99=$(grep -E '^[0-9]+$' "${hol_tmp}" 2>/dev/null | sort -n | tail -1)
rm -f "${hol_tmp}" >/dev/null 2>&1 || true
hol_base_p99="${hol_base_p99:-0}"; hol_conc_p99="${hol_conc_p99:-0}"
echo "  single-client baseline tail=${hol_base_p99}ms ; concurrent(${HOL_CLIENTS}-client) tail=${hol_conc_p99}ms"
echo "  HOL inflation = concurrent_tail - baseline_tail = $(( hol_conc_p99 - hol_base_p99 ))ms"
# BOTH numbers captured + non-empty (the measurement exists; the worker-thread stall is
# now visible). We do NOT assert a magnitude (mock rig) — only that both tails are measured.
hol_ok=$([[ "$hol_base_p99" -gt 0 && "$hol_conc_p99" -gt 0 ]] && echo 1 || echo 0)
assert "HOL: single-client baseline + concurrent tail latency BOTH captured" "$hol_ok"

#################################################################################
# P/D lifecycle taxonomy — a decode-leg wedge must be reported as a DECODE fault
#
#     loxilb_ai_pd_requests_total{phase,status} is the only exported signal that
#     says WHICH leg of a P/D pair failed and HOW. It is derived entirely from
#     the error_phase the datapath passes to llb_ai_pd_record, so a wrong value
#     is not a cosmetic mislabel -- it sends an operator to the wrong tier.
#
#     This stage drives the decode first-byte wedge: the decode endpoints accept
#     the connection and then never answer and never close, which is the exact
#     predicate the reaper tests (phase DECODE_SENDING, no decode byte, no
#     content-length, elapsed >= timeout). The prefill leg completes normally.
#     A wedged DECODE fleet must therefore move {phase="decode"} and must leave
#     {phase="prefill",status="timeout"} alone.
#
#     🚨 THE FLAT ASSERTION IS THE POINT, not decoration. This regression is
#     invisible to a family-total oracle: a mislabelled write moves the family
#     by exactly as much as a correct one. Only the per-{phase,status} child
#     can tell "the wedge was counted" from "the wedge was counted as a prefill
#     timeout". Historically it was the latter, and the decode series never
#     moved at all.
#
#     🚨 DRIVE SHAPE IS ASSERTED, NOT ASSUMED. A stub that gives up and CLOSES
#     sends the decode leg down the zero-byte-EOF path instead, ~10s before the
#     wedge can fire, and every assertion below would then be scoring the stub
#     rather than the product. The witness is the ABSENCE of the zero-byte EOF
#     line together with the PRESENCE of the wedge line, both counted from the
#     datapath log, which is a third oracle independent of Prometheus and of
#     the client receipts.
#
#     Placed before the collision pre-clean below, which destroys this
#     scenario's topology.
#################################################################################
echo "=== P/D lifecycle taxonomy: a decode wedge is reported as a decode fault ==="

PD_TAX_N=2
PD_DECODE_NS="l3ep2 l3ep4 l3ep6"
PD_SWAP="./pd-fault-swap.sh"
DPLOG="/var/log/loxilbdp.log"
PD_WEDGE_LINE="P/D decode first-byte timeout"
PD_ZEOF_LINE="decode backend EOF with ZERO"

# grep -cF, never -c: datapath tags look like "[KV_T15_FALLTHROUGH]" and as a
# BRE that is a character class matching nearly every line. And an UNREADABLE
# log must never score as zero -- grep exits 1 on no-match and >1 on a real
# error, and collapsing those turns "I could not measure" into "nothing
# happened".
dplog_count() {
    local out rc
    out=$(docker exec llb1 grep -cF "$1" "${DPLOG}" 2>/dev/null); rc=$?
    if [[ $rc -gt 1 ]]; then echo "-1"; else echo "${out:-0}"; fi
}

pd_req() {  # pd_req <phase> <status> — summed over models
    metric_val "loxilb_ai_pd_requests_total\{[^}]*phase=\"$1\"[^}]*status=\"$2\""
}

# pd_req_empty_model <phase> <status> — the count carried by an EMPTY model
# label. The summed view above is deliberately blind to this: a failure
# labelled with a different model than the success for the SAME request still
# adds to the family total, but vanishes from every per-model dashboard, alert
# and filter. The reaper used to resolve the model from two sources and fall
# back to "" while every other site used the four-source resolver, so a timed
# out request was attributed to no model at all.
pd_req_empty_model() {
    metric_val "loxilb_ai_pd_requests_total\{model=\"\",[^}]*phase=\"$1\"[^}]*status=\"$2\""
}

pd_tax_ok=1
pd_tax_note=""

if [[ ! -x "${PD_SWAP}" ]]; then
    pd_tax_ok=0; pd_tax_note="missing ${PD_SWAP}"
else
    # ---- control: healthy pair, nothing may look like a wedge --------------
    for ns in ${PD_DECODE_NS}; do sudo ${PD_SWAP} "${ns}" ok >/dev/null || pd_tax_ok=0; done
    sleep 2
    c_succ_b=$(pd_req complete success); c_dtmo_b=$(pd_req decode timeout)
    c_wedge_b=$(dplog_count "${PD_WEDGE_LINE}")
    # Same request shape the rest of this scenario uses: /v1/completions with
    # the rule's own model. A different model name answers model_unavailable
    # and a chat-shaped body leaves the prefix extractor's model source empty,
    # so either would measure the fixture rather than the product.
    pd_tax_body="{\"model\":\"${KV_MODEL}\",\"prompt\":\"pd taxonomy probe\",\"max_tokens\":8}"
    for i in $(seq 1 ${PD_TAX_N}); do
        $hexec l3h1 curl -s -o /dev/null --max-time 30 \
            -H 'Content-Type: application/json' -d "${pd_tax_body}" \
            "http://${VIP}:${VPORT}/v1/completions" || true
    done
    sleep 3
    c_succ_a=$(pd_req complete success); c_dtmo_a=$(pd_req decode timeout)
    c_wedge_a=$(dplog_count "${PD_WEDGE_LINE}")
    echo "  control: {complete,success} ${c_succ_b}->${c_succ_a} ; {decode,timeout} ${c_dtmo_b}->${c_dtmo_a} ; wedge lines ${c_wedge_b}->${c_wedge_a}"
    [[ "${c_dtmo_a}" == "${c_dtmo_b}" ]] || { pd_tax_ok=0; pd_tax_note="${pd_tax_note} control moved {decode,timeout};"; }
    [[ "${c_wedge_a}" == "${c_wedge_b}" ]] || { pd_tax_ok=0; pd_tax_note="${pd_tax_note} control logged a wedge;"; }

    # ---- fault: decode accepts and never answers --------------------------
    for ns in ${PD_DECODE_NS}; do sudo ${PD_SWAP} "${ns}" hang >/dev/null || pd_tax_ok=0; done
    sleep 2
    f_ptmo_b=$(pd_req prefill timeout); f_dtmo_b=$(pd_req decode timeout)
    f_derr_b=$(pd_req decode error)
    f_wedge_b=$(dplog_count "${PD_WEDGE_LINE}"); f_zeof_b=$(dplog_count "${PD_ZEOF_LINE}")
    f_dtmo_empty_b=$(pd_req_empty_model decode timeout)

    pd_codes="${CFGDIR}/.pd-tax-codes"
    : > "${pd_codes}"
    for i in $(seq 1 ${PD_TAX_N}); do
        ( $hexec l3h1 curl -s -o /dev/null --max-time 90 -w '%{http_code}\n' \
            -H 'Content-Type: application/json' -d "${pd_tax_body}" \
            "http://${VIP}:${VPORT}/v1/completions" >> "${pd_codes}" 2>/dev/null ) &
    done
    wait
    sleep 5

    f_ptmo_a=$(pd_req prefill timeout); f_dtmo_a=$(pd_req decode timeout)
    f_derr_a=$(pd_req decode error)
    f_wedge_a=$(dplog_count "${PD_WEDGE_LINE}"); f_zeof_a=$(dplog_count "${PD_ZEOF_LINE}")

    d_ptmo=$(( f_ptmo_a - f_ptmo_b ))
    d_dtmo=$(( f_dtmo_a - f_dtmo_b ))
    d_derr=$(( f_derr_a - f_derr_b ))
    d_wedge=$(( f_wedge_a - f_wedge_b ))
    d_zeof=$(( f_zeof_a - f_zeof_b ))
    n_codes=$(grep -c . "${pd_codes}" 2>/dev/null || echo 0)

    echo "  wedge: {decode,timeout} Δ${d_dtmo} (want ${PD_TAX_N}) ; {prefill,timeout} Δ${d_ptmo} (want 0) ; {decode,error} Δ${d_derr} (want 0)"
    echo "  drive shape: wedge lines Δ${d_wedge} (want ${PD_TAX_N}) ; zero-byte-EOF lines Δ${d_zeof} (want 0) ; codes=$(tr '\n' ' ' < "${pd_codes}")"

    # An empty %{http_code} is a FAILED SPAWN, never a gateway answer -- so the
    # count of recorded codes must equal the number of requests issued or the
    # measurement itself is lost.
    [[ "${n_codes}" == "${PD_TAX_N}" ]] || { pd_tax_ok=0; pd_tax_note="${pd_tax_note} lost a measurement (${n_codes}/${PD_TAX_N} codes);"; }
    [[ "${f_wedge_b}" != "-1" && "${f_zeof_b}" != "-1" ]] || { pd_tax_ok=0; pd_tax_note="${pd_tax_note} datapath log unreadable;"; }
    [[ "${d_wedge}" == "${PD_TAX_N}" ]] || { pd_tax_ok=0; pd_tax_note="${pd_tax_note} wedge did not fire ${PD_TAX_N}x;"; }
    [[ "${d_zeof}" == "0" ]] || { pd_tax_ok=0; pd_tax_note="${pd_tax_note} stub closed first (zero-byte EOF path);"; }
    [[ "${d_dtmo}" == "${PD_TAX_N}" ]] || { pd_tax_ok=0; pd_tax_note="${pd_tax_note} {decode,timeout} Δ${d_dtmo};"; }
    [[ "${d_ptmo}" == "0" ]] || { pd_tax_ok=0; pd_tax_note="${pd_tax_note} leaked into {prefill,timeout} Δ${d_ptmo};"; }
    [[ "${d_derr}" == "0" ]] || { pd_tax_ok=0; pd_tax_note="${pd_tax_note} landed on {decode,error} Δ${d_derr};"; }
    # The wedge must be attributed to the request's own model, exactly as the
    # control's successes were. An empty-model child means the failure is
    # invisible to every per-model view even though the family total moved.
    d_empty=$(( $(pd_req_empty_model decode timeout) - f_dtmo_empty_b ))
    echo "  model label: {decode,timeout} with model=\"\" Δ${d_empty} (want 0)"
    [[ "${d_empty}" == "0" ]] || { pd_tax_ok=0; pd_tax_note="${pd_tax_note} wedge attributed to an EMPTY model label (Δ${d_empty});"; }

    # ---- restore ----------------------------------------------------------
    for ns in ${PD_DECODE_NS}; do sudo ${PD_SWAP} "${ns}" off >/dev/null || true; done
    rm -f "${pd_codes}" 2>/dev/null || true
fi
[[ -n "${pd_tax_note}" ]] && echo "  detail:${pd_tax_note}"
assert "P/D taxonomy: a decode wedge moves {decode,timeout} and leaves {prefill,timeout} flat" "$pd_tax_ok"

#################################################################################
# P/D decode-leg death — a decode backend that closes with ZERO response bytes
#
#     loxilb_pd_decode_ep_died_total is a SIX-WRITER family. A delta on it
#     proves a WRITER ran, not that THIS writer ran, and the six are not
#     interchangeable -- they carry different client outcomes (503 vs 502 vs a
#     cut stream) and two of them belong to a different engine dialect
#     entirely. Read out of the source, the sites and the line each emits are:
#
#       sockproxy_http.c:1597   pd_initiate_decode() failed   "Failed to initiate decode"
#       sockproxy_http.c:7447   pd_initiate_decode() failed   "Failed to initiate decode"   (2nd caller, SAME text)
#       sockproxy_http.c:4937   zero-byte decode EOF          "decode backend EOF with ZERO"   (+ zero_byte_eof)
#       sockproxy_http.c:4994   mid-stream decode EOF         "decode backend EOF mid-stream"
#       sockproxy_pd_sglang.c:478  SGLang decode connect      "[PD_SG] decode EP"
#       sockproxy_pd_sglang.c:545  SGLang decode send         "[PD_SG] decode send failed"
#
#     So the family total moving is NOT the claim this stage makes. The claim
#     is that the zero-byte site and ONLY the zero-byte site fired, and the
#     other five are asserted FLAT in the same window. Without that, a defect
#     that re-routed this event to the mid-stream site -- or an SGLang site
#     firing on a vLLM rule -- would move the family by exactly as much and be
#     invisible, which is the failure mode this campaign exists to catch.
#
#     The byproduct is what makes the attribution cheap: the zero-byte caller
#     ticks pd_decode_zero_byte_eof on its way to the shared statement and no
#     other caller can, so Δzero_byte_eof is a witness for that ONE site.
#
#     🚨 The two "decode backend EOF" lines share a prefix and grep -cF is
#     literal but NOT discriminating, so the discriminator is made
#     self-verifying: the loose prefix count must equal zero + mid-stream. If
#     that identity breaks, the two counts are not measuring what their names
#     say and every verdict below is void.
#
#     🚨 PLACED BEFORE THE CONNECT-RETRY STAGE ON PURPOSE. That stage ends with
#     a refusing control that is exactly the circuit breaker's trip threshold,
#     so all three prefill breakers finish OPEN. Run this stage after it and
#     the drive never gets past prefill into the decode phase at all: the
#     counter reads a flat zero that looks precisely like "this family cannot
#     be driven". The control leg below is also the vacuity guard -- if it is
#     not 200 it is not a control, and the fault leg has nothing to differ FROM.
#
#     🚨 These families are written by the POLLED collector that copies the C
#     proxy_get_metrics() snapshot once per PrometheusDefaultPeriod (10s), not
#     by a direct callback, so a short settle reads a live writer as dead and
#     makes the FLAT assertions vacuous as well as the moving ones wrong.
#################################################################################
echo "=== P/D decode death: a zero-byte decode EOF is counted, receipted and attributed to its OWN site ==="

PD_EOF_N=3
PD_EOF_SETTLE=14
PD_DIED_FAM="loxilb_pd_decode_ep_died_total"
PD_ZEOF_FAM="loxilb_pd_decode_zero_byte_eof_total"
PD_EOF_RECEIPT="pd_decode_backend_died"

PD_EOF_L_ZERO="decode backend EOF with ZERO"
PD_EOF_L_MID="decode backend EOF mid-stream"
PD_EOF_L_LOOSE="decode backend EOF "
PD_EOF_L_INIT="Failed to initiate decode"
PD_EOF_L_SGC="[PD_SG] decode EP"
PD_EOF_L_SGS="[PD_SG] decode send failed"

# "<zero> <mid> <loose> <init> <sg_connect> <sg_send>"
pd_eof_sites() {
    echo "$(dplog_count "${PD_EOF_L_ZERO}") $(dplog_count "${PD_EOF_L_MID}")" \
         "$(dplog_count "${PD_EOF_L_LOOSE}") $(dplog_count "${PD_EOF_L_INIT}")" \
         "$(dplog_count "${PD_EOF_L_SGC}") $(dplog_count "${PD_EOF_L_SGS}")"
}

# pd_eof_drive <tag> <codes-file> <receipts-file>
# The loop writes to FILES: a curl that fails to SPAWN yields an EMPTY code,
# and an empty code is a LOST MEASUREMENT, never a gateway answer. Collecting
# in a variable through a pipe would hide both that and the count.
pd_eof_drive() {
    local tag="$1" cf="$2" rf="$3" i out
    : > "${cf}"; : > "${rf}"
    for i in $(seq 1 ${PD_EOF_N}); do
        out=$($hexec l3h1 curl -s --max-time 60 -w '\n%{http_code}' \
            -H 'Content-Type: application/json' \
            -d "{\"model\":\"${KV_MODEL}\",\"prompt\":\"pd decode-eof ${tag} $i\",\"max_tokens\":8}" \
            "http://${VIP}:${VPORT}/v1/completions" 2>/dev/null)
        printf '%s\n' "${out##*$'\n'}" >> "${cf}"
        printf '%s\n' "${out}" | grep -cF "${PD_EOF_RECEIPT}" >> "${rf}" || true
    done
}

pd_eof_sum()   { awk '{s+=$1} END{printf "%d", s+0}' "$1"; }
pd_eof_codes() { tr '\n' ' ' < "$1"; }
pd_eof_n200()  { grep -cx '200' "$1" || true; }

pd_eof_ok=1
pd_eof_note=""
pd_eof_cf="$(mktemp)"; pd_eof_rf="$(mktemp)"

if [[ ! -x "${PD_SWAP}" ]]; then
    pd_eof_ok=0; pd_eof_note="missing ${PD_SWAP}"
else
    # ---- presence: both are EAGER scalars -------------------------------
    # They must be present at zero from init. An ABSENT family makes every
    # delta below a subtraction against nothing, which reads as "flat".
    e_have_d=$(llb_curl "${METRICS}" 2>/dev/null | grep -cE "^${PD_DIED_FAM}" || true)
    e_have_z=$(llb_curl "${METRICS}" 2>/dev/null | grep -cE "^${PD_ZEOF_FAM}" || true)
    echo "  presence: ${PD_DIED_FAM}=${e_have_d} ${PD_ZEOF_FAM}=${e_have_z} (want >=1 each)"
    [[ "${e_have_d}" -ge 1 && "${e_have_z}" -ge 1 ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} an eager scalar is ABSENT before any traffic — this build does not register it;"; }

    # ---- A control: decode backends answer normally ----------------------
    for ns in ${PD_DECODE_NS}; do sudo ${PD_SWAP} "${ns}" ok >/dev/null || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} could not put ${ns} in ok mode;"; }; done
    sleep 2
    a_d_b=$(metric_val "${PD_DIED_FAM}"); a_z_b=$(metric_val "${PD_ZEOF_FAM}")
    read a_s0_b a_s1_b a_s2_b a_s3_b a_s4_b a_s5_b <<<"$(pd_eof_sites)"
    pd_eof_drive "a" "${pd_eof_cf}" "${pd_eof_rf}"
    sleep ${PD_EOF_SETTLE}
    a_d_a=$(metric_val "${PD_DIED_FAM}"); a_z_a=$(metric_val "${PD_ZEOF_FAM}")
    a_codes="$(pd_eof_codes "${pd_eof_cf}")"; a_n=$(wc -l < "${pd_eof_cf}"); a_200=$(pd_eof_n200 "${pd_eof_cf}"); a_rcpt=$(pd_eof_sum "${pd_eof_rf}")
    echo "  A control-healthy: ${PD_DIED_FAM} Δ$(( a_d_a - a_d_b )) ${PD_ZEOF_FAM} Δ$(( a_z_a - a_z_b )) ; codes=${a_codes}; receipts=${a_rcpt}"
    [[ "${a_n}" -eq "${PD_EOF_N}" ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} A lost a measurement (${a_n}/${PD_EOF_N} codes);"; }
    # The vacuity guard. A control that is not 200 is not a control.
    [[ "${a_200}" -eq "${PD_EOF_N}" ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} A did not reach the decode phase (${a_200}/${PD_EOF_N} were 200, codes=${a_codes}) — the fault leg has nothing to differ FROM;"; }
    [[ $(( a_d_a - a_d_b )) -eq 0 ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} A moved ${PD_DIED_FAM} with no fault;"; }
    [[ $(( a_z_a - a_z_b )) -eq 0 ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} A moved ${PD_ZEOF_FAM} with no fault;"; }
    [[ "${a_rcpt}" -eq 0 ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} A carried a ${PD_EOF_RECEIPT} receipt with no fault;"; }

    # ---- B fault: decode backends close with ZERO response bytes ---------
    for ns in ${PD_DECODE_NS}; do sudo ${PD_SWAP} "${ns}" zerobyte >/dev/null || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} could not put ${ns} in zerobyte mode;"; }; done
    sleep 2
    b_d_b=$(metric_val "${PD_DIED_FAM}"); b_z_b=$(metric_val "${PD_ZEOF_FAM}")
    read b_s0_b b_s1_b b_s2_b b_s3_b b_s4_b b_s5_b <<<"$(pd_eof_sites)"
    pd_eof_drive "b" "${pd_eof_cf}" "${pd_eof_rf}"
    sleep ${PD_EOF_SETTLE}
    b_d_a=$(metric_val "${PD_DIED_FAM}"); b_z_a=$(metric_val "${PD_ZEOF_FAM}")
    read b_s0_a b_s1_a b_s2_a b_s3_a b_s4_a b_s5_a <<<"$(pd_eof_sites)"
    b_codes="$(pd_eof_codes "${pd_eof_cf}")"; b_n=$(wc -l < "${pd_eof_cf}"); b_rcpt=$(pd_eof_sum "${pd_eof_rf}")
    d_died=$(( b_d_a - b_d_b )); d_zeof=$(( b_z_a - b_z_b ))
    d_zero=$(( b_s0_a - b_s0_b )); d_mid=$(( b_s1_a - b_s1_b )); d_loose=$(( b_s2_a - b_s2_b ))
    d_init=$(( b_s3_a - b_s3_b )); d_sgc=$(( b_s4_a - b_s4_b )); d_sgs=$(( b_s5_a - b_s5_b ))
    echo "  B fault-zerobyte: ${PD_DIED_FAM} Δ${d_died} ${PD_ZEOF_FAM} Δ${d_zeof} ; receipts=${b_rcpt}/${PD_EOF_N} ; codes=${b_codes}"
    echo "  B site lines: zero Δ${d_zero} mid-stream Δ${d_mid} init-decode Δ${d_init} sg-connect Δ${d_sgc} sg-send Δ${d_sgs} (loose Δ${d_loose})"

    [[ "${b_n}" -eq "${PD_EOF_N}" ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} B lost a measurement (${b_n}/${PD_EOF_N} codes);"; }
    # An UNREADABLE log is not a flat log. dplog_count returns -1 on a real
    # grep error, and collapsing that into 0 would turn "I could not measure"
    # into "that site stayed silent" — which is the verdict this stage sells.
    for v in "${b_s0_b}" "${b_s1_b}" "${b_s2_b}" "${b_s3_b}" "${b_s4_b}" "${b_s5_b}" "${b_s0_a}" "${b_s1_a}" "${b_s2_a}" "${b_s3_a}" "${b_s4_a}" "${b_s5_a}"; do
        [[ "${v}" != "-1" ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} datapath log unreadable — the FLAT site verdicts would be vacuous;"; break; }
    done
    # the family moved, and the client was told
    [[ "${d_died}" -gt 0 ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} ${PD_DIED_FAM} flat under a zero-byte decode close;"; }
    [[ "${d_zeof}" -gt 0 ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} ${PD_ZEOF_FAM} flat under a zero-byte decode close;"; }
    [[ "${b_rcpt}" -gt 0 ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} no client carried the ${PD_EOF_RECEIPT} receipt;"; }
    # Receipts leave through the RESPONSE path and the deltas through the
    # METRICS path; they agree only if one block did both.
    [[ "${b_rcpt}" -eq "${d_died}" && "${d_died}" -eq "${d_zeof}" ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} receipts=${b_rcpt} Δdied=${d_died} Δzeof=${d_zeof} disagree — the counter and the client's 502 are not the same event;"; }
    # self-verifying discriminator: the loose prefix must be exactly its two parts
    [[ "${d_loose}" -eq $(( d_zero + d_mid )) ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} log discriminator is not discriminating (loose Δ${d_loose} != zero Δ${d_zero} + mid Δ${d_mid});"; }
    # THE ATTRIBUTION: this one site fired, and it fired as often as the family
    [[ "${d_zero}" -eq "${d_died}" ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} the zero-byte SITE fired Δ${d_zero} times but the family moved Δ${d_died} — another writer contributed;"; }
    # ...and the other five stayed silent
    [[ "${d_mid}"  -eq 0 ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} the MID-STREAM site also fired (Δ${d_mid});"; }
    [[ "${d_init}" -eq 0 ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} an initiate-decode site also fired (Δ${d_init});"; }
    [[ "${d_sgc}"  -eq 0 ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} the SGLang decode-connect site fired on a vLLM rule (Δ${d_sgc});"; }
    [[ "${d_sgs}"  -eq 0 ]] || { pd_eof_ok=0; pd_eof_note="${pd_eof_note} the SGLang decode-send site fired on a vLLM rule (Δ${d_sgs});"; }

    # ---- restore ---------------------------------------------------------
    for ns in ${PD_DECODE_NS}; do sudo ${PD_SWAP} "${ns}" off >/dev/null || true; done
fi
rm -f "${pd_eof_cf}" "${pd_eof_rf}" 2>/dev/null || true
[[ -n "${pd_eof_note}" ]] && echo "  detail:${pd_eof_note}"
assert "P/D decode death: a zero-byte decode EOF moves died+zero_byte_eof, receipts agree, and the other five writer sites stay flat" "$pd_eof_ok"

#################################################################################
# P/D prefill-leg death — a prefill backend that dies mid-request
#
#     loxilb_pd_prefill_ep_died_total is a FOUR-WRITER family, and three of the
#     four belong to the SGLang dialect, which this vLLM scenario never enters:
#
#       sockproxy_http.c:4671        vLLM prefill backend died   "Prefill backend died"
#       sockproxy_http.c:4883        SGLang drain-leg death      "[PD_SG] drain leg died"
#       sockproxy_pd_sglang.c:146    SGLang abort-pair (5xx)     byproduct: pd_sg_prefill_abort_decode
#       sockproxy_pd_sglang.c:367    SGLang 5xx after relay      "AFTER decode bytes relayed"
#
#     So "the family moved" is not the claim. The claim is that the vLLM site
#     fired and the three SGLang sites did not -- a dialect leaking across
#     rules would move the family by exactly as much and be invisible.
#
#     🚨 ONE CLIENT REQUEST CAN PRODUCE SEVERAL DEATHS. Prefill is idempotent
#     and the request survives in pd_saved_headers/pd_saved_body, so a death
#     re-dispatches to the next endpoint and the counter moves once per DEAD
#     ENDPOINT, not once per request. Asserting Δ == request-count would be
#     wrong in a way that looks like a product defect. The oracle that survives
#     the multiplicity is the identity Δcounter == Δ"Prefill backend died"
#     lines: the log_error and the atomic_fetch_add are two statements of ONE
#     block, so they agree whatever the re-dispatch count turns out to be.
#
#     🚨 THE RECEIPT IS KEYED ON ITS DETAIL, NOT ITS ERROR CODE. Three
#     different sites answer "pd_pool_unavailable" (sockproxy_http.c:1604,
#     :4737, :7478) and only :4737 is prefill exhaustion; :1604 is a decode
#     endpoint being unreachable. Matching the error code alone would accept a
#     DECODE-path receipt as evidence for a PREFILL-path assertion, so the
#     match is on "prefill backend connection dropped".
#
#     🚨 THIS STAGE TRIPS THE PREFILL BREAKERS, and check 10 below needs them
#     CLOSED -- its healthy control is three 200s. So the stage does not end at
#     its last assertion: it restores the endpoints and then PROVES the pool
#     came back, which is both the precondition check 10 depends on and a real
#     assertion about breaker recovery. Leaving that to luck is how a later
#     stage fails for a reason that has nothing to do with what it tests.
#################################################################################
echo "=== P/D prefill death: a dying prefill backend is counted, receipted and attributed to the vLLM site ==="

PD_PD_N=3
# Defined HERE, not borrowed: this stage runs BEFORE check 10, which is where
# the prefill netns list used to be introduced. Check 10 re-assigns the same
# value later; relying on that ordering would make this stage silently drive
# an EMPTY endpoint list if the two were ever reordered.
PD_PREFILL_NS="l3ep1 l3ep3 l3ep5"
PD_PD_SETTLE=14
PD_PDIED_FAM="loxilb_pd_prefill_ep_died_total"
PD_SGABORT_FAM="loxilb_pd_sg_prefill_abort_decode_total"
PD_PD_RECEIPT="prefill backend connection dropped"

PD_PDIED_L_VLLM="Prefill backend died"
PD_PDIED_L_SGDRAIN="[PD_SG] drain leg died"
PD_PDIED_L_SGAFTER="AFTER decode bytes relayed"

# "<vllm> <sg_drain> <sg_after>"
pd_pd_sites() {
    echo "$(dplog_count "${PD_PDIED_L_VLLM}") $(dplog_count "${PD_PDIED_L_SGDRAIN}") $(dplog_count "${PD_PDIED_L_SGAFTER}")"
}

# pd_pd_drive <tag> <codes-file> <receipts-file>
pd_pd_drive() {
    local tag="$1" cf="$2" rf="$3" i out
    : > "${cf}"; : > "${rf}"
    for i in $(seq 1 ${PD_PD_N}); do
        out=$($hexec l3h1 curl -s --max-time 60 -w '\n%{http_code}' \
            -H 'Content-Type: application/json' \
            -d "{\"model\":\"${KV_MODEL}\",\"prompt\":\"pd prefill-died ${tag} $i\",\"max_tokens\":8}" \
            "http://${VIP}:${VPORT}/v1/completions" 2>/dev/null)
        printf '%s\n' "${out##*$'\n'}" >> "${cf}"
        printf '%s\n' "${out}" | grep -cF "${PD_PD_RECEIPT}" >> "${rf}" || true
    done
}

pd_pd_ok=1
pd_pd_note=""
pd_pd_cf="$(mktemp)"; pd_pd_rf="$(mktemp)"

if [[ ! -x "${PD_SWAP}" ]]; then
    pd_pd_ok=0; pd_pd_note="missing ${PD_SWAP}"
else
    p_have=$(llb_curl "${METRICS}" 2>/dev/null | grep -cE "^${PD_PDIED_FAM}" || true)
    echo "  presence: ${PD_PDIED_FAM}=${p_have} (want >=1)"
    [[ "${p_have}" -ge 1 ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} ${PD_PDIED_FAM} is ABSENT before any traffic;"; }

    # Prove the log oracle can READ before trusting a zero from it. A pattern
    # that never matches and a log that cannot be opened look identical
    # downstream. Check 11 above leaves its own line in this log, so a zero
    # here means the oracle is blind, not that the bed is clean.
    pd_anchor=$(dplog_count "${PD_EOF_L_ZERO}")
    echo "  log oracle readable: ${DPLOG} holds ${pd_anchor} check-11 decode-EOF lines (0 or -1 = blind)"
    [[ "${pd_anchor}" != "-1" && "${pd_anchor}" -ge 1 ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} the datapath log oracle is BLIND (anchor=${pd_anchor}) — every FLAT verdict below would be vacuous;"; }

    # ---- A control: prefill backends answer normally ---------------------
    for ns in ${PD_PREFILL_NS}; do sudo ${PD_SWAP} "${ns}" ok >/dev/null || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} could not put ${ns} in ok mode;"; }; done
    sleep 2
    pa_f_b=$(metric_val "${PD_PDIED_FAM}"); pa_sg_b=$(metric_val "${PD_SGABORT_FAM}")
    read pa_s0_b pa_s1_b pa_s2_b <<<"$(pd_pd_sites)"
    pd_pd_drive "a" "${pd_pd_cf}" "${pd_pd_rf}"
    sleep ${PD_PD_SETTLE}
    pa_f_a=$(metric_val "${PD_PDIED_FAM}")
    read pa_s0_a pa_s1_a pa_s2_a <<<"$(pd_pd_sites)"
    pa_codes="$(tr '\n' ' ' < "${pd_pd_cf}")"; pa_n=$(wc -l < "${pd_pd_cf}"); pa_200=$(grep -cx '200' "${pd_pd_cf}" || true); pa_rcpt=$(awk '{s+=$1} END{printf "%d", s+0}' "${pd_pd_rf}")
    echo "  A control-healthy: ${PD_PDIED_FAM} Δ$(( pa_f_a - pa_f_b )) ; vLLM site lines Δ$(( pa_s0_a - pa_s0_b )) ; codes=${pa_codes}; receipts=${pa_rcpt}"
    [[ "${pa_n}" -eq "${PD_PD_N}" ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} A lost a measurement (${pa_n}/${PD_PD_N} codes);"; }
    [[ "${pa_200}" -eq "${PD_PD_N}" ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} A is not a control (${pa_200}/${PD_PD_N} were 200, codes=${pa_codes});"; }
    [[ $(( pa_f_a - pa_f_b )) -eq 0 ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} A moved ${PD_PDIED_FAM} with no fault;"; }
    [[ $(( pa_s0_a - pa_s0_b )) -eq 0 ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} A logged a prefill-death line with no fault;"; }
    [[ "${pa_rcpt}" -eq 0 ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} A carried a prefill-exhaustion receipt with no fault;"; }

    # ---- B fault: prefill backends close with ZERO response bytes --------
    for ns in ${PD_PREFILL_NS}; do sudo ${PD_SWAP} "${ns}" zerobyte >/dev/null || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} could not put ${ns} in zerobyte mode;"; }; done
    sleep 2
    pb_f_b=$(metric_val "${PD_PDIED_FAM}"); pb_sg_b=$(metric_val "${PD_SGABORT_FAM}")
    read pb_s0_b pb_s1_b pb_s2_b <<<"$(pd_pd_sites)"
    pd_pd_drive "b" "${pd_pd_cf}" "${pd_pd_rf}"
    sleep ${PD_PD_SETTLE}
    pb_f_a=$(metric_val "${PD_PDIED_FAM}"); pb_sg_a=$(metric_val "${PD_SGABORT_FAM}")
    read pb_s0_a pb_s1_a pb_s2_a <<<"$(pd_pd_sites)"
    pb_codes="$(tr '\n' ' ' < "${pd_pd_cf}")"; pb_n=$(wc -l < "${pd_pd_cf}"); pb_rcpt=$(awk '{s+=$1} END{printf "%d", s+0}' "${pd_pd_rf}")
    dp_fam=$(( pb_f_a - pb_f_b )); dp_vllm=$(( pb_s0_a - pb_s0_b ))
    dp_sgdr=$(( pb_s1_a - pb_s1_b )); dp_sgaf=$(( pb_s2_a - pb_s2_b )); dp_sgab=$(( pb_sg_a - pb_sg_b ))
    echo "  B fault-zerobyte: ${PD_PDIED_FAM} Δ${dp_fam} ; receipts=${pb_rcpt}/${PD_PD_N} ; codes=${pb_codes}"
    echo "  B site evidence: vLLM Δ${dp_vllm} ; sg-drain Δ${dp_sgdr} ; sg-after Δ${dp_sgaf} ; ${PD_SGABORT_FAM} Δ${dp_sgab}"

    [[ "${pb_n}" -eq "${PD_PD_N}" ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} B lost a measurement (${pb_n}/${PD_PD_N} codes);"; }
    for v in "${pb_s0_b}" "${pb_s1_b}" "${pb_s2_b}" "${pb_s0_a}" "${pb_s1_a}" "${pb_s2_a}"; do
        [[ "${v}" != "-1" ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} datapath log unreadable during the fault window;"; break; }
    done
    [[ "${dp_fam}" -gt 0 ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} ${PD_PDIED_FAM} flat while every prefill backend died;"; }
    [[ "${pb_rcpt}" -gt 0 ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} no client carried the prefill-exhaustion receipt (${PD_PD_RECEIPT});"; }
    # Survives the re-dispatch multiplicity: same block, two statements.
    [[ "${dp_fam}" -eq "${dp_vllm}" ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} Δcounter=${dp_fam} != Δ'${PD_PDIED_L_VLLM}' lines=${dp_vllm} — the counter and the log are not the same event;"; }
    # ...and the three SGLang writers stayed out of it.
    [[ "${dp_sgdr}" -eq 0 ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} the SGLang drain-leg site fired on a vLLM rule (Δ${dp_sgdr});"; }
    [[ "${dp_sgaf}" -eq 0 ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} the SGLang after-relay site fired on a vLLM rule (Δ${dp_sgaf});"; }
    [[ "${dp_sgab}" -eq 0 ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} the SGLang abort-pair site fired on a vLLM rule (${PD_SGABORT_FAM} Δ${dp_sgab});"; }

    # ---- restore, and PROVE the pool came back --------------------------
    # Not housekeeping: check 10 below opens with three healthy 200s, and this
    # stage has just tripped every prefill breaker. A stage that leaves the bed
    # broken makes the NEXT stage fail for a reason that is not its own.
    for ns in ${PD_PREFILL_NS}; do sudo ${PD_SWAP} "${ns}" off >/dev/null || true; done
    pd_pd_heal=0
    for i in $(seq 1 12); do
        sleep 5
        if [[ "$($hexec l3h1 curl -s -o /dev/null --max-time 30 -w '%{http_code}' \
                -H 'Content-Type: application/json' \
                -d "{\"model\":\"${KV_MODEL}\",\"prompt\":\"pd prefill-heal probe $i\",\"max_tokens\":8}" \
                "http://${VIP}:${VPORT}/v1/completions" 2>/dev/null)" == "200" ]]; then
            pd_pd_heal=$i; break
        fi
    done
    echo "  recovery: prefill pool served a 200 again after ${pd_pd_heal} probe(s) (0 = never recovered)"
    [[ "${pd_pd_heal}" -gt 0 ]] || { pd_pd_ok=0; pd_pd_note="${pd_pd_note} the prefill pool never served a 200 again after the endpoints were restored — the breakers did not recover;"; }
fi
rm -f "${pd_pd_cf}" "${pd_pd_rf}" 2>/dev/null || true
[[ -n "${pd_pd_note}" ]] && echo "  detail:${pd_pd_note}"
assert "P/D prefill death: a dying prefill backend moves prefill_ep_died with the vLLM site's own log line, receipts agree, the three SGLang sites stay flat, and the pool recovers" "$pd_pd_ok"

#################################################################################
# P/D proactive circuit-breaker heal — the 1Hz health pass, not traffic
#
#     loxilb_pd_cb_proactive_heal_total has exactly ONE writer
#     (sockproxy_health.c:425), so Δcounter == Δ its log line is an EXACT
#     identity rather than the inequality the multi-writer families get.
#
#     What makes the family worth a stage is WHICH heal it counts. KV/PD
#     selection skips an OPEN breaker, and recovery normally needs a successful
#     relay -- which can never happen on an endpoint nothing selects. That is a
#     latch: a prefill endpoint whose breaker opened during a restart would be
#     skipped permanently. The health pass breaks it by driving OPEN->HALF_OPEN
#     off the relay path entirely, so the endpoint re-enters rotation and the
#     next genuine success closes it. This stage's whole point is that the heal
#     happens with NO traffic at all: the fault's second phase drives nothing.
#
#     🚨 THIS ARM IS TIME-DRIVEN, AND THE CONTROL MUST GET THE SAME WALL CLOCK.
#     A control that is merely "healthy" would be flat because nobody waited,
#     and a counter that healed on a plain timer regardless of breaker state
#     would sail straight through it. So the control gets the same request
#     count AND the same trip+heal window as the fault.
#
#     🚨 FAILURES ARE RECORDED IN THE REQUEST PATH, NOT THE HEALTH PASS. An
#     earlier version of this arm made the endpoints refuse and simply waited,
#     assuming the 1Hz pass would trip the breaker by itself. It read Δ0 and
#     looked like a dead product; the assumption was the defect. Only the HEAL
#     is health-pass driven. So phase A DRIVES traffic to record the failures,
#     and asserts the CLOSED->OPEN lines actually moved -- without that the
#     heal in phase B would be a delta against breakers that never opened.
#
#     🚨 pd_cb_flips IS ONLY AN INEQUALITY HERE, DELIBERATELY. It has seven
#     writers and one of them -- sockproxy_health.c:1103, OPEN->HALF_OPEN on
#     open_timeout expiry in the traffic path -- increments with NO log line at
#     all. Six sites can be counted and one cannot, so the only statement the
#     code supports is Δflips >= Δ(the observable sites). Asserting equality
#     would be claiming evidence that does not exist. The silent site is itself
#     worth reporting: a state transition that counts but leaves no trace
#     cannot be attributed after the fact.
#
#     🚨 RUNS BEFORE CHECK 10 AND AFTER CHECK 12. Its control needs a bed with
#     NO breaker already open -- check 10 ends with three of them OPEN, and
#     they would heal during this stage's control window and move the very
#     counter the control asserts flat. Check 12 above ends by proving the pool
#     recovered, which is exactly the clean start this needs.
#################################################################################
echo "=== P/D proactive CB heal: an OPEN breaker is healed by the 1Hz health pass with no traffic ==="

PD_CB_N=6
PD_CB_TRIP_WAIT=20
PD_CB_HEAL_WAIT=45
PD_CB_ALL_NS="l3ep1 l3ep2 l3ep3 l3ep4 l3ep5 l3ep6"
PD_HEAL_FAM="loxilb_pd_cb_proactive_heal_total"
PD_FLIPS_FAM="loxilb_pd_cb_flips_total"
PD_HEAL_LINE="OPEN->HALF_OPEN driven by 1Hz health pass"
PD_CB_OPEN_LINE="Circuit breaker CLOSED → OPEN"

pd_cb_drive() {   # <tag> <codes-file>
    local tag="$1" cf="$2" i
    : > "${cf}"
    for i in $(seq 1 ${PD_CB_N}); do
        $hexec l3h1 curl -s -o /dev/null --max-time 60 -w '%{http_code}\n' \
            -H 'Content-Type: application/json' \
            -d "{\"model\":\"${KV_MODEL}\",\"prompt\":\"pd cb-heal ${tag} $i\",\"max_tokens\":8}" \
            "http://${VIP}:${VPORT}/v1/completions" 2>/dev/null >> "${cf}"
    done
}

pd_cb_ok=1
pd_cb_note=""
pd_cb_cf="$(mktemp)"

if [[ ! -x "${PD_SWAP}" ]]; then
    pd_cb_ok=0; pd_cb_note="missing ${PD_SWAP}"
else
    c_have=$(llb_curl "${METRICS}" 2>/dev/null | grep -cE "^${PD_HEAL_FAM}" || true)
    echo "  presence: ${PD_HEAL_FAM}=${c_have} (want >=1)"
    [[ "${c_have}" -ge 1 ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} ${PD_HEAL_FAM} is ABSENT before any traffic;"; }

    # ---- A control: healthy, SAME traffic AND the SAME wall clock ---------
    for ns in ${PD_CB_ALL_NS}; do sudo ${PD_SWAP} "${ns}" off >/dev/null || true; done
    sleep 3
    ca_h_b=$(metric_val "${PD_HEAL_FAM}"); ca_f_b=$(metric_val "${PD_FLIPS_FAM}")
    ca_l_b=$(dplog_count "${PD_HEAL_LINE}")
    pd_cb_drive "a" "${pd_cb_cf}"
    ca_codes="$(tr '\n' ' ' < "${pd_cb_cf}")"; ca_200=$(grep -cx '200' "${pd_cb_cf}" || true); ca_n=$(wc -l < "${pd_cb_cf}")
    sleep $(( PD_CB_TRIP_WAIT + PD_CB_HEAL_WAIT ))
    ca_h_a=$(metric_val "${PD_HEAL_FAM}"); ca_f_a=$(metric_val "${PD_FLIPS_FAM}")
    ca_l_a=$(dplog_count "${PD_HEAL_LINE}")
    echo "  A control-healthy (same ${PD_CB_N} requests + same $(( PD_CB_TRIP_WAIT + PD_CB_HEAL_WAIT ))s window): ${PD_HEAL_FAM} Δ$(( ca_h_a - ca_h_b )) ; ${PD_FLIPS_FAM} Δ$(( ca_f_a - ca_f_b )) ; heal lines Δ$(( ca_l_a - ca_l_b )) ; codes=${ca_codes}"
    [[ "${ca_n}" -eq "${PD_CB_N}" ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} A lost a measurement (${ca_n}/${PD_CB_N} codes);"; }
    [[ "${ca_200}" -eq "${PD_CB_N}" ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} A is not a control (${ca_200}/${PD_CB_N} were 200, codes=${ca_codes});"; }
    [[ $(( ca_h_a - ca_h_b )) -eq 0 ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} ${PD_HEAL_FAM} moved over a full trip+heal window with NO breaker open — it heals on a timer regardless of state;"; }
    [[ $(( ca_l_a - ca_l_b )) -eq 0 ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} A logged a heal line with no breaker open;"; }
    [[ $(( ca_f_a - ca_f_b )) -eq 0 ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} ${PD_FLIPS_FAM} moved on healthy traffic;"; }

    # ---- B phase 1: refuse + DRIVE, so the request path records failures --
    for ns in ${PD_CB_ALL_NS}; do sudo ${PD_SWAP} "${ns}" refuse >/dev/null || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} could not put ${ns} in refuse mode;"; }; done
    sleep 2
    cb_h_b=$(metric_val "${PD_HEAL_FAM}"); cb_f_b=$(metric_val "${PD_FLIPS_FAM}")
    cb_l_b=$(dplog_count "${PD_HEAL_LINE}"); cb_o_b=$(dplog_count "${PD_CB_OPEN_LINE}")
    pd_cb_drive "b" "${pd_cb_cf}"
    cb_codes="$(tr '\n' ' ' < "${pd_cb_cf}")"
    sleep ${PD_CB_TRIP_WAIT}
    cb_o_m=$(dplog_count "${PD_CB_OPEN_LINE}")
    echo "  B1 trip: CLOSED→OPEN lines Δ$(( cb_o_m - cb_o_b )) ; codes=${cb_codes}"
    # Drive-shape proof. If nothing opened, the heal below is a delta against
    # breakers that were never OPEN, and a zero there would read as a dead
    # family rather than as an arm that failed to set up its own precondition.
    [[ "${cb_o_b}" != "-1" && "${cb_o_m}" != "-1" ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} datapath log unreadable during the trip phase;"; }
    [[ $(( cb_o_m - cb_o_b )) -gt 0 ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} no breaker reached OPEN (CLOSED→OPEN Δ0) — the heal phase below would be vacuous;"; }

    # ---- B phase 2: restore and DRIVE NOTHING. Only the health pass runs ---
    for ns in ${PD_CB_ALL_NS}; do sudo ${PD_SWAP} "${ns}" off >/dev/null || true; done
    sleep ${PD_CB_HEAL_WAIT}
    cb_h_a=$(metric_val "${PD_HEAL_FAM}"); cb_f_a=$(metric_val "${PD_FLIPS_FAM}")
    cb_l_a=$(dplog_count "${PD_HEAL_LINE}")
    d_heal=$(( cb_h_a - cb_h_b )); d_flips=$(( cb_f_a - cb_f_b )); d_heall=$(( cb_l_a - cb_l_b ))
    echo "  B2 heal (NO traffic driven, ${PD_CB_HEAL_WAIT}s): ${PD_HEAL_FAM} Δ${d_heal} ; heal lines Δ${d_heall} ; ${PD_FLIPS_FAM} Δ${d_flips}"
    [[ "${cb_l_b}" != "-1" && "${cb_l_a}" != "-1" ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} datapath log unreadable during the heal phase;"; }
    [[ "${d_heal}" -gt 0 ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} ${PD_HEAL_FAM} flat — an OPEN breaker was NOT healed by the health pass, which is the permanent-skip latch this family exists to report;"; }
    # Single writer, so this is an exact identity, not an inequality.
    [[ "${d_heal}" -eq "${d_heall}" ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} Δcounter=${d_heal} != Δheal-log=${d_heall} — the family has ONE writer, so these must agree exactly;"; }
    # Inequality ON PURPOSE: one pd_cb_flips site logs nothing at all.
    [[ "${d_flips}" -ge "${d_heal}" ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} ${PD_FLIPS_FAM} Δ${d_flips} < ${PD_HEAL_FAM} Δ${d_heal} — every proactive heal IS a flip, so the superset counted fewer than the subset;"; }

    # ---- restore, and PROVE the pool serves again ------------------------
    for ns in ${PD_CB_ALL_NS}; do sudo ${PD_SWAP} "${ns}" off >/dev/null || true; done
    pd_cb_heal_ok=0
    for i in $(seq 1 12); do
        sleep 5
        if [[ "$($hexec l3h1 curl -s -o /dev/null --max-time 30 -w '%{http_code}' \
                -H 'Content-Type: application/json' \
                -d "{\"model\":\"${KV_MODEL}\",\"prompt\":\"pd cb-heal recovery probe $i\",\"max_tokens\":8}" \
                "http://${VIP}:${VPORT}/v1/completions" 2>/dev/null)" == "200" ]]; then
            pd_cb_heal_ok=$i; break
        fi
    done
    echo "  recovery: pool served a 200 again after ${pd_cb_heal_ok} probe(s) (0 = never recovered)"
    [[ "${pd_cb_heal_ok}" -gt 0 ]] || { pd_cb_ok=0; pd_cb_note="${pd_cb_note} the pool never served a 200 again — a healed breaker did not restore service;"; }
fi
rm -f "${pd_cb_cf}" 2>/dev/null || true
[[ -n "${pd_cb_note}" ]] && echo "  detail:${pd_cb_note}"
assert "P/D proactive CB heal: an OPEN breaker is healed by the 1Hz health pass with no traffic, counted exactly once per log line" "$pd_cb_ok"

#################################################################################
# P/D session stickiness gauge — a SESSION count, not a request count
#
#     loxilb_pd_sessions_active is not a counter and not a concurrency gauge.
#     sockproxy_metrics.c:192 computes it as HASH_COUNT(tepval->pd_session_map)
#     summed over services: the SIZE OF THE STICKINESS MAP. The obvious drive --
#     hold N requests in flight against a hanging backend and expect N -- would
#     measure a different thing entirely and pass or fail for the wrong reason.
#
#     Entries come from pd_session_store(), and a key exists only if the request
#     carries one. The key is read from exactly two places
#     (sockproxy_ep.c:834-838, mirrored at sockproxy_pd.c:1917-1928): the JSON
#     body "user" field, and a client-provided X-Conversation-Id header which
#     takes priority and whose auto-generated "auto-" prefix is explicitly
#     skipped. With neither present the key stays NULL and nothing is stored.
#
#     That gives this stage an unusually strong control: THE IDENTICAL REQUEST,
#     same body, same endpoints, MINUS ONE HEADER. A flat control here cannot be
#     dismissed as flat-for-lack-of-traffic, which is the usual weakness of a
#     gauge control.
#
#     🚨 DRIVE B IS THE POINT OF THE STAGE. pd_session_store is an UPSERT
#     (HASH_FIND_STR then update-in-place, sockproxy_pd.c:1146-1167; the
#     HASH_ADD_STR at :1213 is reached only when the key is NOT found), so M
#     requests sharing ONE key add EXACTLY ONE entry. A delta of M there would
#     mean the gauge counts requests and its name is wrong. Without drive B,
#     drive A alone is equally consistent with a request counter.
#
#     🚨 ONE INSERT STATEMENT, FOUR CALLERS. pd_session_store is called from
#     sockproxy_ep.c:840 (normal selection), sockproxy_ep.c:1165 (mid-cycle
#     failover), sockproxy_pd_vllm.c:683 (prefill mid-request failover) and
#     sockproxy_pd_sglang.c:949 (SGLang). A delta proves a caller ran, not WHICH
#     one, so the two failover callers are asserted flat by their own log lines
#     AND by loxilb_pd_connect_failover_total, which the vLLM failover caller
#     ticks on its way past and the normal caller cannot.
#
#     🚨 THIS GAUGE DOES NOT RETURN TO BASELINE AND MUST NOT BE ASSERTED TO.
#     Entries live out PD_SESSION_DEFAULT_TTL (300s, sockproxy_pd.c:958) because
#     that is correct behaviour for an affinity map. An assertion that it falls
#     back to zero would FAIL AGAINST A WORKING PRODUCT. The bound above it
#     (PD_SESSION_MAX_ENTRIES 4096, LRU-evicted) is far out of reach here, so
#     neither eviction nor TTL can move the gauge under the measurement.
#################################################################################
echo "=== P/D session gauge: sessions_active counts session KEYS, and an upsert adds one ==="

PD_SESS_FAM="loxilb_pd_sessions_active"
PD_FAILOVER_FAM2="loxilb_pd_connect_failover_total"
PD_SESS_SETTLE=14
PD_SESS_SEL_LINE="US-PD804: P/D EP selected"
PD_SESS_MIDFO_LINE="US-PD804: P/D mid-cycle failover"
PD_SESS_LOOSE_LINE="US-PD804: P/D "
PD_SESS_VLLMFO_LINE="prefill mid-request failover"

# "<selected> <midcycle_failover> <loose> <vllm_failover>"
pd_sess_sites() {
    echo "$(dplog_count "${PD_SESS_SEL_LINE}") $(dplog_count "${PD_SESS_MIDFO_LINE}")" \
         "$(dplog_count "${PD_SESS_LOOSE_LINE}") $(dplog_count "${PD_SESS_VLLMFO_LINE}")"
}

# pd_sess_drive <codes-file> <n> [conv-id]
# With no conv-id the request carries NO session key at all -- same body, same
# endpoints, one header fewer. That is the control.
pd_sess_drive() {
    local cf="$1" n="$2" cid="${3:-}" i
    : > "${cf}"
    for i in $(seq 1 "${n}"); do
        if [[ -n "${cid}" ]]; then
            $hexec l3h1 curl -s -o /dev/null --max-time 60 -w '%{http_code}\n' \
                -H 'Content-Type: application/json' -H "X-Conversation-Id: ${cid}" \
                -d "{\"model\":\"${KV_MODEL}\",\"prompt\":\"pd session probe ${cid} $i\",\"max_tokens\":8}" \
                "http://${VIP}:${VPORT}/v1/completions" 2>/dev/null >> "${cf}"
        else
            $hexec l3h1 curl -s -o /dev/null --max-time 60 -w '%{http_code}\n' \
                -H 'Content-Type: application/json' \
                -d "{\"model\":\"${KV_MODEL}\",\"prompt\":\"pd session probe nokey $i\",\"max_tokens\":8}" \
                "http://${VIP}:${VPORT}/v1/completions" 2>/dev/null >> "${cf}"
        fi
    done
}

pd_sess_ok=1
pd_sess_note=""
pd_sess_cf="$(mktemp)"
PD_SESS_STAMP="$(date +%s)"

s_have=$(llb_curl "${METRICS}" 2>/dev/null | grep -cE "^${PD_SESS_FAM}" || true)
echo "  presence: ${PD_SESS_FAM}=${s_have} (want >=1)"
[[ "${s_have}" -ge 1 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} ${PD_SESS_FAM} is ABSENT — every delta below would be computed from nothing;"; }

# Endpoints healthy and unmodified for the whole stage: this gauge is driven by
# request SHAPE, not by faults, and a fault would drag in the failover callers
# that the site assertions below require to stay silent.
for ns in ${PD_PREFILL_NS} ${PD_DECODE_NS}; do sudo ${PD_SWAP} "${ns}" off >/dev/null || true; done
sleep 3

# ---- A control: identical requests carrying NO session key -----------------
sa_b=$(metric_val "${PD_SESS_FAM}"); sa_fo_b=$(metric_val "${PD_FAILOVER_FAM2}")
read sa_s0_b sa_s1_b sa_s2_b sa_s3_b <<<"$(pd_sess_sites)"
pd_sess_drive "${pd_sess_cf}" 3
sleep ${PD_SESS_SETTLE}
sa_a=$(metric_val "${PD_SESS_FAM}")
sa_codes="$(tr '\n' ' ' < "${pd_sess_cf}")"; sa_n=$(wc -l < "${pd_sess_cf}"); sa_200=$(grep -cx '200' "${pd_sess_cf}" || true)
echo "  A control (3 requests, NO X-Conversation-Id): ${PD_SESS_FAM} ${sa_b}->${sa_a} Δ$(( sa_a - sa_b )) ; codes=${sa_codes}"
[[ "${sa_n}" -eq 3 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} A lost a measurement (${sa_n}/3 codes);"; }
[[ "${sa_200}" -eq 3 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} A is not a control (${sa_200}/3 were 200, codes=${sa_codes});"; }
[[ $(( sa_a - sa_b )) -eq 0 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} A moved the gauge Δ$(( sa_a - sa_b )) on requests carrying NO session key — something other than the key is creating map entries;"; }

# ---- B drive: three DISTINCT keys must add EXACTLY three -------------------
sb_b=$(metric_val "${PD_SESS_FAM}")
: > "${pd_sess_cf}.all"
for k in 1 2 3; do pd_sess_drive "${pd_sess_cf}" 1 "wp11-sess-${PD_SESS_STAMP}-${k}"; cat "${pd_sess_cf}" >> "${pd_sess_cf}.all"; done
sleep ${PD_SESS_SETTLE}
sb_a=$(metric_val "${PD_SESS_FAM}")
sb_codes="$(tr '\n' ' ' < "${pd_sess_cf}.all")"; sb_200=$(grep -cx '200' "${pd_sess_cf}.all" || true)
d_sb=$(( sb_a - sb_b ))
echo "  B drive (3 requests, 3 DISTINCT keys): ${PD_SESS_FAM} ${sb_b}->${sb_a} Δ${d_sb} (want EXACTLY 3) ; codes=${sb_codes}"
[[ "${sb_200}" -eq 3 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} B did not get 3x200 (codes=${sb_codes});"; }
[[ "${d_sb}" -eq 3 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} 3 distinct session keys moved the gauge Δ${d_sb}, not 3 — one key must add exactly one map entry;"; }

# ---- C drive: FOUR requests on ONE key must add EXACTLY one ---------------
# This is the check that makes it a SESSION gauge rather than a request counter.
sc_b=$(metric_val "${PD_SESS_FAM}")
pd_sess_drive "${pd_sess_cf}" 4 "wp11-sess-${PD_SESS_STAMP}-shared"
sleep ${PD_SESS_SETTLE}
sc_a=$(metric_val "${PD_SESS_FAM}")
read sc_s0_a sc_s1_a sc_s2_a sc_s3_a <<<"$(pd_sess_sites)"
sa_fo_a=$(metric_val "${PD_FAILOVER_FAM2}")
sc_codes="$(tr '\n' ' ' < "${pd_sess_cf}")"; sc_n=$(wc -l < "${pd_sess_cf}"); sc_200=$(grep -cx '200' "${pd_sess_cf}" || true)
d_sc=$(( sc_a - sc_b ))
echo "  C drive (4 requests, ONE shared key): ${PD_SESS_FAM} ${sc_b}->${sc_a} Δ${d_sc} (want EXACTLY 1 — upsert) ; codes=${sc_codes}"
[[ "${sc_n}" -eq 4 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} C lost a measurement (${sc_n}/4 codes);"; }
[[ "${sc_200}" -eq 4 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} C did not get 4x200 (codes=${sc_codes});"; }
[[ "${d_sc}" -eq 1 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} 4 requests on ONE key moved the gauge Δ${d_sc}, not 1 — pd_session_store is an UPSERT, so a delta of 4 would mean this gauge counts REQUESTS and its name is wrong;"; }

# ---- which caller did it -------------------------------------------------
d_sel=$(( sc_s0_a - sa_s0_b )); d_midfo=$(( sc_s1_a - sa_s1_b ))
d_loose=$(( sc_s2_a - sa_s2_b )); d_vllmfo=$(( sc_s3_a - sa_s3_b ))
d_fo=$(( sa_fo_a - sa_fo_b ))
echo "  caller evidence over the whole stage: selected Δ${d_sel} ; mid-cycle failover Δ${d_midfo} ; vLLM prefill failover Δ${d_vllmfo} ; ${PD_FAILOVER_FAM2} Δ${d_fo} (loose Δ${d_loose})"
for v in "${sa_s0_b}" "${sa_s1_b}" "${sa_s2_b}" "${sa_s3_b}" "${sc_s0_a}" "${sc_s1_a}" "${sc_s2_a}" "${sc_s3_a}"; do
    [[ "${v}" != "-1" ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} datapath log unreadable — the FLAT caller verdicts would be vacuous;"; break; }
done
[[ "${d_sel}" -gt 0 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} the normal selection caller never logged, so no caller is attributable;"; }
# Self-verifying: the loose prefix is shared by exactly these two lines.
[[ "${d_loose}" -eq $(( d_sel + d_midfo )) ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} log discriminator is not discriminating (loose Δ${d_loose} != selected Δ${d_sel} + mid-cycle Δ${d_midfo});"; }
[[ "${d_midfo}" -eq 0 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} the mid-cycle failover caller also stored sessions (Δ${d_midfo}) — the deltas above are not attributable to normal selection;"; }
[[ "${d_vllmfo}" -eq 0 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} the vLLM prefill-failover caller also stored sessions (Δ${d_vllmfo});"; }
[[ "${d_fo}" -eq 0 ]] || { pd_sess_ok=0; pd_sess_note="${pd_sess_note} ${PD_FAILOVER_FAM2} Δ${d_fo} — a failover ran during a no-fault stage, so a failover caller may own part of the gauge delta;"; }

rm -f "${pd_sess_cf}" "${pd_sess_cf}.all" 2>/dev/null || true
[[ -n "${pd_sess_note}" ]] && echo "  detail:${pd_sess_note}"
assert "P/D session gauge: no key adds nothing, 3 distinct keys add 3, and 4 requests on one key add 1 (upsert), all from the normal selection caller" "$pd_sess_ok"

#################################################################################
# P/D radix-trie gauge — a CONFIG-gated structure with an exact node arithmetic
#
#     loxilb_pd_trie_nodes (sockproxy_metrics.c:196) is pd_trie_node_count()
#     summed over services: the live size of the Tier-1 radix trie. It is gated
#     by the per-rule API field pd_cache_aware_mode, NOT by an engine and NOT by
#     a build flag on this image -- common/Makefile defines
#     HAVE_LLM_SYSTEM_PROMPT_HASH unconditionally, and the one code path that
#     would degrade the mode to 0 logs when it does. pd_cache_aware_mode is in
#     the extended-mutable-field set (pkg/loxinet/rules.go:4183), so flipping it
#     is a re-POST of the SAME rule, not a delete plus re-add by hand; a field
#     NOT in that set (kvEngineType) rejects instead, which is why this stage
#     can toggle its own gate but a stage for that one could not.
#
#     🚨 A GAUGE HAS TWO WRITER CLASSES AND ONE END-STATE READING CANNOT TELL
#     THEM APART. Opening the gate creates the trie ROOT at rule-add time
#     (pd_trie_create sets node_count = 1, sockproxy_pd_trie.c:316) -- that is
#     the CONFIG-time writer. Requests then add leaves -- the TRAFFIC-time
#     writer. So the stage reads the gauge with the gate OPEN and NO TRAFFIC
#     first, pinning the config-time contribution at EXACTLY 1, and only then
#     drives. Without that reading, 4 could be one root plus three inserts or
#     any other split, and the arithmetic below would prove nothing.
#
#     The node arithmetic is read out of pd_trie_insert (sockproxy_pd_trie.c:384).
#     It is a RADIX trie: a key whose FIRST BYTE matches no child of the root
#     allocates ONE leaf holding the whole remaining text (node_count++ at :403).
#     A key sharing a first byte with an existing child SPLITS it and adds TWO
#     (:452 mid, :463 leaf). So three prompts with DISTINCT first bytes add
#     exactly three, and 1 + 3 = 4 is an exact prediction rather than a
#     direction. The prompts below therefore start with distinct characters on
#     purpose -- for /v1/completions the trie key is the PROMPT TEXT itself
#     (sockproxy_json.c:1138 copies the unescaped prompt into
#     prefix_key.prefix), not a hash, so the first byte is ours to choose.
#
#     🚨 WHICH INSERT SITE. There are two (sockproxy_pd.c:1998 Tier-1, :2168
#     Tier-2) and they are not interchangeable. Tier 1 inserts ONLY on a trie
#     MATCH at or above the threshold; Tier 1.5 (kvExactMode=1 here) RETURNS
#     before Tier 2 when it resolves. So the prompts are stamped and unique:
#     they cannot match the trie and cannot hit a KV block, and they fall
#     through to the Tier-2 RR site. That is asserted, not assumed, by an
#     INDEPENDENT family -- loxilb_ai_pd_tier_selected_total{tier="tier2"} must
#     move by the drive count while {tier="tier1"} stays flat.
#
#     🚨 NO SESSION KEY ON THESE REQUESTS. Tier 0 is session stickiness and
#     returns before Tier 1 entirely, so an X-Conversation-Id would route the
#     drive past both insert sites and read as a dead family.
#
#     Closing the gate again must return the gauge to EXACTLY 0, which is what
#     rules out "the rule re-add did it" as an explanation for the rise.
#################################################################################
echo "=== P/D trie gauge: a config-gated trie, one root plus one leaf per distinct-first-byte key ==="

PD_TRIE_FAM="loxilb_pd_trie_nodes"
PD_TRIE_SETTLE=14
PD_TRIE_N=3
PD_TRIE_STAMP="$(date +%s)"

pd_tier_sel() { metric_val "loxilb_ai_pd_tier_selected_total\{[^}]*tier=\"$1\""; }

# Re-POST the scenario's own rule with pd_cache_aware_mode set as asked. Same
# key (externalIP/port/host/model_name), so this is a field change on the live
# rule rather than a second service.
pd_trie_post() {   # <true|false> -> echoes the HTTP code
    local mode="$1"
    $hexec llb1 curl -s -o /dev/null --max-time 20 -w '%{http_code}' \
        -X POST "${LBBASE}" -H 'Content-Type: application/json' -d "{
  \"serviceArguments\": {
    \"externalIP\": \"${VIP}\",
    \"port\": ${VPORT},
    \"protocol\": \"tcp\",
    \"sel\": 0,
    \"mode\": 4,
    \"host\": \"${VIP}\",
    \"model_name\": \"${KV_MODEL}\",
    \"pd_disagg_mode\": true,
    \"probeRetries\": 1,
    \"pd_cache_aware_mode\": ${mode},
    \"kvExactMode\": 1,
    \"kvZmqPort\": ${KV_ZMQ_PORT},
    \"kvHashAlgo\": \"${KV_HASH_ALGO}\",
    \"kvWarmupSec\": 20,
    \"kvBlockSize\": ${KV_BLOCK_SIZE}
  },
  \"endpoints\": [
    { \"endpointIP\": \"31.31.31.1\", \"targetPort\": 80, \"weight\": 1, \"ep_role\": 1 },
    { \"endpointIP\": \"32.32.32.1\", \"targetPort\": 80, \"weight\": 1, \"ep_role\": 2 },
    { \"endpointIP\": \"33.33.33.1\", \"targetPort\": 80, \"weight\": 1, \"ep_role\": 1 },
    { \"endpointIP\": \"34.34.34.1\", \"targetPort\": 80, \"weight\": 1, \"ep_role\": 2 },
    { \"endpointIP\": \"35.35.35.1\", \"targetPort\": 80, \"weight\": 1, \"ep_role\": 1 },
    { \"endpointIP\": \"36.36.36.1\", \"targetPort\": 80, \"weight\": 1, \"ep_role\": 2 }
  ]
}" 2>/dev/null
}

# Three prompts with DISTINCT first bytes, each stamped so it can neither match
# the trie nor hit a KV block. NO X-Conversation-Id: a session key returns at
# Tier 0, before either insert site.
pd_trie_drive() {   # <codes-file>
    local cf="$1" p
    : > "${cf}"
    for p in A B C; do
        $hexec l3h1 curl -s -o /dev/null --max-time 60 -w '%{http_code}\n' \
            -H 'Content-Type: application/json' \
            -d "{\"model\":\"${KV_MODEL}\",\"prompt\":\"${p}lpha trie probe ${PD_TRIE_STAMP} ${p} unique tail\",\"max_tokens\":8}" \
            "http://${VIP}:${VPORT}/v1/completions" 2>/dev/null >> "${cf}"
    done
}

pd_trie_ok=1
pd_trie_note=""
pd_trie_cf="$(mktemp)"

t_have=$(llb_curl "${METRICS}" 2>/dev/null | grep -cE "^${PD_TRIE_FAM} " || true)
echo "  presence: ${PD_TRIE_FAM}=${t_have} (want >=1 — ABSENT and 0 are different states and metric_val cannot tell them apart)"
[[ "${t_have}" -ge 1 ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} ${PD_TRIE_FAM} is ABSENT, so every reading below is a subtraction against nothing;"; }

for ns in ${PD_PREFILL_NS} ${PD_DECODE_NS}; do sudo ${PD_SWAP} "${ns}" off >/dev/null || true; done
sleep 3

# ---- A control: gate CLOSED, real traffic, gauge pinned at zero ------------
ta_t2_b=$(pd_tier_sel tier2)
pd_trie_drive "${pd_trie_cf}"
sleep ${PD_TRIE_SETTLE}
ta_v=$(metric_val "${PD_TRIE_FAM}"); ta_t2_a=$(pd_tier_sel tier2)
ta_codes="$(tr '\n' ' ' < "${pd_trie_cf}")"; ta_200=$(grep -cx '200' "${pd_trie_cf}" || true)
echo "  A control (gate CLOSED, ${PD_TRIE_N} requests): ${PD_TRIE_FAM}=${ta_v} (want EXACTLY 0) ; tier2 Δ$(( ta_t2_a - ta_t2_b )) ; codes=${ta_codes}"
[[ "${ta_200}" -eq "${PD_TRIE_N}" ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} A did not get ${PD_TRIE_N}x200 (codes=${ta_codes});"; }
[[ "${ta_v}" -eq 0 ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} the gauge reads ${ta_v} with pd_cache_aware_mode OFF — the trie exists without its gate;"; }
# Non-vacuous: the requests really were routed, so the flat gauge is the gate's
# doing and not an absence of traffic.
[[ $(( ta_t2_a - ta_t2_b )) -ge "${PD_TRIE_N}" ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} A drove no Tier-2 selections (Δ$(( ta_t2_a - ta_t2_b ))), so the zero gauge proves nothing;"; }

# ---- B: open the gate, drive NOTHING — isolate the CONFIG-time writer -----
tb_code=$(pd_trie_post true)
sleep ${PD_TRIE_SETTLE}
tb_v=$(metric_val "${PD_TRIE_FAM}")
echo "  B gate OPENED, NO traffic: POST -> HTTP ${tb_code} ; ${PD_TRIE_FAM}=${tb_v} (want EXACTLY 1 — the root created at rule add)"
[[ "${tb_code}" =~ ^2 ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} the gate-open POST answered HTTP ${tb_code};"; }
[[ "${tb_v}" -eq 1 ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} with the gate open and NO traffic the gauge reads ${tb_v}, not 1 — the config-time contribution is not one root, so the drive arithmetic below cannot be attributed;"; }

# ---- C: drive three distinct-first-byte keys -> EXACTLY 1+3 = 4 -----------
tc_t1_b=$(pd_tier_sel tier1); tc_t2_b=$(pd_tier_sel tier2)
pd_trie_drive "${pd_trie_cf}"
sleep ${PD_TRIE_SETTLE}
tc_v=$(metric_val "${PD_TRIE_FAM}")
tc_t1_a=$(pd_tier_sel tier1); tc_t2_a=$(pd_tier_sel tier2)
tc_codes="$(tr '\n' ' ' < "${pd_trie_cf}")"; tc_200=$(grep -cx '200' "${pd_trie_cf}" || true)
d_t1=$(( tc_t1_a - tc_t1_b )); d_t2=$(( tc_t2_a - tc_t2_b ))
echo "  C drive (${PD_TRIE_N} distinct first bytes): ${PD_TRIE_FAM}=${tc_v} (want EXACTLY $(( 1 + PD_TRIE_N ))) ; tier1 Δ${d_t1} ; tier2 Δ${d_t2} ; codes=${tc_codes}"
[[ "${tc_200}" -eq "${PD_TRIE_N}" ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} C did not get ${PD_TRIE_N}x200 (codes=${tc_codes});"; }
[[ "${tc_v}" -eq $(( 1 + PD_TRIE_N )) ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} ${PD_TRIE_N} distinct-first-byte keys took the trie to ${tc_v}, not $(( 1 + PD_TRIE_N )) — a radix insert off the root adds exactly one node per key;"; }
# Attribution by an INDEPENDENT family: every insert belongs to the Tier-2 site.
[[ "${d_t2}" -ge "${PD_TRIE_N}" ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} tier2 moved Δ${d_t2} for ${PD_TRIE_N} requests — the drive did not reach the Tier-2 insert site;"; }
[[ "${d_t1}" -eq 0 ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} tier1 moved Δ${d_t1} — the Tier-1 insert site also ran, so the node count is not attributable to Tier 2 alone;"; }

# ---- D: close the gate -> EXACTLY 0, and the service still serves ---------
# This is what rules out "the rule re-add produced the rise": the same re-POST
# with the gate closed must take it back to zero, not leave a residue.
td_code=$(pd_trie_post false)
sleep ${PD_TRIE_SETTLE}
td_v=$(metric_val "${PD_TRIE_FAM}")
pd_trie_drive "${pd_trie_cf}"
td_codes="$(tr '\n' ' ' < "${pd_trie_cf}")"; td_200=$(grep -cx '200' "${pd_trie_cf}" || true)
echo "  D gate CLOSED again: POST -> HTTP ${td_code} ; ${PD_TRIE_FAM}=${td_v} (want EXACTLY 0) ; post-restore codes=${td_codes}"
[[ "${td_code}" =~ ^2 ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} the gate-close POST answered HTTP ${td_code};"; }
[[ "${td_v}" -eq 0 ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} closing the gate left the gauge at ${td_v}, not 0 — the trie outlived its gate;"; }
[[ "${td_200}" -eq "${PD_TRIE_N}" ]] || { pd_trie_ok=0; pd_trie_note="${pd_trie_note} the service did not serve after the rule was restored (codes=${td_codes}) — this stage must hand the next one a working rule;"; }

rm -f "${pd_trie_cf}" 2>/dev/null || true
[[ -n "${pd_trie_note}" ]] && echo "  detail:${pd_trie_note}"
assert "P/D trie gauge: gated off it is 0, opening it alone gives exactly the root, three distinct keys give exactly root+3 via the Tier-2 site, and closing it returns to 0" "$pd_trie_ok"

#################################################################################
# P/D same-endpoint connect retry — a refused connect that SUCCEEDS on retry
#
#     loxilb_pd_connect_retry_same_ep_ok_total is the SUCCESS half of a pair.
#     Its sibling counts ATTEMPTS, and a control in which nothing happened
#     cannot tell the two apart, so the control here is the BRANCH ITSELF: with
#     the endpoints simply refusing, the retry loop still runs and the attempt
#     counter still moves, and only the success half is declined.
#
#     The gate (sockproxy_ep.c:1053-1070) is ep_cfd < 0 && rt_budget > 0 && the
#     retry's own connect() >= 0 -- the initial connect failed, the rule is
#     affinity-bearing (budget 1 for P/D disagg or KV-exact, 0 for plain LB),
#     and the SAME endpoint accepted the second time. Nothing in it reads an
#     engine. What it needs is a connect that FAILS and then SUCCEEDS on one
#     endpoint, and because the retry is in-process and immediate the fault
#     cannot be time-based: it has to act at the TCP handshake and be
#     COUNT-based. An nth-parity REJECT --reject-with tcp-reset on every second
#     SYN does exactly that -- the initial connect takes ECONNREFUSED and the
#     retry lands on the very next SYN and connects.
#
#     🚨 THE PARITY IS ARMED PER REQUEST, AND THAT IS THE WHOLE STAGE. The stub
#     port is NOT private to the data connect: the gateway's own vLLM /metrics
#     scraper (pkg/aimetrics.Poller, started per-rule under pdDisaggMode) dials
#     the endpoint's service port every 10s and the REDIRECT carries it to the
#     same stub port, where it is indistinguishable from a data connect at SYN
#     time. A rule left armed across a whole burst counts both in ONE sequence.
#     That is not hypothetical: the lab arm this stage is ported from did it,
#     its rule counter reported EXACTLY the predicted resets -- one per flapped
#     endpoint -- and every reset it had counted was a scrape while the data
#     connects took the accepting slot and succeeded first time. A WORKING
#     family was reported dead by a drive-shape oracle that said CONFIRMED.
#
#     So each request gets its own freshly armed window, and the window states
#     its own shape. A fall-through witness chain sits BEHIND the REJECT, so
#     refused+accepted is the total the port saw and a clean window is exactly
#     one refused and one accepted. Anything else discards the window and
#     re-drives rather than scoring it.
#
#     🚨 STAGE ORDER IS LOAD-BEARING. The refusing control runs LAST. Three
#     requests against three prefill endpoints is exactly the circuit breaker's
#     trip threshold, so running it first meets the drive with "no healthy
#     prefill candidates": selection fails before any connect is attempted and
#     the counter reads a flat zero that looks exactly like "this family cannot
#     be driven".
#
#     Placed before the collision pre-clean below, which destroys this
#     scenario's topology.
#################################################################################
echo "=== P/D connect retry: a refused connect that succeeds on the SAME endpoint ==="

PD_RETRY_N=3
PD_PREFILL_NS="l3ep1 l3ep3 l3ep5"
# 🚨 These three families are written by the POLLED collector that copies the C
# proxy_get_metrics() snapshot once per PrometheusDefaultPeriod (10s) — NOT by a
# direct callback. A 3s wait reads a live writer as DEAD, and in the flat
# assertions below that reads as "the product is correct" for the wrong reason.
# One full period plus margin, every time a delta is scored.
PD_RETRY_SETTLE=14
PD_STUB_PORT="${STUB_PORT:-8099}"
PD_RETRY_TAG="[PD_CONN_RETRY]"
PD_RETRY_ATT_LINE="transient backend connect failure, retrying SAME EP"
PD_RETRY_OK_LINE="affinity preserved"
PD_NOPOOL_LINE="no healthy prefill candidates"

# The REJECT counts the REFUSED SYNs. The witness is an EMPTY user chain, so a
# SYN that reaches it falls through and continues -- it counts the ACCEPTED
# ones. Order matters: REJECT first, witness second, so the two never
# double-count and their sum is the total the port saw.
PD_FLAP_RULE="-p tcp --dport ${PD_STUB_PORT} --syn -m statistic --mode nth --every 2 --packet 0 -m comment --comment wp11flap -j REJECT --reject-with tcp-reset"
PD_FLAP_WITNESS="-p tcp --dport ${PD_STUB_PORT} --syn -m comment --comment wp11all -j WP11CNT"

pd_ipt() { sudo ip netns exec "$1" iptables ${@:2} >/dev/null 2>&1; }

pd_flap_disarm() {   # idempotent, and it PROVES the REJECT is gone
    local ns rc=0
    for ns in ${PD_PREFILL_NS}; do
        while pd_ipt "$ns" -C INPUT ${PD_FLAP_RULE};    do pd_ipt "$ns" -D INPUT ${PD_FLAP_RULE}    || break; done
        while pd_ipt "$ns" -C INPUT ${PD_FLAP_WITNESS}; do pd_ipt "$ns" -D INPUT ${PD_FLAP_WITNESS} || break; done
        # A leftover REJECT would refuse half of every LATER connect, and
        # nothing about it looks like a fault.
        pd_ipt "$ns" -C INPUT ${PD_FLAP_RULE} && rc=1
    done
    return $rc
}

pd_flap_arm() {      # FRESH rules: both counters start at zero by construction
    local ns
    pd_flap_disarm || return 1
    for ns in ${PD_PREFILL_NS}; do
        pd_ipt "$ns" -N WP11CNT                          # exists after the first
        pd_ipt "$ns" -I INPUT 1 ${PD_FLAP_WITNESS} || return 1
        pd_ipt "$ns" -I INPUT 1 ${PD_FLAP_RULE}    || return 1
    done
    return 0
}

# pd_flap_counts -> "<refused> <accepted> <pairs>"; pairs must equal the number
# of prefill netns or a rule is missing and the measurement is not one.
pd_flap_counts() {
    local ns out r=0 a=0 pairs=0 hasr hasa
    for ns in ${PD_PREFILL_NS}; do
        out=$(sudo ip netns exec "$ns" iptables -L INPUT -v -n -x 2>/dev/null)
        hasr=$(echo "$out" | grep -c "wp11flap" || true)
        hasa=$(echo "$out" | grep -c "wp11all"  || true)
        [[ "$hasr" -ge 1 && "$hasa" -ge 1 ]] && pairs=$(( pairs + 1 ))
        r=$(( r + $(echo "$out" | awk '/wp11flap/ {s+=$1} END {print s+0}') ))
        a=$(( a + $(echo "$out" | awk '/wp11all/  {s+=$1} END {print s+0}') ))
    done
    echo "$r $a $pairs"
}

# Both [PD_CONN_RETRY] lines carry the same tag and they are the only two the
# block emits, so loose must equal attempts + oks. The two are close enough to
# collide by eye -- "to preserve affinity" vs "affinity preserved" -- which is
# exactly the shape that has produced false readings before, so the sum is
# asserted rather than the discriminator trusted.
pd_retry_counts() { echo "$(dplog_count "${PD_RETRY_TAG}") $(dplog_count "${PD_RETRY_ATT_LINE}") $(dplog_count "${PD_RETRY_OK_LINE}")"; }

pd_retry_drive() {   # one request, the scenario's own shape
    $hexec l3h1 curl -s -o /dev/null --max-time 60 -w '%{http_code}\n' \
        -H 'Content-Type: application/json' \
        -d "{\"model\":\"${KV_MODEL}\",\"prompt\":\"pd connect-retry probe $1\",\"max_tokens\":8}" \
        "http://${VIP}:${VPORT}/v1/completions" 2>/dev/null
}

pd_retry_ok=1
pd_retry_note=""
PD_RETRY_OK_FAM="loxilb_pd_connect_retry_same_ep_ok_total"
PD_RETRY_FAM="loxilb_pd_connect_retry_same_ep_total"
PD_FAILOVER_FAM="loxilb_pd_connect_failover_total"

if [[ ! -x "${PD_SWAP}" ]]; then
    pd_retry_ok=0; pd_retry_note="missing ${PD_SWAP}"
else
    # ---- A control: every connect succeeds first time ---------------------
    for ns in ${PD_PREFILL_NS}; do sudo ${PD_SWAP} "${ns}" ok >/dev/null || pd_retry_ok=0; done
    pd_flap_disarm || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} a flap REJECT survived pre-clean;"; }
    sleep 2
    a_ok_b=$(metric_val "${PD_RETRY_OK_FAM}"); read a_l_b a_a_b a_o_b <<<"$(pd_retry_counts)"
    for i in $(seq 1 ${PD_RETRY_N}); do pd_retry_drive "a$i" >/dev/null; done
    sleep ${PD_RETRY_SETTLE}
    a_ok_a=$(metric_val "${PD_RETRY_OK_FAM}"); read a_l_a a_a_a a_o_a <<<"$(pd_retry_counts)"
    echo "  A control-healthy: ${PD_RETRY_OK_FAM} ${a_ok_b}->${a_ok_a} ; attempt lines Δ$(( a_a_a - a_a_b )) ; ok lines Δ$(( a_o_a - a_o_b ))"
    [[ "${a_ok_a}" == "${a_ok_b}" ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} A moved the success counter with no fault;"; }
    [[ $(( a_a_a - a_a_b )) -eq 0 && $(( a_o_a - a_o_b )) -eq 0 ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} A entered the retry block at all;"; }

    # ---- B drive: one request per freshly armed parity window -------------
    # 🚨 A DISCARDED WINDOW STILL DROVE A REAL REQUEST, AND ITS COUNTER
    # MOVEMENT IS REAL. The discard removes the window from the drive-shape
    # accounting (refused_tot/accepted_tot) but it cannot remove it from the
    # metric, which was already incremented: a window that read (3,1) had its
    # request refused and then rescued by the retry exactly like a clean one.
    # With ONE baseline taken outside the loop, the delta therefore counts
    # clean windows PLUS discarded ones, so a single discard makes the family
    # read Δ4 for 3 scored windows and the stage fails as though the product
    # over-counted. It does not: the counter and its log line agreed at 4, and
    # 4 requests really were driven. Two oracles, and only one of them was
    # taught about discards.
    #
    # The sound fix is to make the baseline describe exactly the windows that
    # get scored, so the whole B phase is re-driven from a FRESH baseline
    # whenever it contained a discard. Re-baselining works only because the
    # settle below is a full collector period: the polluted movement is banked
    # before the next round reads its baseline. The assertions are unchanged.
    pdr_round_clean=0
    for pdr_round in 1 2 3; do
    b_ok_b=$(metric_val "${PD_RETRY_OK_FAM}"); b_rt_b=$(metric_val "${PD_RETRY_FAM}")
    b_fo_b=$(metric_val "${PD_FAILOVER_FAM}"); b_np_b=$(dplog_count "${PD_NOPOOL_LINE}")
    read b_l_b b_a_b b_o_b <<<"$(pd_retry_counts)"
    refused_tot=0; accepted_tot=0; discarded=0; b_codes=""
    # 🚨 Locals are PREFIXED. `code` is this scenario's global exit accumulator
    # and the drive returns an HTTP status, so an unprefixed `code=$(...)` here
    # put 200 into the script's exit status: every assertion passed and the
    # scenario still reported FAILED with rc=200. A stage that cannot be
    # trusted to leave the harness alone is not a stage.
    for pdr_i in $(seq 1 ${PD_RETRY_N}); do
        pdr_got=0
        for pdr_try in 1 2 3 4 5 6 7 8; do
            pd_flap_arm || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} could not arm the parity;"; break; }
            pdr_code=$(pd_retry_drive "b${pdr_i}")
            read pdr_r pdr_a pdr_pairs <<<"$(pd_flap_counts)"
            pd_flap_disarm || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} a flap REJECT survived its disarm;"; }
            pdr_npre=$(echo "${PD_PREFILL_NS}" | wc -w)
            if [[ "${pdr_pairs}" != "${pdr_npre}" ]]; then
                pd_retry_ok=0; pd_retry_note="${pd_retry_note} the flap rule pair is incomplete (${pdr_pairs}/${pdr_npre});"; break
            fi
            if [[ "${pdr_r}" == "1" && "${pdr_a}" == "1" ]]; then
                refused_tot=$(( refused_tot + pdr_r )); accepted_tot=$(( accepted_tot + pdr_a ))
                b_codes="${b_codes}${pdr_code} "; pdr_got=1; break
            fi
            discarded=$(( discarded + 1 ))
            echo "    window DISCARDED: refused=${pdr_r} accepted=${pdr_a} (want 1 1) — the /metrics scraper shares this port; re-driving"
            sleep 3
        done
        [[ "${pdr_got}" == "1" ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} no clean window for request ${pdr_i};"; break; }
    done
    pd_flap_disarm || true
    sleep ${PD_RETRY_SETTLE}
        if [[ "${discarded}" -eq 0 ]]; then pdr_round_clean=1; break; fi
        echo "    round ${pdr_round} contained ${discarded} discarded window(s) — their counter movement is real and already banked; re-baselining and re-driving the whole phase"
    done
    [[ "${pdr_round_clean}" == "1" ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} no discard-free round in 3 attempts — the /metrics scraper shared the port every time;"; }
    b_ok_a=$(metric_val "${PD_RETRY_OK_FAM}"); b_rt_a=$(metric_val "${PD_RETRY_FAM}")
    b_fo_a=$(metric_val "${PD_FAILOVER_FAM}"); b_np_a=$(dplog_count "${PD_NOPOOL_LINE}")
    read b_l_a b_a_a b_o_a <<<"$(pd_retry_counts)"
    d_ok=$(( b_ok_a - b_ok_b )); d_rt=$(( b_rt_a - b_rt_b )); d_fo=$(( b_fo_a - b_fo_b ))
    d_okline=$(( b_o_a - b_o_b ))
    n_b_codes=$(echo ${b_codes} | wc -w)
    echo "  B drive shape: refused=${refused_tot} accepted=${accepted_tot} (want ${PD_RETRY_N} each) ; discarded windows=${discarded}"
    echo "  B: ${PD_RETRY_OK_FAM} Δ${d_ok} ; ${PD_RETRY_FAM} Δ${d_rt} ; ${PD_FAILOVER_FAM} Δ${d_fo} ; ok lines Δ${d_okline} ; codes=${b_codes}"
    # The pool must have been healthy, or every delta measures an open breaker
    # rather than the retry block.
    [[ $(( b_np_a - b_np_b )) -eq 0 ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} selection failed before any connect (Δ'${PD_NOPOOL_LINE}'=$(( b_np_a - b_np_b )));"; }
    [[ "${refused_tot}" == "${PD_RETRY_N}" && "${accepted_tot}" == "${PD_RETRY_N}" ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} drive shape refused=${refused_tot} accepted=${accepted_tot};"; }
    # An empty %{http_code} is a FAILED SPAWN, never a gateway answer.
    [[ "${n_b_codes}" == "${PD_RETRY_N}" ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} lost a measurement (${n_b_codes}/${PD_RETRY_N} codes);"; }
    [[ "${b_codes// /}" == "$(printf '200%.0s' $(seq 1 ${PD_RETRY_N}))" ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} the retry did not rescue the request (codes=${b_codes});"; }
    [[ "${d_ok}" == "${PD_RETRY_N}" ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} ${PD_RETRY_OK_FAM} Δ${d_ok};"; }
    # Same statement as the counter, so an inequality means one oracle lies.
    [[ "${d_ok}" == "${d_okline}" ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} counter Δ${d_ok} != ok-lines Δ${d_okline};"; }
    [[ "${d_rt}" == "${PD_RETRY_N}" ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} ${PD_RETRY_FAM} Δ${d_rt};"; }
    # A move here would mean a DIFFERENT endpoint rescued the request, which is
    # the outcome this family exists to be distinguished from.
    [[ "${d_fo}" == "0" ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} failover Δ${d_fo} — affinity was NOT preserved;"; }
    [[ $(( b_l_a - b_l_b )) -eq $(( ( b_a_a - b_a_b ) + d_okline )) ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} the [PD_CONN_RETRY] discriminator does not account for its own lines;"; }

    # ---- C control: every connect refuses. LAST: it trips the breakers ----
    for ns in ${PD_PREFILL_NS}; do sudo ${PD_SWAP} "${ns}" refuse >/dev/null || pd_retry_ok=0; done
    sleep 2
    c_ok_b=$(metric_val "${PD_RETRY_OK_FAM}"); c_rt_b=$(metric_val "${PD_RETRY_FAM}")
    read c_l_b c_a_b c_o_b <<<"$(pd_retry_counts)"
    c_codes=""
    for i in $(seq 1 ${PD_RETRY_N}); do c_codes="${c_codes}$(pd_retry_drive "c$i") "; done
    sleep ${PD_RETRY_SETTLE}
    c_ok_a=$(metric_val "${PD_RETRY_OK_FAM}"); c_rt_a=$(metric_val "${PD_RETRY_FAM}")
    read c_l_a c_a_a c_o_a <<<"$(pd_retry_counts)"
    echo "  C control-refusing: ${PD_RETRY_OK_FAM} Δ$(( c_ok_a - c_ok_b )) (want 0) ; ${PD_RETRY_FAM} Δ$(( c_rt_a - c_rt_b )) (want ${PD_RETRY_N}) ; attempt lines Δ$(( c_a_a - c_a_b )) ; ok lines Δ$(( c_o_a - c_o_b )) ; codes=${c_codes}"
    [[ $(( c_ok_a - c_ok_b )) -eq 0 ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} C moved the SUCCESS counter while every connect failed — it counts attempts;"; }
    # Non-vacuous: the same branch that holds the increment under test was
    # entered and then declined. A zero here would mean the flow never reached
    # the retry block and the flat counter above would prove nothing.
    [[ $(( c_rt_a - c_rt_b )) -eq ${PD_RETRY_N} && $(( c_a_a - c_a_b )) -eq ${PD_RETRY_N} ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} C never entered the retry block, so its flat success counter proves nothing;"; }
    [[ $(( c_o_a - c_o_b )) -eq 0 ]] || { pd_retry_ok=0; pd_retry_note="${pd_retry_note} C logged a success line;"; }

    # ---- restore ----------------------------------------------------------
    pd_flap_disarm || true
    for ns in ${PD_PREFILL_NS}; do sudo ${PD_SWAP} "${ns}" off >/dev/null || true; done
fi
[[ -n "${pd_retry_note}" ]] && echo "  detail:${pd_retry_note}"
assert "P/D connect retry: a refused connect succeeds on the SAME endpoint and is counted as a SUCCESS" "$pd_retry_ok"

#################################################################################
# backward-compat — re-run cicd/vllm-pd-disagg byte-for-byte AFTER the collision pre-clean
#     this scenario AND vllm-pd-disagg both name backends l3ep1/l3ep2. This stage re-enters the
#     sibling vllm-pd-disagg harness on the SAME runner; without a docker rm -f + netns/network prune
#     first the python3 apt-install execs into the wrong (alpine reflect-echo, no-apt) image and aborts
#     Require SCENARIO-vllm-pd-disagg [PASS] byte-for-byte.
#     DELIBERATELY THE LAST STAGE: the collision pre-clean DESTROYS this scenario's topology, so every
#     KV-rule-dependent assert (the overlap scenarios, the counter/liveness checks, the exit gate) must already have run.
#################################################################################
echo "=== backward-compat: vllm-pd-disagg byte-for-byte re-run [PASS] after l3ep1/l3ep2 collision pre-clean ==="
AI_SCENARIO_DIR="../vllm-pd-disagg"
AI_RUNNER="${AI_SCENARIO_DIR}/run-pd-cicd.sh"
fr8_ok=0
if [[ -d "${AI_SCENARIO_DIR}" && -x "${AI_RUNNER}" ]]; then
    echo "  AI regression scenario present; pre-cleaning the l3ep1/l3ep2 collision set then re-running..."
    # Collision pre-clean FIRST: tear down THIS scenario's containers + any stale netns/networks
    # so vllm-pd-disagg stands up its OWN ubuntu `host` backends (apt-able) cleanly.
    docker rm -f llb1 llb2 l3h1 l3ep1 l3ep2 l3ep3 l3ep4 l3ep5 l3ep6 r1 ka_llb1 ka_llb2 >/dev/null 2>&1 || true
    sudo ip -all netns delete >/dev/null 2>&1 || true
    docker network prune -f >/dev/null 2>&1 || true
    g_out=$(cd "${AI_SCENARIO_DIR}" && ./run-pd-cicd.sh 2>&1)
    echo "$g_out" | tail -15
    echo "$g_out" | grep -qiE 'SCENARIO-vllm-pd-disagg \[PASS\]' && fr8_ok=1
else
    echo "  AI regression scenario MISSING or non-executable: ${AI_RUNNER}"
fi
assert "backward-compat: vllm-pd-disagg byte-for-byte [PASS] (collision pre-cleaned)" "$fr8_ok"

#################################################################################
# Result + scoped cleanup
#################################################################################
if [[ $code == 0 ]]; then
    echo "=== SCENARIO-vllm-kvcache-routing-cpu [OK] ==="
else
    echo "=== SCENARIO-vllm-kvcache-routing-cpu [FAILED] ==="
fi
# Scoped teardown: kill ONLY this suite's publisher PIDs by its anchored tag. NEVER a
# host-wide process-name killall — that reaps unrelated PIDs across the runner. Containers torn down by rmconfig.sh.
kill_publisher
rm -f "${CFGDIR}"/.kvpub-*.json >/dev/null 2>&1 || true
exit $code
