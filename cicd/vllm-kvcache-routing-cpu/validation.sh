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
#   check 8  vllm-pd-disagg byte-for-byte re-run [PASS] AFTER the l3ep1/l3ep2 collision pre-clean.
#
# Metric source-of-truth (api/prometheus/sockproxy_metrics.go):
#   loxilb_pd_kv_tier15_hits_total{ep_idx}        loxilb_pd_kv_tier15_miss_reason_total{reason}
#   loxilb_pd_kv_tier15_fallthrough_total         loxilb_kv_subscriber_connected{service,ep}
#   loxilb_kv_subscriber_reconnect_total{...}     loxilb_kv_subscriber_recv_error_total{...}
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
PARITY="${CFGDIR}/../vllm-loxilb-kvcache-aws-small/kv_hash_parity.py"
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
#       5a/5b/5c FAIL pre-D-LC2 (selector tokenized RAW escaped bytes -> zero
#                block parity -> silent Tier-2 RR on every code prompt);
#       5a-resp FAILS pre-D-LC5 (a >=64KB response overflowed the 64KB PREFILL
#                response buffer -> completion check could never fire -> the flow
#                sat in PREFILL_WAITING forever; client got NOTHING, http=000.
#                Live-proven threshold: resp<=32KB fine, >=64KB total wedge);
#       5d      FAILS pre-D-LC3 (>1MB JSON hit the 95% rcvbuf guard -> the
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

# ── (cap/eviction) drive an EP over the lowered LOXILB_KV_MAX_BLOCKS → counter>0 AND Size==cap ─────────
#    config.sh injected LOXILB_KV_MAX_BLOCKS=${KV_MAX_BLOCKS} into llb1. Flood ONE prefill EP with far
#    more distinct blocks than the cap (a synthetic many-prompt corpus — distinct CONTENT, not seq) so
#    its inventory overflows: loxilb_kv_inv_cap_evictions_total must move (> its pre-flood value) AND the
#    EP's KVINV Size must PIN at the cap (FIFO eviction holds the bound — end-to-end). The
#    eviction is ALSO observable in the log via the structured cap-hit marker (structured-marker-anchored, not a bare
#    word). The flood publishes to EP-B so it does not perturb the EP-A/EP-C state the legs above used.
echo "=== (cap/eviction) overflow the lowered cap (${KV_MAX_BLOCKS}) -> evictions_total>0 AND KVINV Size==cap ==="
cap_evict_before="$(metric_val "loxilb_kv_inv_cap_evictions_total")"
# Observability of cap-hits is the prometheus counter loxilb_kv_inv_cap_evictions_total (the
# authoritative "publisher misbehaving" signal) + the pinned inventory Size — NOT a log grep: the Go
# subscriber logs via logrus to stderr, which loxilb's `docker exec -dt` launch discards (the file
# /var/log/loxilb*.log is the loxilib tk-logger only). So this leg asserts on metric + Size (the
# log-grep self-satisfy concern is moot — there is no log grep to self-satisfy).
# Block hashes are CONTENT-derived, NOT seq-derived: re-publishing one corpus at different --seq-base
# yields IDENTICAL hashes and never grows the inventory (the prior 4-pass loop produced only ~4 blocks).
# Generate a SYNTHETIC corpus of many DISTINCT prompts (each ~32 blocks) so a single resident publisher
# emits > KV_MAX_BLOCKS distinct blocks in ONE monotonic seq run (no per-publish reconnect/resync churn).
# 60 prompts * ~32 blocks ~= 1900 distinct blocks >> the 1000 cap -> FIFO eviction pins Size at the cap.
CAP_FLOOD_CORPUS="${CFGDIR}/.kvpub-cap-flood.json"
# The publisher consumes a FLAT LIST [{"prompt":..}], NOT {"prompts":[..]} (same shape config.sh's
# baseline + publish_prompt_to_ep write). A {"prompts":[..]} object makes it read 0 prompts (silent).
python3 -c "import json,sys
json.dump([{'prompt':('cap flood distinct filler block number %03d '%i)*48} for i in range(60)],
  open(sys.argv[1],'w'))" "${CAP_FLOOD_CORPUS}" 2>/dev/null
for _pp in $(pgrep -f "${PUB_TAG}" 2>/dev/null); do kill "${_pp}" >/dev/null 2>&1 || true; done
sleep 1
# One RESIDENT publisher (--repeat 6 keeps it bound ~30s so the subscriber redials after the pre-kill
# and ingests a full pass — a one-shot pass exits before the redial window and is missed). The large
# seq-base (9000 >> EP-B's lastSeq) makes the first post-reconnect message a CLEAR, so Size reflects
# ONLY this flood set; --no-vocabulary keeps the trailing AllBlocksCleared from wiping it afterward.
CAP_FLOOD_LOG="${CFGDIR}/.kvpub-cap-flood.log"
setsid $hexec "$(netns_for_ep_ip "${EP_B_IP}")" bash -c "export PYTHONPATH='${PY_USER_SITE}' PYTHONHASHSEED=0; exec -a ${PUB_TAG} python3 '${PUBLISHER}' \
    --corpus '${CAP_FLOOD_CORPUS}' --tokenizer '${TOKENIZER_SRC}' --vectors '${VECTORS_SRC}' \
    --bind '${EP_B_IP}' --port ${KV_ZMQ_PORT} --algo ${KV_HASH_ALGO} \
    --block-size ${KV_BLOCK_SIZE} --seq-base 9000 --repeat 6 --repeat-interval 5 --no-vocabulary" >"${CAP_FLOOD_LOG}" 2>&1 &
sleep 14   # let the subscriber connect, ingest the >1000-block flood, and run the cap-eviction loop
cap_evict_after="${cap_evict_before}"
for _ in $(seq 1 15); do
    cap_evict_after="$(metric_val "loxilb_kv_inv_cap_evictions_total")"
    [[ "${cap_evict_after}" -gt "${cap_evict_before}" ]] && break
    sleep 1
done
cap_size="$(inv_total "${EP_B_IDX}")"
cap_counter_moved=$([[ "${cap_evict_after}" -gt "${cap_evict_before}" ]] && echo 1 || echo 0)
# Size must PIN exactly at the cap (FIFO holds the bound at KV_MAX_BLOCKS, not merely <=).
cap_size_pinned=$([[ "${cap_size}" -eq "${KV_MAX_BLOCKS}" ]] && echo 1 || echo 0)
echo "  cap=${KV_MAX_BLOCKS} ; evictions_total ${cap_evict_before}->${cap_evict_after} (want delta) ; KVINV Size=${cap_size} (want ==cap, pinned)"
cap_ok=$([[ "${cap_counter_moved}" == 1 && "${cap_size_pinned}" == 1 ]] && echo 1 || echo 0)
assert "(cap) overflow drives loxilb_kv_inv_cap_evictions_total>0 AND KVINV Size pinned at the cap" "$cap_ok"

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
