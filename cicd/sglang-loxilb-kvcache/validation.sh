#!/bin/bash
# validation.sh — two-VIP multi-framework KV-routing coexistence exit gate.
#
# Asserts coexistence both ways + engine-mix rejection, plus the mock halves of the
# Tier-1.5-hit, EP-restart-clears, and multi-rank-union behaviours, against ONE live loxilb
# carrying VIP-A (vLLM P/D mock, kvExactMode=1) and VIP-B (SGLang single-role mock, kvExactMode=3,
# kvEngineType=sglang, kvDpRankCount=3) — seeded by config.sh. Every functional assert is
# HARD/FATAL under SKELETON_STRICT=1; only inherently non-deterministic timing sub-checks soft().
# A single SCENARIO-sglang-loxilb-kvcache [OK] sentinel governs the run.
#
# Assertion map (each leg self-confirms its stimulus FIRED before asserting):
#   L0  PUBLISHER-FIDELITY — kv_event_publisher --self-check for BOTH the vLLM cbor vectors AND
#       the SGLang golden vectors (the sglang_hash_core import chain proven before any leg).
#   L1  INVENTORY-GROWS / MULTI-RANK UNION — a 3-rank publish to the VIRGIN VIP-B EP (idx 2)
#       converges the shared per-EP inventory to EXACTLY blocks_total (sum of per-rank distinct
#       blocks) and STRICTLY exceeds any single rank's contribution (union check).
#   L2  TIER15-HIT BOTH VIPS — corpus-matching request per VIP; tier15_hits{right ep_idx} delta
#       >= 1 on BOTH (A at idx 0 dual-proofed with the P/D serverD* banner; B at idx 1
#       dual-proofed with the single-role serverS1 banner).
#   L3  ISOLATION BOTH WAYS — VIP-A tier15/inventory deltas == 0 while VIP-B takes traffic +
#       rule delete/re-add; then mirrored (VIP-B stable while VIP-A churns).
#   L4  SAME-MODEL NEGATIVE CONTROL — same-model content planted as SGLANG hashes inside
#       VIP-A's inventory; a VIP-B request for it must tier15-hit NOWHERE (sum delta == 0).
#       FAILS WITHOUT THE SVC-ID FILTER — do not weaken (see leg comment).
#   L5  ENGINE-IMMUTABLE — re-POST of VIP-B with kvEngineType=vllm is REJECTED with the exact
#       engine-mix message; the rule still routes afterwards.
#   L6  EP-RESTART-CLEARS + SEQ-GAP — publisher kill/high-seq restart drives the
#       structured `resync CLEAR` marker + inventory drop-then-regrow; a live-stream >window
#       jump drives `decision=CLEAR`; a small jump on rank 1 drives `decision=KEEP` with ZERO
#       spurious clears on OTHER EPs (rank-interleave teeth).
#   L7  ZERO-HIT WATCHDOG — a throwaway third rule with a DELIBERATELY wrong kvBlockSize
#       fires [KV_ZEROHIT] exactly once + loxilb_pd_kv_zero_hit_watchdog_total{service_id}
#       delta > 0 within ~8 lookups (LOXILB_KV_ZERO_HIT_N=5 injected by config.sh); rule deleted.
#   L8  COLD-START SEED — a throwaway fourth rule (correct kvBlockSize) with ONE publishing
#       EP: 20 hit-requests must divert exactly the 16th (default LOXILB_KV_COLDSTART_SEED_N)
#       to the LOWEST empty-inventory EP — [KV_COLDSEED] marker +
#       loxilb_pd_kv_tier15_cold_seeds_total{ep_idx} + the cold EP's banner; rule deleted.
#
# Metric source-of-truth (api/prometheus/sockproxy_metrics.go):
#   loxilb_pd_kv_tier15_hits_total{ep_idx}                (NO service label — see ep_idx note)
#   loxilb_pd_kv_zero_hit_watchdog_total{service_id}      (Go-side, instant)
#   loxilb_kv_subscriber_connected{service,ep} / loxilb_kv_subscriber_reconnect_total{...}
# Inventory (SERVICE-SCOPED — the per-service isolation surface):
#   GET /netlox/v1/config/ai/kv/inventory?service_id=<id>&ep_idx=<idx>
#
# ep_idx ATTRIBUTION NOTE: tier15_hits carries no service label, so the legs steer hits to
# NUMERICALLY DISJOINT indices — VIP-A can only ever hit idx 0/2 (prefills; decode EPs are never
# Tier-1.5 candidates), VIP-B legs target idx 1. Cross-index movement == contamination.
#
# STRUCTURED-MARKER LOG SURFACE (NO bare-event-name greps anywhere): all log
# assertions anchor on the exact logrus markers, read from /var/log/loxilb-go.log
# inside llb1 (config.sh restarted loxilb with stderr captured there — `docker exec -dt`
# discards logrus stderr):
#   kv-subscriber: ep N rank R resync CLEAR — first post-reconnect seq=... (reconnect restart)
#   kv-subscriber: ep N rank R seq gap A -> B (missing G, no replay) decision=KEEP|CLEAR
#   kv-subscriber: AllBlocksCleared received for ep N (rank R) — clearing shared inventory
#   [KV_ZEROHIT] service N: ...
# The `ep <digits> rank <digits>` / `service <digits>` field anchors are what no prompt text can
# reproduce. `grep -c` prints 0 AND exits 1 on zero matches — every counter helper captures the
# count itself, never `|| echo 0` (which would mask a real zero as a match).
#
# REST hits localhost:11111 (auth-off, CICD mode) and MUST run in the llb1 netns; routing
# requests are driven from l3h1. NO SSH/password content — the scenario is self-contained and
# runs where it is deployed (a FAIL here is guilty until proven innocent).
#
# Run on the remote testbed. macOS validates `bash -n` + `shellcheck -S error` only.
# Exit: prints SCENARIO-sglang-loxilb-kvcache [OK]/[FAILED]; exits non-zero on any HARD failure.

source ../common.sh

echo SCENARIO-sglang-loxilb-kvcache

# ── parameters (mirror config.sh) ──────────────────────────────────────────────────────────
CFGDIR="$(cd "$(dirname "$0")" && pwd)"
VIP="10.10.10.254"
VPORT_A=8080
VPORT_B=9090
VPORT_C=9091                       # L7 throwaway zero-hit rule
LBBASE="http://localhost:11111/netlox/v1/config/loadbalancer"
METRICS="http://localhost:11111/netlox/v1/metrics"
KVINV="http://localhost:11111/netlox/v1/config/ai/kv/inventory"
KV_ZMQ_PORT_A=5557
KV_ZMQ_PORT_B=5561
KV_ZMQ_PORT_C=5571                 # L7 publisher port (distinct from B's rank ports)
KV_HASH_ALGO_A="sha256_cbor"
KV_DP_RANKS=3
KV_WARMUP_SEC=20
KV_BLOCK_SIZE=16
KV_BLOCK_SIZE_WRONG=32             # L7: deliberate mismatch vs the publisher page size (16)
GO_LOG="/var/log/loxilb-go.log"    # config.sh's logrus-capture surface inside llb1
KV_MODEL="${KV_MODEL:-Qwen/Qwen3-0.6B}"
KV_MODEL_SLUG="${KV_MODEL//\//__}"
TOKENIZER_SRC="${CFGDIR}/../common/kv_hash/fixtures/tokenizers/${KV_MODEL_SLUG}/tokenizer.json"
VECTORS_SRC="${CFGDIR}/../common/kv_hash/fixtures/kv_hash_vectors.json"
PUBLISHER="${CFGDIR}/../vllm-kvcache-routing-cpu/kv_event_publisher.py"
PUB_TAG="${PUB_TAG:-kvpub99}"
PY_USER_SITE="$(python3 -m site --user-site 2>/dev/null || echo '')"

# EP map. VIP-A prefills: idx 0 (l3ep1) / idx 2 (l3ep3). VIP-B: idx 0/1/2 (l3ep5/6/7).
EP_A0_IP="31.31.31.1"   # VIP-A prefill idx 0 (serverP0)
EP_A2_IP="33.33.33.1"   # VIP-A prefill idx 2 (serverP1) — L4 contamination plant target
EP_B0_IP="35.35.35.1"   # VIP-B idx 0 (serverS0) — L6b/L6c + L7 publisher host
EP_B1_IP="36.36.36.1"   # VIP-B idx 1 (serverS1) — the B tier15 target (A can never hit idx 1)
EP_B2_IP="37.37.37.1"   # VIP-B idx 2 (serverS2) — VIRGIN until the L1 union publish

netns_for_ep_ip() {
    case "$1" in
        "${EP_A0_IP}") echo "l3ep1" ;;
        "${EP_A2_IP}") echo "l3ep3" ;;
        "${EP_B0_IP}") echo "l3ep5" ;;
        "${EP_B1_IP}") echo "l3ep6" ;;
        "${EP_B2_IP}") echo "l3ep7" ;;
        *) echo "" ;;
    esac
}

# ── prompts of record (fixed in ONE place; requests POST the SAME bytes the publishers hash;
#    all ASCII, JSON-escape-clean, < MAX_PREFIX_LEN 512) ────────────────────────────────────
PA_HIT="sgl99 vip a coexistence anchor prompt the vllm prefill endpoint at index zero holds this content exclusively so the tier argmax must select it alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon phi chi psi omega"
PB_HIT="sgl99 vip b single role anchor prompt the sglang endpoint at index one holds this content exclusively so the single role tier selection must route here quebec romeo sierra tango uniform victor whiskey xray yankee zulu one two three four five six seven eight nine ten eleven twelve"
NC_PROMPT="sgl99 negative control same model cross vip prompt this content is planted only inside vip a inventory as sglang hashes and never on any vip b endpoint so a correct service scoped selector must never tier hit it november oscar papa golf hotel india lima mike delta four seven"
P6A_RESTART="sgl99 restart clears short prompt one full block only kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey xray"
ZH_PROMPT="sgl99 zero hit watchdog probe prompt with a deliberately mismatched rule block size so its request side thirty two token pages can never intersect the sixteen token publisher inventory pages ankle bishop candle dagger ember falcon garnet hollow ingot jasper kettle lantern marble nickel orchid pebble quartz rocket saddle thimble umber velvet walnut xenon yonder zephyr anchor bramble cinder dapple ellipse fathom gimbal harbor icicle jonquil krypton lattice"

# SKELETON_STRICT gate (default 1 = enforcing). assert = HARD; soft = timing windows only.
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

# Scoped publisher kills: resolve PIDs by anchored tag + a discriminating cmdline anchor and
# kill EXACTLY those PIDs (never a name-wide sweep). `exec -a kvpub99` replaces
# argv[0] only, so the full cmdline still carries --bind/--port for scoping.
kill_publisher_ep() {   # <ep-ip> — all of one EP's publishers (any port)
    local pid
    for pid in $(pgrep -f "${PUB_TAG}.*--bind ${1}" 2>/dev/null); do
        kill "${pid}" >/dev/null 2>&1 || true
    done
}
kill_publisher_port() { # <port> — one port's publisher (the L7 :5571 case)
    local pid
    for pid in $(pgrep -f "${PUB_TAG}.*--port ${1}" 2>/dev/null); do
        kill "${pid}" >/dev/null 2>&1 || true
    done
}

# inv_total <service_id> <ep_idx> — inventory block count (0 if unreachable/absent).
inv_total() {
    local v
    v=$(llb_curl "${KVINV}?service_id=${1}&ep_idx=${2}" 2>/dev/null \
        | grep -Eo '"total":[0-9]+' | grep -Eo '[0-9]+' | head -1)
    echo "${v:-0}"
}

# inv_exists <service_id> <ep_idx> — 1 if the (service, ep) inventory key exists.
inv_exists() {
    llb_curl "${KVINV}?service_id=${1}&ep_idx=${2}" 2>/dev/null \
        | grep -q '"service_id"' && echo 1 || echo 0
}

# tier15_hits <ep_idx> — current loxilb_pd_kv_tier15_hits_total{ep_idx} (0 if absent).
tier15_hits() {
    llb_curl "${METRICS}" 2>/dev/null \
        | grep -E "loxilb_pd_kv_tier15_hits_total\{[^}]*ep_idx=\"$1\"" \
        | awk '{print $NF}' | tail -1 | grep -Eo '^[0-9]+' || echo 0
}

# tier15_sum — sum over ALL ep_idx lines (the "no hit anywhere" negative-control surface).
tier15_sum() {
    local v
    v=$(llb_curl "${METRICS}" 2>/dev/null | grep -E "^loxilb_pd_kv_tier15_hits_total" \
        | awk '{s+=$NF} END{printf "%d", s}')
    echo "${v:-0}"
}

# metric_val <grep-pattern> — sum the value column of matching metric lines (0 if none).
metric_val() {
    local v
    v=$(llb_curl "${METRICS}" 2>/dev/null | grep -E "$1" | awk '{s+=$NF} END{printf "%d", s}')
    echo "${v:-0}"
}

# go_log_count <ANCHORED-EXTENDED-REGEX> — count matching lines in llb1's Go-log (the logrus
# capture config.sh set up). grep -c prints its own 0 on no match — captured, never || echo 0.
go_log_count() {
    local n
    n=$(docker exec llb1 sh -c "cat ${GO_LOG} 2>/dev/null" 2>/dev/null | grep -cE "$1")
    echo "${n:-0}"
}

# req_banner <vport> <prompt-text> — POST the OpenAI /v1/completions JSON to a VIP from l3h1
# and echo the serving banner (serverP*/serverD*/serverS*). The "model" key maps to the staged
# tokenizer (slug Qwen__Qwen3-0.6B); the "prompt" bytes are EXACTLY what the publishers hashed.
req_banner() {
    local vport="$1" prompt="$2" body
    body=$(python3 -c 'import json,sys; print(json.dumps({"model": sys.argv[1], "prompt": sys.argv[2], "max_tokens": 8}))' \
        "${KV_MODEL}" "${prompt}")
    client_get -o - -w '' -X POST "http://${VIP}:${vport}/v1/completions" \
        -H 'Content-Type: application/json' --data-binary "${body}" 2>/dev/null \
        | grep -Eo 'server[PDS][0-9]' | head -1
}

# write_corpus_single <file> <prompt> — the publisher's FLAT-LIST corpus shape.
write_corpus_single() {
    python3 -c 'import json,sys; json.dump([{"prompt": sys.argv[2]}], open(sys.argv[1], "w"))' \
        "$1" "$2" 2>/dev/null
}

# launch_publisher <ep-ip> <port> <algo> <ranks> <corpus> <log> [extra publisher args...]
# Binds inside the EP's OWN netns (the EP IPs are local only there); always
# --verbose so seq-jump/PUBLISH-done lines are grep-able self-confirm surfaces; --no-vocabulary
# so a live subscriber never ingests a trailing AllBlocksCleared that wipes the seeded set.
launch_publisher() {
    local ep_ip="$1" port="$2" algo="$3" ranks="$4" corpus="$5" log="$6"; shift 6
    local ns; ns="$(netns_for_ep_ip "${ep_ip}")"
    if [[ -z "${ns}" ]]; then
        echo "  WARN: no netns owns EP ${ep_ip} — publisher bind would fail (skipping)"
        return
    fi
    setsid $hexec "${ns}" bash -c "export PYTHONPATH='${PY_USER_SITE}' PYTHONHASHSEED=0; exec -a ${PUB_TAG} python3 '${PUBLISHER}' \
        --corpus '${corpus}' --tokenizer '${TOKENIZER_SRC}' --vectors '${VECTORS_SRC}' \
        --bind ${ep_ip} --port ${port} --algo ${algo} --dp-ranks ${ranks} \
        --block-size ${KV_BLOCK_SIZE} --verbose --no-vocabulary $*" >"${log}" 2>&1 &
}

# wait_inv <service_id> <ep_idx> <predicate> <value> <secs> — poll inv_total until the
# predicate (-gt / -eq / -lt) holds vs value; echo 1/0.
wait_inv() {
    local sid="$1" idx="$2" op="$3" want="$4" secs="$5" cur
    for _ in $(seq 1 "${secs}"); do
        cur="$(inv_total "${sid}" "${idx}")"
        case "${op}" in
            -gt) [[ "${cur}" -gt "${want}" ]] && { echo 1; return; } ;;
            -eq) [[ "${cur}" -eq "${want}" ]] && { echo 1; return; } ;;
            -lt) [[ "${cur}" -lt "${want}" ]] && { echo 1; return; } ;;
        esac
        sleep 1
    done
    echo 0
}

# wait_inv_changed <sid> <idx> <before> <secs> — a publish REPLACES an EP inventory (the
# reconnect resync clears, then the pass re-populates), so "grows past before" stalls and
# ">0" passes trivially on a baseline-warm EP. Converged = the total CHANGED from its
# pre-publish value at any sample (incl. the 0-dip after the clear) AND is now non-zero.
wait_inv_changed() {
    local sid="$1" idx="$2" before="$3" secs="$4" cur seen=0
    for _ in $(seq 1 "${secs}"); do
        cur="$(inv_total "${sid}" "${idx}")"
        [[ "${cur}" != "${before}" ]] && seen=1
        if [[ "${seen}" == 1 && "${cur}" -gt 0 ]]; then echo 1; return; fi
        sleep 1
    done
    echo 0
}

sleep 3
code=0

#################################################################################
# SERVICE-ID RESOLUTION — the inventory Admin API is the authoritative keyspace
# (KvSubscriberStart creates per-EP inventories at rule create). Shape-based:
# VIP-A (P/D) subscribes PREFILLS ONLY -> has idx 0 but NOT idx 1 (idx 1 is a
# decode EP); VIP-B (single-role) subscribes ALL EPs -> has idx 0 AND idx 1.
#################################################################################
SID_A=""; SID_B=""
resolve_sids() {
    local sid has0 has1
    SID_A=""; SID_B=""
    for sid in 1 2 3 4 5 6 7 8 9 10; do
        has0="$(inv_exists "${sid}" 0)"
        [[ "${has0}" == 1 ]] || continue
        has1="$(inv_exists "${sid}" 1)"
        if [[ "${has1}" == 1 ]]; then
            [[ -z "${SID_B}" ]] && SID_B="${sid}"
        else
            [[ -z "${SID_A}" ]] && SID_A="${sid}"
        fi
    done
}
resolve_sids
echo "  resolved serviceIDs: VIP-A(vllm)=${SID_A:-UNRESOLVED} VIP-B(sglang)=${SID_B:-UNRESOLVED}"
assert "(pre) both rules resolved to distinct serviceIDs (shape-based inventory probe)" \
    "$([[ -n "${SID_A}" && -n "${SID_B}" && "${SID_A}" != "${SID_B}" ]] && echo 1 || echo 0)"

# Feature-enable proof: the SGLang fields are live on the VIP-B rule.
lb_all="$(llb_curl "${LBBASE}/all" 2>/dev/null)"
featB_mode=$(echo "${lb_all}" | grep -qE '"kvExactMode" *: *3' && echo 1 || echo 0)
featB_eng=$(echo "${lb_all}" | grep -qE '"kvEngineType" *: *"sglang"' && echo 1 || echo 0)
featB_rank=$(echo "${lb_all}" | grep -qE '"kvDpRankCount" *: *3' && echo 1 || echo 0)
featA_mode=$(echo "${lb_all}" | grep -qE '"kvExactMode" *: *1' && echo 1 || echo 0)
echo "  feature-live: A kvExactMode=1:${featA_mode} ; B kvExactMode=3:${featB_mode} kvEngineType=sglang:${featB_eng} kvDpRankCount=3:${featB_rank}"
assert "(pre) coexistence config live: kvExactMode 1 AND 3 + kvEngineType=sglang + kvDpRankCount=3 on one gateway" \
    "$([[ "${featA_mode}" == 1 && "${featB_mode}" == 1 && "${featB_eng}" == 1 && "${featB_rank}" == 1 ]] && echo 1 || echo 0)"

#################################################################################
# (L0) PUBLISHER FIDELITY — both hash cores self-checked BEFORE any scenario leg
#     (the publisher proves its own hash fidelity: vLLM golden vectors via the
#     reused kv_hash_parity core AND the SGLang golden vectors via the imported
#     sglang_hash_core — the single-source-of-record chain).
#################################################################################
echo "=== (L0) publisher fidelity: vLLM + SGLang golden-vector self-checks ==="
l0_cbor=$(PYTHONHASHSEED=0 python3 "${PUBLISHER}" --self-check --algo sha256_cbor \
    --vectors "${VECTORS_SRC}" >/dev/null 2>&1 && echo 1 || echo 0)
l0_sgl=$(PYTHONHASHSEED=0 python3 "${PUBLISHER}" --self-check --algo sha256_sglang \
    >/dev/null 2>&1 && echo 1 || echo 0)
echo "  self-check: sha256_cbor=${l0_cbor} ; sha256_sglang=${l0_sgl}"
assert "(L0) publisher reproduces BOTH engines' golden vectors (hash fidelity before any leg)" \
    "$([[ "${l0_cbor}" == 1 && "${l0_sgl}" == 1 ]] && echo 1 || echo 0)"

#################################################################################
# (L1) INVENTORY-GROWS / MULTI-RANK UNION — 3-rank publish to the VIRGIN VIP-B EP
#     (idx 2, l3ep7 — config.sh launched NO baseline there, so this is a clean
#     first-connect ingest with zero reconnect-clear history). 6 disjoint prompts
#     partition 2-per-rank; the publisher's multi-rank PUBLISH report prints the
#     per-rank DISTINCT block counts + blocks_total, and the shared inventory must
#     converge to EXACTLY that union. Initial per-rank first-message
#     clears (fresh-rank CLEAR is conservative-by-design) self-heal across the
#     --repeat passes, so equality-at-convergence is deterministic.
#################################################################################
echo "=== (L1) multi-rank union: 3-rank publish to VIRGIN VIP-B idx 2 -> inventory == blocks_total ==="
L1_CORPUS="${CFGDIR}/.kvpub-l1-union.json"
python3 -c '
import json, sys
ps = []
for i in range(6):
    filler = " ".join("u%dw%02d" % (i, k) for k in range(30))
    ps.append({"prompt": "sgl99 union corpus prompt number %d %s" % (i, filler)})
json.dump(ps, open(sys.argv[1], "w"))' "${L1_CORPUS}" 2>/dev/null \
    || echo "  WARN: could not write L1 union corpus"
L1_LOG="${CFGDIR}/.kvpub-l1-union.log"
kill_publisher_ep "${EP_B2_IP}"
sleep 1
launch_publisher "${EP_B2_IP}" "${KV_ZMQ_PORT_B}" "sha256_sglang" "${KV_DP_RANKS}" \
    "${L1_CORPUS}" "${L1_LOG}" --repeat 4 --repeat-interval 4
# Self-confirm the stimulus FIRED: wait for the multi-rank PUBLISH report, then parse it.
l1_report=""
for _ in $(seq 1 40); do
    l1_report="$(grep -E "PUBLISH done: .*ranks=${KV_DP_RANKS} .*blocks_total=" "${L1_LOG}" 2>/dev/null | tail -1)"
    [[ -n "${l1_report}" ]] && break
    sleep 1
done
echo "  publisher report: ${l1_report:-ABSENT}"
l1_total="$(echo "${l1_report}" | grep -Eo 'blocks_total=[0-9]+' | grep -Eo '[0-9]+')"
l1_total="${l1_total:-0}"
# rank_blocks=[a, b, c] — per-rank distinct block counts.
l1_ranks_csv="$(echo "${l1_report}" | grep -Eo 'rank_blocks=\[[0-9, ]+\]' | grep -Eo '[0-9]+' | tr '\n' ' ')"
l1_rank_min=999999; l1_rank_max=0; l1_rank_n=0
for rb in ${l1_ranks_csv}; do
    l1_rank_n=$((l1_rank_n + 1))
    [[ "${rb}" -lt "${l1_rank_min}" ]] && l1_rank_min="${rb}"
    [[ "${rb}" -gt "${l1_rank_max}" ]] && l1_rank_max="${rb}"
done
l1_fired=$([[ "${l1_rank_n}" -eq "${KV_DP_RANKS}" && "${l1_rank_min}" -gt 0 ]] && echo 1 || echo 0)
echo "  self-confirm: ${l1_rank_n}/${KV_DP_RANKS} ranks published (per-rank blocks: ${l1_ranks_csv:-none}; total=${l1_total})"
assert "(L1) stimulus FIRED: every rank published >0 distinct blocks" "${l1_fired}"
l1_conv=$(wait_inv "${SID_B}" 2 -eq "${l1_total}" 45)
l1_size="$(inv_total "${SID_B}" 2)"
l1_union=$([[ "${l1_conv}" == 1 && "${l1_total}" -gt "${l1_rank_max}" ]] && echo 1 || echo 0)
echo "  union: inventory(svc ${SID_B}, idx 2)=${l1_size} (want ==${l1_total}) ; max single rank=${l1_rank_max} (union must exceed it)"
assert "(L1) shared inventory converges to the EXACT 3-rank union AND union > any single rank" "${l1_union}"

#################################################################################
# (L2) TIER15-HIT BOTH VIPS — one steered hit per VIP, disjoint ep_idx targets.
#     VIP-A: PA_HIT published (cbor) ONLY to prefill idx 0 -> request must argmax
#     there. P/D-flow banner semantics (observed on the live testbed): the client-visible
#     banner is the DECODE echo (serverD*); the selection proof is tier15_hits{0}.
#     VIP-B: PB_HIT published (sglang) ONLY to idx 1 -> single-role routes the
#     winner DIRECTLY, so the banner itself is serverS1 (dual proof both ways).
#################################################################################
echo "=== (L2) Tier-1.5 hit on BOTH VIPs (A at idx 0, B at idx 1 — disjoint ep_idx attribution) ==="
L2A_CORPUS="${CFGDIR}/.kvpub-l2-a.json"; write_corpus_single "${L2A_CORPUS}" "${PA_HIT}"
l2a_before_size=$(inv_total "${SID_A}" 0)   # baseline dummy set — the publish must REPLACE it
kill_publisher_ep "${EP_A0_IP}"; sleep 1
launch_publisher "${EP_A0_IP}" "${KV_ZMQ_PORT_A}" "${KV_HASH_ALGO_A}" 1 \
    "${L2A_CORPUS}" "${CFGDIR}/.kvpub-l2-a.log" --repeat 3 --repeat-interval 5 --seq-base 3000
l2a_seeded=$(wait_inv_changed "${SID_A}" 0 "${l2a_before_size}" 30)
[[ "${l2a_seeded}" == 1 ]] || { echo "  WARN: VIP-A idx 0 inventory change not observed in 30s (before=${l2a_before_size})"; sleep 4; }
sleep 3   # let the reconnect-clear/replace settle before the request
a_hits0_before=$(tier15_hits 0)
l2a_banner=$(req_banner "${VPORT_A}" "${PA_HIT}")
a_hits0_after=$(tier15_hits 0)
l2a_deliver=$([[ "${l2a_banner}" == server"D"* ]] && echo 1 || echo 0)
l2a_decide=$([[ "${a_hits0_after}" -gt "${a_hits0_before}" ]] && echo 1 || echo 0)
echo "  VIP-A: seeded=${l2a_seeded} banner=${l2a_banner} (want serverD* — P/D flow) ; tier15{0} ${a_hits0_before}->${a_hits0_after} (want delta)"
assert "(L2) VIP-A Tier-1.5 hit (banner==serverD* P/D flow AND tier15_hits{0} delta — dual proof)" \
    "$([[ "${l2a_deliver}" == 1 && "${l2a_decide}" == 1 ]] && echo 1 || echo 0)"

L2B_CORPUS="${CFGDIR}/.kvpub-l2-b.json"; write_corpus_single "${L2B_CORPUS}" "${PB_HIT}"
l2b_before_size=$(inv_total "${SID_B}" 1)   # baseline dummy set — the publish must REPLACE it
kill_publisher_ep "${EP_B1_IP}"; sleep 1
launch_publisher "${EP_B1_IP}" "${KV_ZMQ_PORT_B}" "sha256_sglang" "${KV_DP_RANKS}" \
    "${L2B_CORPUS}" "${CFGDIR}/.kvpub-l2-b.log" --repeat 3 --repeat-interval 5 --seq-base 3000
l2b_seeded=$(wait_inv_changed "${SID_B}" 1 "${l2b_before_size}" 30)
[[ "${l2b_seeded}" == 1 ]] || { echo "  WARN: VIP-B idx 1 inventory change not observed in 30s (before=${l2b_before_size})"; sleep 4; }
sleep 3
b_hits1_before=$(tier15_hits 1)
l2b_banner=$(req_banner "${VPORT_B}" "${PB_HIT}")
b_hits1_after=$(tier15_hits 1)
l2b_deliver=$([[ "${l2b_banner}" == "serverS1" ]] && echo 1 || echo 0)
l2b_decide=$([[ "${b_hits1_after}" -gt "${b_hits1_before}" ]] && echo 1 || echo 0)
echo "  VIP-B: seeded=${l2b_seeded} banner=${l2b_banner} (want serverS1 — single-role direct) ; tier15{1} ${b_hits1_before}->${b_hits1_after} (want delta)"
assert "(L2) VIP-B Tier-1.5 hit (banner==serverS1 AND tier15_hits{1} delta — dual proof)" \
    "$([[ "${l2b_deliver}" == 1 && "${l2b_decide}" == 1 ]] && echo 1 || echo 0)"

#################################################################################
# (L3) ISOLATION BOTH WAYS — the coexistence core. Surfaces: tier15 deltas on the
#     OTHER VIP's exclusive ep_idx set + the SERVICE-SCOPED inventory sizes.
#     Direction 1: VIP-A frozen while VIP-B takes traffic AND a full rule
#     delete/re-add cycle. Direction 2 mirrored. Self-confirm: the churn side
#     demonstrably served (banners + delete/re-add HTTP codes + re-hit after).
#################################################################################
echo "=== (L3.1) isolation: VIP-A unchanged while VIP-B churns (traffic + rule delete/re-add) ==="
a_iso_h0=$(tier15_hits 0); a_iso_h2=$(tier15_hits 2)
a_iso_i0=$(inv_total "${SID_A}" 0); a_iso_i2=$(inv_total "${SID_A}" 2)
# churn: VIP-B traffic...
b_served=0
for _ in 1 2 3; do
    bn=$(req_banner "${VPORT_B}" "${PB_HIT}")
    [[ -n "${bn}" ]] && b_served=$((b_served + 1))
done
# ...then delete + re-add the VIP-B rule on the SAME gateway.
del_b_rc=$(llb_curl -o /dev/null -w "%{http_code}" -X DELETE \
    "${LBBASE}/hosturl/${VIP}/externalipaddress/${VIP}/port/${VPORT_B}/protocol/tcp" 2>/dev/null)
sleep 3
read -r -d '' RULE_B_JSON <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}", "port": ${VPORT_B}, "protocol": "tcp", "sel": 0, "mode": 4,
    "host": "${VIP}", "probeRetries": 1,
    "kvExactMode": 3, "kvEngineType": "sglang", "kvDpRankCount": ${KV_DP_RANKS},
    "kvZmqPort": ${KV_ZMQ_PORT_B}, "kvWarmupSec": ${KV_WARMUP_SEC}, "kvBlockSize": ${KV_BLOCK_SIZE}
  },
  "endpoints": [
    { "endpointIP": "${EP_B0_IP}", "targetPort": 80, "weight": 1 },
    { "endpointIP": "${EP_B1_IP}", "targetPort": 80, "weight": 1 },
    { "endpointIP": "${EP_B2_IP}", "targetPort": 80, "weight": 1 }
  ]
}
JSON
add_b_rc=$(llb_curl -o /dev/null -w "%{http_code}" -X POST "${LBBASE}" \
    -H 'Content-Type: application/json' -d "${RULE_B_JSON}" 2>/dev/null)
sleep 3
resolve_sids   # re-add mints a NEW ruleNum for B — re-resolve both (A must be unchanged)
echo "  churn self-confirm: B served ${b_served}/3 ; DELETE rc=${del_b_rc} ; re-POST rc=${add_b_rc} ; re-resolved A=${SID_A} B=${SID_B}"
# re-warm B idx 1 and prove B functional post-churn (part of the churn evidence).
kill_publisher_ep "${EP_B1_IP}"; sleep 1
launch_publisher "${EP_B1_IP}" "${KV_ZMQ_PORT_B}" "sha256_sglang" "${KV_DP_RANKS}" \
    "${L2B_CORPUS}" "${CFGDIR}/.kvpub-l3-b.log" --repeat 3 --repeat-interval 5
l3_b_rewarm=$(wait_inv "${SID_B}" 1 -gt 0 30)
sleep 3
l3_b_banner=$(req_banner "${VPORT_B}" "${PB_HIT}")
[[ -n "${l3_b_banner}" ]] && b_served=$((b_served + 1))
l3_churn_fired=$([[ "${b_served}" -ge 3 && "${del_b_rc}" == 2* && "${add_b_rc}" == 2* ]] && echo 1 || echo 0)
assert "(L3.1) churn FIRED: VIP-B served >=3, rule deleted (2xx) and re-added (2xx), re-warmed=${l3_b_rewarm}" "${l3_churn_fired}"
a_iso_h0_after=$(tier15_hits 0); a_iso_h2_after=$(tier15_hits 2)
a_iso_i0_after=$(inv_total "${SID_A}" 0); a_iso_i2_after=$(inv_total "${SID_A}" 2)
echo "  VIP-A stability: tier15{0} ${a_iso_h0}->${a_iso_h0_after} tier15{2} ${a_iso_h2}->${a_iso_h2_after} ; inv(A,0) ${a_iso_i0}->${a_iso_i0_after} inv(A,2) ${a_iso_i2}->${a_iso_i2_after} (want all unchanged)"
assert "(L3.1) VIP-A untouched by VIP-B churn: tier15{0}/{2} deltas == 0 AND svc-A inventories unchanged" \
    "$([[ "${a_iso_h0}" == "${a_iso_h0_after}" && "${a_iso_h2}" == "${a_iso_h2_after}" && "${a_iso_i0}" == "${a_iso_i0_after}" && "${a_iso_i2}" == "${a_iso_i2_after}" ]] && echo 1 || echo 0)"

echo "=== (L3.2) isolation mirrored: VIP-B unchanged while VIP-A churns (traffic + rule delete/re-add) ==="
b_iso_h1=$(tier15_hits 1)
b_iso_i0=$(inv_total "${SID_B}" 0); b_iso_i1=$(inv_total "${SID_B}" 1); b_iso_i2=$(inv_total "${SID_B}" 2)
a_served=0
for _ in 1 2; do
    an=$(req_banner "${VPORT_A}" "${PA_HIT}")
    [[ -n "${an}" ]] && a_served=$((a_served + 1))
done
del_a_rc=$(llb_curl -o /dev/null -w "%{http_code}" -X DELETE \
    "${LBBASE}/hosturl/${VIP}/externalipaddress/${VIP}/port/${VPORT_A}/protocol/tcp" 2>/dev/null)
sleep 3
read -r -d '' RULE_A_JSON <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}", "port": ${VPORT_A}, "protocol": "tcp", "sel": 0, "mode": 4,
    "host": "${VIP}", "pd_disagg_mode": true, "probeRetries": 1,
    "kvExactMode": 1, "kvZmqPort": ${KV_ZMQ_PORT_A}, "kvHashAlgo": "${KV_HASH_ALGO_A}",
    "kvWarmupSec": ${KV_WARMUP_SEC}, "kvBlockSize": ${KV_BLOCK_SIZE}
  },
  "endpoints": [
    { "endpointIP": "${EP_A0_IP}", "targetPort": 80, "weight": 1, "ep_role": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 80, "weight": 1, "ep_role": 2 },
    { "endpointIP": "${EP_A2_IP}", "targetPort": 80, "weight": 1, "ep_role": 1 },
    { "endpointIP": "34.34.34.1", "targetPort": 80, "weight": 1, "ep_role": 2 }
  ]
}
JSON
add_a_rc=$(llb_curl -o /dev/null -w "%{http_code}" -X POST "${LBBASE}" \
    -H 'Content-Type: application/json' -d "${RULE_A_JSON}" 2>/dev/null)
sleep 3
resolve_sids
echo "  churn self-confirm: A served ${a_served}/2 ; DELETE rc=${del_a_rc} ; re-POST rc=${add_a_rc} ; re-resolved A=${SID_A} B=${SID_B}"
# re-warm A idx 0 and prove A functional post-churn.
kill_publisher_ep "${EP_A0_IP}"; sleep 1
launch_publisher "${EP_A0_IP}" "${KV_ZMQ_PORT_A}" "${KV_HASH_ALGO_A}" 1 \
    "${L2A_CORPUS}" "${CFGDIR}/.kvpub-l3-a.log" --repeat 3 --repeat-interval 5
l3_a_rewarm=$(wait_inv "${SID_A}" 0 -gt 0 30)
sleep 3
l3_a_banner=$(req_banner "${VPORT_A}" "${PA_HIT}")
[[ -n "${l3_a_banner}" ]] && a_served=$((a_served + 1))
l3a_churn_fired=$([[ "${a_served}" -ge 2 && "${del_a_rc}" == 2* && "${add_a_rc}" == 2* ]] && echo 1 || echo 0)
assert "(L3.2) churn FIRED: VIP-A served >=2, rule deleted (2xx) and re-added (2xx), re-warmed=${l3_a_rewarm}" "${l3a_churn_fired}"
b_iso_h1_after=$(tier15_hits 1)
b_iso_i0_after=$(inv_total "${SID_B}" 0); b_iso_i1_after=$(inv_total "${SID_B}" 1); b_iso_i2_after=$(inv_total "${SID_B}" 2)
echo "  VIP-B stability: tier15{1} ${b_iso_h1}->${b_iso_h1_after} ; inv(B,0/1/2) ${b_iso_i0}/${b_iso_i1}/${b_iso_i2} -> ${b_iso_i0_after}/${b_iso_i1_after}/${b_iso_i2_after} (want all unchanged)"
assert "(L3.2) VIP-B untouched by VIP-A churn: tier15{1} delta == 0 AND svc-B inventories unchanged" \
    "$([[ "${b_iso_h1}" == "${b_iso_h1_after}" && "${b_iso_i0}" == "${b_iso_i0_after}" && "${b_iso_i1}" == "${b_iso_i1_after}" && "${b_iso_i2}" == "${b_iso_i2_after}" ]] && echo 1 || echo 0)"
# B must still Tier-1.5-hit AFTER surviving A's churn (functional isolation, not just frozen).
b_post_h1_before=$(tier15_hits 1)
b_post_banner=$(req_banner "${VPORT_B}" "${PB_HIT}")
b_post_h1_after=$(tier15_hits 1)
assert "(L3.2) VIP-B still Tier-1.5-hits after VIP-A churn (banner==serverS1 AND tier15{1} delta)" \
    "$([[ "${b_post_banner}" == "serverS1" && "${b_post_h1_after}" -gt "${b_post_h1_before}" ]] && echo 1 || echo 0)"

#################################################################################
# (L4) SAME-MODEL NEGATIVE CONTROL — fails without the svc-id filter; DO NOT
#     WEAKEN. Construction: NC_PROMPT's SGLANG hashes (same model, same tokenizer,
#     same block size as VIP-B's request side) are planted into VIP-A's inventory
#     at ep_idx 2 (inventories store opaque uint64s — the plant is exactly the
#     same-engine+same-model cross-VIP content the svc-id filter must guard against).
#     NC_PROMPT is published to NO VIP-B endpoint. A VIP-B request for NC_PROMPT therefore:
#       * WITH the svc-id filter (correct): scans ONLY svc-B -> zero overlap ->
#         no Tier-1.5 hit ANYWHERE (tier15 sum delta == 0) -> Tier-2 still serves
#         inside VIP-B's OWN ep space (banner==serverS*).
#       * WITHOUT the filter (a legacy all-services scan): svc-A's
#         planted idx-2 inventory is a FULL match; idx 2 passes VIP-B's own
#         eligibility mask (B has an idx 2), so the selector returns 2 and
#         tier15_hits{2} increments — the assert below FAILS. Temporarily removing
#         the filter is how these teeth were confirmed.
#################################################################################
echo "=== (L4) same-model negative control: sglang-hash plant in VIP-A must NOT be reachable from VIP-B ==="
L4_CORPUS="${CFGDIR}/.kvpub-l4-nc.json"; write_corpus_single "${L4_CORPUS}" "${NC_PROMPT}"
kill_publisher_ep "${EP_A2_IP}"; sleep 1
# Plant: SGLang-hash publisher aimed at VIP-A's prefill idx 2 subscriber (:5557, single rank).
launch_publisher "${EP_A2_IP}" "${KV_ZMQ_PORT_A}" "sha256_sglang" 1 \
    "${L4_CORPUS}" "${CFGDIR}/.kvpub-l4-nc.log" --repeat 3 --repeat-interval 5
l4_planted=$(wait_inv "${SID_A}" 2 -gt 0 30)
sleep 3
echo "  self-confirm: NC sglang-hash plant ingested into svc-A idx 2 (inv=$(inv_total "${SID_A}" 2), planted=${l4_planted})"
assert "(L4) stimulus FIRED: same-model sglang plant present in VIP-A's idx-2 inventory" "${l4_planted}"
l4_h2_before=$(tier15_hits 2)
l4_sum_before=$(tier15_sum)
l4_banner1=$(req_banner "${VPORT_B}" "${NC_PROMPT}")
l4_banner2=$(req_banner "${VPORT_B}" "${NC_PROMPT}")
l4_h2_after=$(tier15_hits 2)
l4_sum_after=$(tier15_sum)
l4_served=$([[ "${l4_banner1}" == server"S"* && "${l4_banner2}" == server"S"* ]] && echo 1 || echo 0)
echo "  NC requests: banners=${l4_banner1}/${l4_banner2} (want serverS* — B's own ep space, Tier-2) ; tier15{2} ${l4_h2_before}->${l4_h2_after} (want NO delta) ; tier15 sum ${l4_sum_before}->${l4_sum_after} (want NO delta)"
# fails without the svc-id filter — do not weaken: the legacy all-services scan
# would return svc-A's planted epIdx 2 here and increment tier15_hits{2}.
assert "(L4) NEGATIVE CONTROL: VIP-B NC request hits NOWHERE (tier15{2} delta==0 AND tier15 sum delta==0) AND stays in VIP-B's ep space" \
    "$([[ "${l4_h2_after}" == "${l4_h2_before}" && "${l4_sum_after}" == "${l4_sum_before}" && "${l4_served}" == 1 ]] && echo 1 || echo 0)"
kill_publisher_ep "${EP_A2_IP}"   # unplant: stop the sglang feeder aimed at A

#################################################################################
# (L5) ENGINE-IMMUTABLE — an update changing kvEngineType on the live
#     VIP-B rule must be REJECTED with the EXACT message (delete+recreate is the
#     sanctioned path), and the rule must keep routing afterwards.
#################################################################################
echo "=== (L5) engine immutability: kvEngineType change on live VIP-B rule is rejected ==="
read -r -d '' RULE_B_ENGINE_FLIP <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}", "port": ${VPORT_B}, "protocol": "tcp", "sel": 0, "mode": 4,
    "host": "${VIP}", "probeRetries": 1,
    "kvExactMode": 3, "kvEngineType": "vllm", "kvDpRankCount": ${KV_DP_RANKS},
    "kvZmqPort": ${KV_ZMQ_PORT_B}, "kvWarmupSec": ${KV_WARMUP_SEC}, "kvBlockSize": ${KV_BLOCK_SIZE}
  },
  "endpoints": [
    { "endpointIP": "${EP_B0_IP}", "targetPort": 80, "weight": 1 },
    { "endpointIP": "${EP_B1_IP}", "targetPort": 80, "weight": 1 },
    { "endpointIP": "${EP_B2_IP}", "targetPort": 80, "weight": 1 }
  ]
}
JSON
l5_body="${CFGDIR}/.l5-engine-flip-response.json"
l5_rc=$(llb_curl -o /dev/null -w "%{http_code}" -X POST "${LBBASE}" \
    -H 'Content-Type: application/json' -d "${RULE_B_ENGINE_FLIP}" 2>/dev/null)
llb_curl -X POST "${LBBASE}" -H 'Content-Type: application/json' \
    -d "${RULE_B_ENGINE_FLIP}" 2>/dev/null >"${l5_body}" || true
l5_msg=$(grep -c "cant modify rule kv engine type" "${l5_body}" 2>/dev/null)
l5_msg="${l5_msg:-0}"
l5_rejected=$([[ "${l5_rc}" != 2* && "${l5_msg}" -ge 1 ]] && echo 1 || echo 0)
echo "  engine-flip update: HTTP ${l5_rc} (want non-2xx) ; exact engine-mix message present=${l5_msg} (response: $(head -c 160 "${l5_body}" 2>/dev/null))"
assert "(L5) engine change REJECTED: non-2xx + exact 'cant modify rule kv engine type' message" "${l5_rejected}"
# The rule must still route (and still Tier-1.5-hit) after the rejected update.
l5_h1_before=$(tier15_hits 1)
l5_banner=$(req_banner "${VPORT_B}" "${PB_HIT}")
l5_h1_after=$(tier15_hits 1)
assert "(L5) VIP-B still routes + Tier-1.5-hits after the rejected engine change (banner==serverS1 AND tier15{1} delta)" \
    "$([[ "${l5_banner}" == "serverS1" && "${l5_h1_after}" -gt "${l5_h1_before}" ]] && echo 1 || echo 0)"

#################################################################################
# (L6) EP-RESTART-CLEARS + SEQ-GAP DISCRIMINATION — the structured-marker
#     legs. All greps target the exact logrus markers in the Go-log
#     (field-anchored `ep <digits> rank <digits>`), never bare words.
#################################################################################
echo "=== (L6a) EP-restart-clears: kill + high-seq restart -> 'resync CLEAR' marker + inventory drop-then-regrow ==="
l6a_pre_size=$(inv_total "${SID_B}" 1)
l6a_clear_before=$(go_log_count "kv-subscriber: ep 1 rank [0-9]+ resync CLEAR")
kill_publisher_ep "${EP_B1_IP}"
sleep 6   # subscriber detects the dead socket + rebuilds (clear deferred to first message)
L6A_CORPUS="${CFGDIR}/.kvpub-l6a.json"; write_corpus_single "${L6A_CORPUS}" "${P6A_RESTART}"
launch_publisher "${EP_B1_IP}" "${KV_ZMQ_PORT_B}" "sha256_sglang" "${KV_DP_RANKS}" \
    "${L6A_CORPUS}" "${CFGDIR}/.kvpub-l6a.log" --repeat 3 --repeat-interval 4 --seq-base 50000
# 50000 >> lastSeq+kvSeqResumeWindow(64) -> the first post-reconnect message must log the
# structured reconnect marker `kv-subscriber: ep 1 rank N resync CLEAR — first post-reconnect
# seq=...` and ClearAll the stale set. (AllBlocksCleared is the EVENT-path clear; the restart
# path's marker is resync CLEAR — both are valid log anchors.)
l6a_clear_after="${l6a_clear_before}"
for _ in $(seq 1 30); do
    l6a_clear_after=$(go_log_count "kv-subscriber: ep 1 rank [0-9]+ resync CLEAR")
    [[ "${l6a_clear_after}" -gt "${l6a_clear_before}" ]] && break
    sleep 1
done
l6a_marker=$([[ "${l6a_clear_after}" -gt "${l6a_clear_before}" ]] && echo 1 || echo 0)
# Drop-then-regrow: the restart corpus is ONE full block, strictly smaller than the pre-kill
# warm set — a converged size in (0, pre_size) PROVES the stale set was dropped AND the fresh
# set ingested (equality would mean "never cleared"). Poll for the
# converged window explicitly (sampling right after the marker can catch the 0-dip or the
# not-yet-cleared stale size).
l6a_post_size=$(inv_total "${SID_B}" 1)
for _ in $(seq 1 30); do
    l6a_post_size=$(inv_total "${SID_B}" 1)
    [[ "${l6a_post_size}" -gt 0 && "${l6a_post_size}" -lt "${l6a_pre_size}" ]] && break
    sleep 1
done
l6a_dropped=$([[ "${l6a_post_size}" -gt 0 && "${l6a_post_size}" -lt "${l6a_pre_size}" ]] && echo 1 || echo 0)
echo "  restart: resync-CLEAR markers ${l6a_clear_before}->${l6a_clear_after} (want delta) ; inv(B,1) ${l6a_pre_size} -> ${l6a_post_size} (want 0 < post < pre)"
assert "(L6a) EP restart CLEARS: structured 'resync CLEAR' marker delta AND inventory drop-then-regrow" \
    "$([[ "${l6a_marker}" == 1 && "${l6a_dropped}" == 1 ]] && echo 1 || echo 0)"

echo "=== (L6b) live-stream large gap -> 'decision=CLEAR' marker (no reconnect involved) ==="
L6B_CORPUS="${CFGDIR}/.kvpub-l6b.json"
python3 -c '
import json, sys
ps = []
for i in range(6):
    filler = " ".join("j%dw%02d" % (i, k) for k in range(14))
    ps.append({"prompt": "sgl99 jump leg corpus prompt number %d %s" % (i, filler)})
json.dump(ps, open(sys.argv[1], "w"))' "${L6B_CORPUS}" 2>/dev/null \
    || echo "  WARN: could not write L6b corpus"
l6b_clear_before=$(go_log_count "kv-subscriber: ep 0 rank 0 seq gap .*decision=CLEAR")
kill_publisher_ep "${EP_B0_IP}"; sleep 1
# --seq-jump 100 (> kvSeqResumeWindow 64) on rank 0 mid-stream: the NEXT rank-0 message is a
# live gap with replay==nil -> the seq-gap discriminator logs `... decision=CLEAR — large
# forward jump` (justResynced does not suppress it — this is not the first post-reconnect msg).
# --settle-sec 7 (> kvReconnectFailBackoff 5s): after the kill above, loxilb's
# subscriber is mid-backoff; a long post-bind settle lets it re-establish the live
# stream BEFORE the mid-stream jump, so the +100 hop is seen as a live-stream gap
# (decision=CLEAR) and not as the first post-reconnect message (resync path).
launch_publisher "${EP_B0_IP}" "${KV_ZMQ_PORT_B}" "sha256_sglang" "${KV_DP_RANKS}" \
    "${L6B_CORPUS}" "${CFGDIR}/.kvpub-l6b.log" --repeat 2 --repeat-interval 4 \
    --settle-sec 7 --seq-base 70000 --seq-jump 100 --seq-jump-rank 0
l6b_fired=0
for _ in $(seq 1 30); do
    grep -q "seq-jump +100 on rank 0" "${CFGDIR}/.kvpub-l6b.log" 2>/dev/null && l6b_fired=1 && break
    sleep 1
done
assert "(L6b) stimulus FIRED: publisher applied seq-jump +100 on rank 0 (verbose log line)" "${l6b_fired}"
l6b_clear_after="${l6b_clear_before}"
for _ in $(seq 1 30); do
    l6b_clear_after=$(go_log_count "kv-subscriber: ep 0 rank 0 seq gap .*decision=CLEAR")
    [[ "${l6b_clear_after}" -gt "${l6b_clear_before}" ]] && break
    sleep 1
done
echo "  decision=CLEAR markers (ep 0 rank 0): ${l6b_clear_before}->${l6b_clear_after} (want delta)"
assert "(L6b) live >window gap logs the structured 'decision=CLEAR' marker (gap-no-replay)" \
    "$([[ "${l6b_clear_after}" -gt "${l6b_clear_before}" ]] && echo 1 || echo 0)"

echo "=== (L6c) rank-interleave teeth: small jump on rank 1 -> 'decision=KEEP', ZERO spurious clears elsewhere ==="
l6c_keep_before=$(go_log_count "kv-subscriber: ep 0 rank 1 seq gap .*decision=KEEP")
# OTHER-EP stability surfaces (rank interleave must never leak across EPs):
l6c_ep1_clears_before=$(( $(go_log_count "kv-subscriber: ep 1 rank [0-9]+ resync CLEAR") + $(go_log_count "kv-subscriber: ep 1 rank [0-9]+ seq gap .*decision=CLEAR") ))
l6c_ep1_size_before=$(inv_total "${SID_B}" 1)
kill_publisher_ep "${EP_B0_IP}"; sleep 6
# --seq-jump 7 (<= kvSeqResumeWindow 64) on rank 1: its next message is a small live gap ->
# decision=KEEP (warm inventory retained). Ranks are per-goroutine state — the jump on ep-0
# rank-1 must not move ANY ep-1 clear surface.
# --settle-sec 7 (> kvReconnectFailBackoff 5s): same rationale as L6b — let the
# subscriber reconnect before the small +7 mid-stream hop so it logs decision=KEEP.
launch_publisher "${EP_B0_IP}" "${KV_ZMQ_PORT_B}" "sha256_sglang" "${KV_DP_RANKS}" \
    "${L6B_CORPUS}" "${CFGDIR}/.kvpub-l6c.log" --repeat 2 --repeat-interval 4 \
    --settle-sec 7 --seq-base 80000 --seq-jump 7 --seq-jump-rank 1
l6c_fired=0
for _ in $(seq 1 30); do
    grep -q "seq-jump +7 on rank 1" "${CFGDIR}/.kvpub-l6c.log" 2>/dev/null && l6c_fired=1 && break
    sleep 1
done
assert "(L6c) stimulus FIRED: publisher applied seq-jump +7 on rank 1 (verbose log line)" "${l6c_fired}"
l6c_keep_after="${l6c_keep_before}"
for _ in $(seq 1 30); do
    l6c_keep_after=$(go_log_count "kv-subscriber: ep 0 rank 1 seq gap .*decision=KEEP")
    [[ "${l6c_keep_after}" -gt "${l6c_keep_before}" ]] && break
    sleep 1
done
l6c_ep1_clears_after=$(( $(go_log_count "kv-subscriber: ep 1 rank [0-9]+ resync CLEAR") + $(go_log_count "kv-subscriber: ep 1 rank [0-9]+ seq gap .*decision=CLEAR") ))
l6c_ep1_size_after=$(inv_total "${SID_B}" 1)
echo "  decision=KEEP (ep 0 rank 1): ${l6c_keep_before}->${l6c_keep_after} (want delta) ; ep-1 clear markers ${l6c_ep1_clears_before}->${l6c_ep1_clears_after} + inv(B,1) ${l6c_ep1_size_before}->${l6c_ep1_size_after} (want both unchanged)"
assert "(L6c) small jump KEEPs (structured marker) AND no spurious clears on OTHER EPs (markers + inventory stable)" \
    "$([[ "${l6c_keep_after}" -gt "${l6c_keep_before}" && "${l6c_ep1_clears_after}" == "${l6c_ep1_clears_before}" && "${l6c_ep1_size_after}" == "${l6c_ep1_size_before}" ]] && echo 1 || echo 0)"

#################################################################################
# (L7) ZERO-HIT WATCHDOG — a THROWAWAY third rule with a
#     DELIBERATELY wrong kvBlockSize (32 vs the publisher's 16-token pages): its
#     request-side pages can never intersect its (non-empty, eligible) inventory,
#     so >N consecutive lookups must fire [KV_ZEROHIT] exactly once (transition
#     edge) + move loxilb_pd_kv_zero_hit_watchdog_total{service_id} (volume).
#     config.sh injected LOXILB_KV_ZERO_HIT_N=5, so ~8 lookups suffice.
#################################################################################
echo "=== (L7) zero-hit watchdog: throwaway rule with wrong kvBlockSize -> [KV_ZEROHIT] + counter ==="
read -r -d '' RULE_C_JSON <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}", "port": ${VPORT_C}, "protocol": "tcp", "sel": 0, "mode": 4,
    "host": "${VIP}", "probeRetries": 1,
    "kvExactMode": 3, "kvEngineType": "sglang", "kvDpRankCount": 1,
    "kvZmqPort": ${KV_ZMQ_PORT_C}, "kvWarmupSec": ${KV_WARMUP_SEC}, "kvBlockSize": ${KV_BLOCK_SIZE_WRONG}
  },
  "endpoints": [
    { "endpointIP": "${EP_B0_IP}", "targetPort": 80, "weight": 1 },
    { "endpointIP": "${EP_B1_IP}", "targetPort": 80, "weight": 1 },
    { "endpointIP": "${EP_B2_IP}", "targetPort": 80, "weight": 1 }
  ]
}
JSON
add_c_rc=$(llb_curl -o /dev/null -w "%{http_code}" -X POST "${LBBASE}" \
    -H 'Content-Type: application/json' -d "${RULE_C_JSON}" 2>/dev/null)
sleep 3
# Resolve SID_C by novelty: the sid with an idx-0 inventory that is neither A nor B.
SID_C=""
for sid in 1 2 3 4 5 6 7 8 9 10 11 12; do
    [[ "${sid}" == "${SID_A}" || "${sid}" == "${SID_B}" ]] && continue
    [[ "$(inv_exists "${sid}" 0)" == 1 ]] && SID_C="${sid}" && break
done
echo "  VIP-C created rc=${add_c_rc} (want 2xx) ; resolved SID_C=${SID_C:-UNRESOLVED}"
assert "(L7) throwaway rule created (2xx) + serviceID resolved" \
    "$([[ "${add_c_rc}" == 2* && -n "${SID_C}" ]] && echo 1 || echo 0)"
# Feed VIP-C's idx-0 inventory with 16-token pages (:5571 — its own zmq port; the eligible
# NON-EMPTY precondition the watchdog requires).
L7_CORPUS="${CFGDIR}/.kvpub-l7-zh.json"; write_corpus_single "${L7_CORPUS}" "${ZH_PROMPT}"
kill_publisher_port "${KV_ZMQ_PORT_C}"; sleep 1
launch_publisher "${EP_B0_IP}" "${KV_ZMQ_PORT_C}" "sha256_sglang" 1 \
    "${L7_CORPUS}" "${CFGDIR}/.kvpub-l7-zh.log" --repeat 8 --repeat-interval 4
l7_seeded=$(wait_inv "${SID_C:-0}" 0 -gt 0 30)
echo "  self-confirm: VIP-C idx-0 inventory non-empty (eligible precondition) seeded=${l7_seeded} size=$(inv_total "${SID_C:-0}" 0)"
assert "(L7) stimulus precondition: VIP-C holds a non-empty (16-token-page) inventory" "${l7_seeded}"
l7_warn_before=$(go_log_count "\[KV_ZEROHIT\] service ${SID_C:-999}:")
l7_cnt_before=$(metric_val "loxilb_pd_kv_zero_hit_watchdog_total\{service_id=\"${SID_C:-999}\"\}")
l7_served=0
for _ in 1 2 3 4 5 6 7 8; do
    cb=$(req_banner "${VPORT_C}" "${ZH_PROMPT}")
    [[ -n "${cb}" ]] && l7_served=$((l7_served + 1))
done
assert "(L7) stimulus FIRED: >N lookups driven and served via Tier-2 fail-open (8/8 non-empty banners == data plane never breaks)" \
    "$([[ "${l7_served}" -eq 8 ]] && echo 1 || echo 0)"
l7_warn_after="${l7_warn_before}"; l7_cnt_after="${l7_cnt_before}"
for _ in $(seq 1 15); do
    l7_warn_after=$(go_log_count "\[KV_ZEROHIT\] service ${SID_C:-999}:")
    l7_cnt_after=$(metric_val "loxilb_pd_kv_zero_hit_watchdog_total\{service_id=\"${SID_C:-999}\"\}")
    [[ "${l7_warn_after}" -gt "${l7_warn_before}" && "${l7_cnt_after}" -gt "${l7_cnt_before}" ]] && break
    sleep 1
done
l7_warn_delta=$((l7_warn_after - l7_warn_before))
echo "  watchdog: [KV_ZEROHIT] service ${SID_C:-?} WARNs ${l7_warn_before}->${l7_warn_after} (want +1, transition edge) ; counter{service_id=\"${SID_C:-?}\"} ${l7_cnt_before}->${l7_cnt_after} (want delta>0, volume)"
assert "(L7) [KV_ZEROHIT] WARN fired EXACTLY once (transition edge) for VIP-C" \
    "$([[ "${l7_warn_delta}" -eq 1 ]] && echo 1 || echo 0)"
assert "(L7) loxilb_pd_kv_zero_hit_watchdog_total{service_id=${SID_C:-?}} delta > 0 (authoritative parity-failure signal)" \
    "$([[ "${l7_cnt_after}" -gt "${l7_cnt_before}" ]] && echo 1 || echo 0)"
# Teardown the throwaway rule + its feeder (paired-resource discipline).
del_c_rc=$(llb_curl -o /dev/null -w "%{http_code}" -X DELETE \
    "${LBBASE}/hosturl/${VIP}/externalipaddress/${VIP}/port/${VPORT_C}/protocol/tcp" 2>/dev/null)
kill_publisher_port "${KV_ZMQ_PORT_C}"
assert "(L7) throwaway rule deleted (2xx)" "$([[ "${del_c_rc}" == 2* ]] && echo 1 || echo 0)"

#################################################################################
# (L8) COLD-START SEED — a fourth throwaway rule (CORRECT kvBlockSize this
#     time) whose idx-1 EP carries the only publisher: idx 0/2 subscribe but
#     never receive, so their inventories exist EMPTY (cold). Every request is
#     a deep tier15 hit on idx 1; at the built-in default
#     LOXILB_KV_COLDSTART_SEED_N=16 the 16th hit must divert to the LOWEST
#     cold index (0): [KV_COLDSEED] marker + cold_seeds{ep_idx=0} counter + a
#     serverS0 banner (the datapath receipt), while idx 2 gets nothing and the
#     other 19 requests keep their idx-1 affinity.
#################################################################################
echo "=== (L8) cold-start seed: warm idx-1 + empty idx-0/2 -> the 16th hit re-admits the lowest cold EP ==="
VPORT_D=9092
KV_ZMQ_PORT_D=5572
CS_PROMPT="sgl99 cold start seed anchor prompt the sglang endpoint at index one is the only publisher on this throwaway rule so every lookup is a deep hit there while index zero and index two stay empty and starved abbot breeze cobalt drift ember frost gully harbor inlet juniper knoll lagoon meadow nectar orchard prairie quarry ridge summit thicket upland valley willow xanadu yarrow zenith"
read -r -d '' RULE_D_JSON <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}", "port": ${VPORT_D}, "protocol": "tcp", "sel": 0, "mode": 4,
    "host": "${VIP}", "probeRetries": 1,
    "kvExactMode": 3, "kvEngineType": "sglang", "kvDpRankCount": 1,
    "kvZmqPort": ${KV_ZMQ_PORT_D}, "kvWarmupSec": ${KV_WARMUP_SEC}, "kvBlockSize": ${KV_BLOCK_SIZE}
  },
  "endpoints": [
    { "endpointIP": "${EP_B0_IP}", "targetPort": 80, "weight": 1 },
    { "endpointIP": "${EP_B1_IP}", "targetPort": 80, "weight": 1 },
    { "endpointIP": "${EP_B2_IP}", "targetPort": 80, "weight": 1 }
  ]
}
JSON
add_d_rc=$(llb_curl -o /dev/null -w "%{http_code}" -X POST "${LBBASE}" \
    -H 'Content-Type: application/json' -d "${RULE_D_JSON}" 2>/dev/null)
sleep 3
# Resolve SID_D by novelty (VIP-C is deleted; its state is gone, so the scan
# lands on the one live sid that is neither A nor B).
SID_D=""
for sid in 1 2 3 4 5 6 7 8 9 10 11 12; do
    [[ "${sid}" == "${SID_A}" || "${sid}" == "${SID_B}" ]] && continue
    [[ "$(inv_exists "${sid}" 0)" == 1 ]] && SID_D="${sid}" && break
done
echo "  VIP-D created rc=${add_d_rc} (want 2xx) ; resolved SID_D=${SID_D:-UNRESOLVED}"
assert "(L8) throwaway rule created (2xx) + serviceID resolved" \
    "$([[ "${add_d_rc}" == 2* && -n "${SID_D}" ]] && echo 1 || echo 0)"
# idx-1 is the ONLY feeder; idx 0/2 inventories must stay empty (the cold set).
L8_CORPUS="${CFGDIR}/.kvpub-l8-cs.json"; write_corpus_single "${L8_CORPUS}" "${CS_PROMPT}"
kill_publisher_port "${KV_ZMQ_PORT_D}"; sleep 1
launch_publisher "${EP_B1_IP}" "${KV_ZMQ_PORT_D}" "sha256_sglang" 1 \
    "${L8_CORPUS}" "${CFGDIR}/.kvpub-l8-cs.log" --repeat 8 --repeat-interval 4
l8_warm=$(wait_inv "${SID_D:-0}" 1 -gt 0 30)
l8_cold0=$(inv_total "${SID_D:-0}" 0); l8_cold2=$(inv_total "${SID_D:-0}" 2)
echo "  precondition: inv(D,1)=$(inv_total "${SID_D:-0}" 1) (want >0) ; inv(D,0)=${l8_cold0} inv(D,2)=${l8_cold2} (want both 0)"
assert "(L8) stimulus precondition: idx-1 warm, idx-0/idx-2 EMPTY (the cold set exists)" \
    "$([[ "${l8_warm}" == 1 && "${l8_cold0}" == 0 && "${l8_cold2}" == 0 ]] && echo 1 || echo 0)"
sleep $((KV_WARMUP_SEC + 2))   # let the rule's kvWarmupSec elapse so hits count
l8_seed0_before=$(metric_val "loxilb_pd_kv_tier15_cold_seeds_total\{ep_idx=\"0\"\}")
l8_seed2_before=$(metric_val "loxilb_pd_kv_tier15_cold_seeds_total\{ep_idx=\"2\"\}")
l8_hits1_before=$(tier15_hits 1)
l8_marker_before=$(go_log_count "\[KV_COLDSEED\] svc=${SID_D:-999} ")
l8_s0=0; l8_s1=0; l8_s2=0; l8_served=0
for _ in $(seq 1 20); do
    cb=$(req_banner "${VPORT_D}" "${CS_PROMPT}")
    case "${cb}" in
        serverS0) l8_s0=$((l8_s0 + 1)) ;;
        serverS1) l8_s1=$((l8_s1 + 1)) ;;
        serverS2) l8_s2=$((l8_s2 + 1)) ;;
    esac
    [[ -n "${cb}" ]] && l8_served=$((l8_served + 1))
done
assert "(L8) stimulus FIRED: 20/20 requests served (data plane never breaks)" \
    "$([[ "${l8_served}" -eq 20 ]] && echo 1 || echo 0)"
l8_seed0_after="${l8_seed0_before}"; l8_marker_after="${l8_marker_before}"
for _ in $(seq 1 15); do
    l8_seed0_after=$(metric_val "loxilb_pd_kv_tier15_cold_seeds_total\{ep_idx=\"0\"\}")
    l8_marker_after=$(go_log_count "\[KV_COLDSEED\] svc=${SID_D:-999} ")
    [[ "${l8_seed0_after}" -gt "${l8_seed0_before}" && "${l8_marker_after}" -gt "${l8_marker_before}" ]] && break
    sleep 1
done
l8_seed2_after=$(metric_val "loxilb_pd_kv_tier15_cold_seeds_total\{ep_idx=\"2\"\}")
l8_hits1_after=$(tier15_hits 1)
l8_seed0_delta=$((l8_seed0_after - l8_seed0_before))
echo "  seed: cold_seeds{0} ${l8_seed0_before}->${l8_seed0_after} (want delta>0) ; cold_seeds{2} ${l8_seed2_before}->${l8_seed2_after} (want unchanged) ; [KV_COLDSEED] svc=${SID_D:-?} markers ${l8_marker_before}->${l8_marker_after}"
echo "  banners: S0=${l8_s0} S1=${l8_s1} S2=${l8_s2} ; tier15_hits{1} ${l8_hits1_before}->${l8_hits1_after}"
assert "(L8) [KV_COLDSEED] marker + cold_seeds{ep_idx=0} delta > 0 (the cold EP was re-admitted)" \
    "$([[ "${l8_seed0_delta}" -gt 0 && "${l8_marker_after}" -gt "${l8_marker_before}" ]] && echo 1 || echo 0)"
assert "(L8) lowest cold index wins: cold_seeds{ep_idx=2} unchanged AND zero S2 banners" \
    "$([[ "${l8_seed2_after}" == "${l8_seed2_before}" && "${l8_s2}" -eq 0 ]] && echo 1 || echo 0)"
assert "(L8) datapath receipt: serverS0 banners == cold_seeds{0} delta (each seed actually served by the cold EP)" \
    "$([[ "${l8_s0}" -eq "${l8_seed0_delta}" ]] && echo 1 || echo 0)"
assert "(L8) warm affinity undisturbed: tier15_hits{1} delta >= 15 of 20 (only the seeded ticks diverted)" \
    "$([[ $((l8_hits1_after - l8_hits1_before)) -ge 15 ]] && echo 1 || echo 0)"
# Teardown the throwaway rule + its feeder (paired-resource discipline).
del_d_rc=$(llb_curl -o /dev/null -w "%{http_code}" -X DELETE \
    "${LBBASE}/hosturl/${VIP}/externalipaddress/${VIP}/port/${VPORT_D}/protocol/tcp" 2>/dev/null)
kill_publisher_port "${KV_ZMQ_PORT_D}"
assert "(L8) throwaway rule deleted (2xx)" "$([[ "${del_d_rc}" == 2* ]] && echo 1 || echo 0)"

#################################################################################
# EVIDENCE DUMP (non-assert) — captured BEFORE the sentinel so a FAIL always ships
# its decision trail (a FAIL is guilty until an experiment proves innocent).
#################################################################################
echo "=== evidence: structured Go-log markers + KV metrics ==="
docker exec llb1 sh -c "grep -hE 'kv-subscriber: (ep [0-9]+ rank [0-9]+ (resync|seq gap)|AllBlocksCleared received)|KV_ZEROHIT|KV_COLDSEED' ${GO_LOG} 2>/dev/null | tail -25" \
    | sed 's/^/  [go-log] /' || echo "  (no Go-log access)"
llb_curl "${METRICS}" 2>/dev/null | grep -E "tier15_hits|tier15_cold_seeds|zero_hit_watchdog|kv_subscriber_connected|kv_subscriber_reconnect" \
    | grep -v '^#' | sed 's/^/  [metric] /' || true
for _pl in "${CFGDIR}"/.kvpub-l*.log; do
    [[ -e "${_pl}" ]] || continue
    echo "  [publisher ${_pl##*/}] $(grep -E 'PUBLISH done|seq-jump' "${_pl}" 2>/dev/null | tail -1)"
done

if [[ "${code}" == 0 ]]; then
    echo "=== SCENARIO-sglang-loxilb-kvcache [OK] ==="
else
    echo "=== SCENARIO-sglang-loxilb-kvcache [FAILED] ==="
    exit 1
fi
