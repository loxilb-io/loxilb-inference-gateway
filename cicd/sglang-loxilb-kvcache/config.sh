#!/bin/bash
# config.sh — two-VIP multi-framework KV-routing coexistence topology.
#
# Stands up ONE loxilb gateway carrying TWO KV-exact rules simultaneously to exercise the
# coexistence surface (two engines, one gateway):
#
#   VIP-A (10.10.10.254:8080) — the unmodified vLLM P/D mock shape (kvExactMode=1,
#          pd_disagg_mode, sha256_cbor publishers, prefill/decode roles) — byte-for-byte the
#          vllm-kvcache-routing-cpu rule template.
#   VIP-B (10.10.10.254:9090) — the single-role SGLang shape (kvExactMode=3,
#          kvEngineType=sglang, kvDpRankCount=3, role-less EPs), fed by mock publishers
#          speaking the SGLang wire/hash contract (--algo sha256_sglang --dp-ranks 3 —
#          kv_event_publisher.py imports sglang_hash_core, the single hash source of record).
#          kvHashAlgo is deliberately omitted so the engine default drives
#          kv_hash_algo=sha256_sglang on the C request side.
#
# Both rules share ONE loxilb process AND one VIP IP (different ports) — deliberately: rules
# are keyed VIP:port:proto, so per-service isolation is fully measurable (service-scoped
# inventory REST + disjoint tier15 ep_idx targets), and the same-IP/different-engine pair
# exercises the engine-mix WARN ("that IS the coexistence story" — allowed, logged).
#
# Topology (9 containers; reflect-echo banners are the visible proof that requests landed):
#
#   llb1   — loxilb (ONE gateway for both VIPs), REST on localhost:11111 (auth-off, CICD mode)
#   l3h1   — client host (drives requests to BOTH VIPs + hosts nothing else)
#   VIP-A EPs (P/D roles, prefill at NON-ADJACENT abs indices 0/2 — bitmask shape):
#     l3ep1 — 31.31.31.1  ECHO_NAME=serverP0  PREFILL (abs idx 0)  ep_role=1
#     l3ep2 — 32.32.32.1  ECHO_NAME=serverD0  DECODE  (abs idx 1)  ep_role=2
#     l3ep3 — 33.33.33.1  ECHO_NAME=serverP1  PREFILL (abs idx 2)  ep_role=1
#     l3ep4 — 34.34.34.1  ECHO_NAME=serverD1  DECODE  (abs idx 3)  ep_role=2
#   VIP-B EPs (role-less — kvExactMode=3 single-role):
#     l3ep5 — 35.35.35.1  ECHO_NAME=serverS0  (abs idx 0)
#     l3ep6 — 36.36.36.1  ECHO_NAME=serverS1  (abs idx 1)
#     l3ep7 — 37.37.37.1  ECHO_NAME=serverS2  (abs idx 2)  — VIRGIN (see below)
#
# ep_idx NUMERIC-SPACE NOTE (tier15 attribution): loxilb_pd_kv_tier15_hits_total{ep_idx}
# carries NO service label, so validation.sh steers hits to NUMERICALLY DISJOINT targets:
# VIP-A can only ever hit idx 0/2 (its prefills — decode EPs are never Tier-1.5 candidates),
# VIP-B legs target idx 1 (serverS1). A tier15{1} delta during a VIP-A-only window (or a
# tier15{0}/{2} delta during a VIP-B-only window) is therefore cross-VIP contamination.
#
# VIRGIN EP (l3ep7 / VIP-B idx 2): NO baseline publisher is launched for it HERE — it is
# reserved for validation.sh's multi-rank UNION leg, which needs a first-connect ingest with
# ZERO reconnect-clear history so the 3-rank union size is exactly assertable.
#
# GO-LOG SURFACE: the Go kv-subscriber logs via logrus to stderr, and common.sh launches
# loxilb with `docker exec -dt`, which DISCARDS that stream (/var/log/loxilb*.log is the
# C/tk-logger only; `docker logs llb1` shows only the entrypoint bash). The structured
# markers (`decision=KEEP|CLEAR`, `resync CLEAR`, `AllBlocksCleared received for ep N
# (rank R)`, `[KV_ZEROHIT]`) that validation.sh anchors on live in THAT stream. So after
# the topology is up we RESTART loxilb in-container with stderr+stdout redirected to
# /var/log/loxilb-go.log (a standard in-container restart — this is a scenario-local
# container, never a shared controller) and re-gate on REST readiness before seeding any rule.
#
# LOXILB_KV_ZERO_HIT_N=5 (env-injected at spawn): lowers the zero-hit watchdog threshold
# from 50 so validation.sh's deliberate-block-size-mismatch leg fires within ~8 lookups. The
# healthy VIPs never accumulate a 5-streak (their corpus requests HIT, which resets the
# per-service streak), so the lowered N does not perturb the coexistence legs.
#
# Run on the remote testbed (Docker + ip netns are NOT available on macOS):
#   ./scripts/remote-cicd.sh sglang-loxilb-kvcache
# or, on a Linux testbed directly: sudo ./config.sh && sudo ./validation.sh ; ./rmconfig.sh
# macOS only validates `bash -n` + `shellcheck -S error` (no Docker/eBPF/CGO build there).

# No host-side port publish: this scenario drives REST exclusively via $hexec (in-netns
# curl to localhost:11111), and a resident host-network loxilb (--net=host) may already own
# 8091/11111 — publishing would leave llb1 stuck in "Created".
export LLB_HOST_PORTS=""
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"

# Idempotency: a prior aborted run leaves containers + llb1
# counters/inventories behind and spawn_docker_host silently no-ops on existing names —
# validation would then run against STALE state. Always self-clean first; rmconfig is
# scoped to THIS scenario's containers + anchored publisher tag.
"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true

# ── paths of record (shared fixtures + the extended publisher) ─────────────────────────────
TOKENIZER_SLUG="Qwen__Qwen3-0.6B"
TOKENIZER_SRC="${CFGDIR}/../common/kv_hash/fixtures/tokenizers/${TOKENIZER_SLUG}/tokenizer.json"
VECTORS_SRC="${CFGDIR}/../common/kv_hash/fixtures/kv_hash_vectors.json"
PUBLISHER="${CFGDIR}/../vllm-kvcache-routing-cpu/kv_event_publisher.py"

# ── feature-enable parameters (must match validation.sh + the publishers) ──────────────────
VIP="10.10.10.254"
VPORT_A=8080            # VIP-A — vLLM P/D mock rule
VPORT_B=9090            # VIP-B — SGLang single-role rule
KV_ZMQ_PORT_A=5557      # vLLM publisher port (kvZmqPort default)
KV_ZMQ_PORT_B=5561      # SGLang rank-0 base port (ranks bind 5561/5562/5563)
KV_HASH_ALGO_A="sha256_cbor"
KV_DP_RANKS=3
KV_WARMUP_SEC=20
KV_BLOCK_SIZE=16
KV_ZERO_HIT_N=5

echo "#########################################"
echo "Building the reflect-echo backend image (ghcr.io/loxilb-io/reflect-echo:latest)"
echo "#########################################"
# reflect-echo dock-type runs ghcr.io/loxilb-io/reflect-echo:latest — built locally from the shared
# cicd/common/reflect-echo context (NOT pulled). Without this the 7 EP containers fail silently
# and every VIP probe returns an empty banner. Idempotent (docker layer cache).
"$(dirname "$0")/../common/reflect-echo/docker-build.sh"

echo "#########################################"
echo "Spawning all hosts (2 VIPs on one gateway: 4 P/D EPs + 3 single-role EPs)"
echo "#########################################"

# LLB_KV_NONE_HASH_SEED=0 matters for VIP-A ONLY (chained cbor hashing): it
# aligns the C request-side NONE_HASH parent with the publisher's PYTHONHASHSEED=0 seed.
# The SGLang chain (VIP-B) has NO NONE_HASH concept (block 0 hashes with no prior bytes),
# so the env is inert for VIP-B — exactly the per-engine independence this scenario proves.
# LOXILB_KV_ZERO_HIT_N=5 lowers the watchdog threshold (see header).
spawn_docker_host --dock-type loxilb --dock-name llb1 --docker-args "-e LLB_KV_NONE_HASH_SEED=0 -e LOXILB_KV_ZERO_HIT_N=${KV_ZERO_HIT_N}"
spawn_docker_host --dock-type host   --dock-name l3h1
# VIP-A EPs (P/D roles — banner==serverP*/serverD*):
spawn_docker_host --dock-type reflect-echo --dock-name l3ep1 --docker-args "-e ECHO_NAME=serverP0"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep2 --docker-args "-e ECHO_NAME=serverD0"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep3 --docker-args "-e ECHO_NAME=serverP1"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep4 --docker-args "-e ECHO_NAME=serverD1"
# VIP-B EPs (role-less — banner==serverS*):
spawn_docker_host --dock-type reflect-echo --dock-name l3ep5 --docker-args "-e ECHO_NAME=serverS0"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep6 --docker-args "-e ECHO_NAME=serverS1"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep7 --docker-args "-e ECHO_NAME=serverS2"

echo "#########################################"
echo "Connecting and configuring hosts"
echo "#########################################"

connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1
connect_docker_hosts l3ep3 llb1
connect_docker_hosts l3ep4 llb1
connect_docker_hosts l3ep5 llb1
connect_docker_hosts l3ep6 llb1
connect_docker_hosts l3ep7 llb1

sleep 5

# L3 config — each backend on its own /24 so loxilb routes to it as a distinct member.
config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 l3ep3 --host2 llb1 --ptype phy --addr 33.33.33.1/24 --gw 33.33.33.254
config_docker_host --host1 l3ep4 --host2 llb1 --ptype phy --addr 34.34.34.1/24 --gw 34.34.34.254
config_docker_host --host1 l3ep5 --host2 llb1 --ptype phy --addr 35.35.35.1/24 --gw 35.35.35.254
config_docker_host --host1 l3ep6 --host2 llb1 --ptype phy --addr 36.36.36.1/24 --gw 36.36.36.254
config_docker_host --host1 l3ep7 --host2 llb1 --ptype phy --addr 37.37.37.1/24 --gw 37.37.37.254
config_docker_host --host1 llb1 --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb1 --host2 l3ep3 --ptype phy --addr 33.33.33.254/24
config_docker_host --host1 llb1 --host2 l3ep4 --ptype phy --addr 34.34.34.254/24
config_docker_host --host1 llb1 --host2 l3ep5 --ptype phy --addr 35.35.35.254/24
config_docker_host --host1 llb1 --host2 l3ep6 --ptype phy --addr 36.36.36.254/24
config_docker_host --host1 llb1 --host2 l3ep7 --ptype phy --addr 37.37.37.254/24

sleep 5

# ── stage the tokenizer.json of record into llb1 (fixture parity) ──────────────────────────
# loxilb's CGO daulet path reads /etc/loxilb/tokenizers/<slug>/tokenizer.json; the publishers
# read the SAME committed fixture — identical token IDs on BOTH engines' request paths.
echo "Staging tokenizer.json (${TOKENIZER_SLUG}) into llb1..."
if [[ ! -f "${TOKENIZER_SRC}" ]]; then
    echo "  WARN: tokenizer fixture missing: ${TOKENIZER_SRC} (KV intersection will be empty)"
fi
docker exec llb1 mkdir -p "/etc/loxilb/tokenizers/${TOKENIZER_SLUG}" >/dev/null 2>&1 || true
docker cp "${TOKENIZER_SRC}" "llb1:/etc/loxilb/tokenizers/${TOKENIZER_SLUG}/tokenizer.json" 2>/dev/null \
    || echo "  WARN: docker cp tokenizer.json failed"
docker cp "${VECTORS_SRC}" "llb1:/etc/loxilb/tokenizers/kv_hash_vectors.json" 2>/dev/null || true

# ── REST readiness helper: :11111 comes up only AFTER the eBPF load (10-20s) ───────────────
LBBASE="http://localhost:11111/netlox/v1/config/loadbalancer"
wait_rest_ready() {
    local tries="$1" ok=0 rc
    for _ in $(seq 1 "${tries}"); do
        rc=$($hexec llb1 curl -s -m 3 -o /dev/null -w "%{http_code}" "${LBBASE}/all" 2>/dev/null)
        if [[ "$rc" == "200" ]]; then ok=1; break; fi
        sleep 1
    done
    echo "${ok}"
}
echo "Waiting for loxilb REST API (localhost:11111) to be ready..."
[[ "$(wait_rest_ready 40)" == 1 ]] && echo "  loxilb REST API ready" \
    || echo "  WARN: loxilb REST API not ready after 40s — proceeding anyway"

# ── GO-LOG RESTART (see header): recapture the logrus stderr stream ────────────────────────
# common.sh started loxilb via `docker exec -dt` (Go stderr DISCARDED). Kill exactly the
# loxilb process (POSIX /proc walk — no procps dependency in the container) and relaunch it
# with stdout+stderr appended to /var/log/loxilb-go.log. The container env (-e injections
# above) is inherited by docker exec, so LLB_KV_NONE_HASH_SEED / LOXILB_KV_ZERO_HIT_N carry
# over. This is a standard in-container restart on a scenario-local container
# (loxilb is the SUBJECT here, never a fault target — the restart happens BEFORE any rule
# or publisher exists, so no KV state is perturbed).
GO_LOG="/var/log/loxilb-go.log"
echo "Restarting loxilb inside llb1 with Go-log capture (${GO_LOG})..."
docker exec llb1 sh -c 'for c in /proc/[0-9]*/comm; do
    if [ "$(cat "$c" 2>/dev/null)" = "loxilb" ]; then
        p="${c#/proc/}"; kill "${p%/comm}" 2>/dev/null || true
    fi
done' 2>/dev/null || true
sleep 3
# CRITICAL: preserve common.sh's launch flags — a bare relaunch drops extra_opts
# ("-p ..." = Prometheus), leaving /netlox/v1/metrics EMPTY so every metric-delta
# assert reads 0->0. cluster_opts/extra_opts come from common.sh.
docker exec -d llb1 sh -c "exec /root/loxilb-io/loxilb/loxilb ${cluster_opts:-} ${extra_opts:-} >>${GO_LOG} 2>&1"
echo "Waiting for the restarted loxilb REST API..."
[[ "$(wait_rest_ready 40)" == 1 ]] && echo "  restarted loxilb REST API ready" \
    || echo "  WARN: restarted loxilb REST API not ready after 40s"

# ── Enable Prometheus metrics (REQUIRED) ────────────────────────────────────────────────────
# loxilb exposes /netlox/v1/metrics ONLY after this runtime toggle is POSTed; a bare launch
# (no `-p` flag, which this scenario's spawn does not pass) leaves the endpoint empty. Without
# it, validation.sh's tier15_hits/metric_val reads all return 0 and every KV metric-delta
# assert (L2/L3.2/L5 tier15 hits, L7 zero_hit_watchdog counter) FAILS even though the KV
# routing itself works. Enable BEFORE seeding rules so the counters are exposed from t0.
echo "Enabling Prometheus metrics (POST /config/metrics)..."
$hexec llb1 curl -s -o /dev/null -w "  POST /config/metrics -> HTTP %{http_code}\n" \
    -X POST "http://localhost:11111/netlox/v1/config/metrics" 2>/dev/null || \
    echo "  WARN: enabling metrics failed — KV metric-delta asserts will read 0"

# ── Rule 1 of 2: VIP-A — the UNMODIFIED vLLM P/D mock shape ────────────────────────────────
# Byte-for-byte the vllm-kvcache-routing-cpu rule template (kvExactMode=1 + pd_disagg over
# role-partitioned EPs; prefill at non-adjacent abs indices 0/2). The body is a fixed
# template with quoted shell vars only (no unsanitized input).
read -r -d '' SEED_RULE_A <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}",
    "port": ${VPORT_A},
    "protocol": "tcp",
    "sel": 0,
    "mode": 4,
    "host": "${VIP}",
    "pd_disagg_mode": true,
    "probeRetries": 1,
    "kvExactMode": 1,
    "kvZmqPort": ${KV_ZMQ_PORT_A},
    "kvHashAlgo": "${KV_HASH_ALGO_A}",
    "kvWarmupSec": ${KV_WARMUP_SEC},
    "kvBlockSize": ${KV_BLOCK_SIZE}
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1, "ep_role": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 80, "weight": 1, "ep_role": 2 },
    { "endpointIP": "33.33.33.1", "targetPort": 80, "weight": 1, "ep_role": 1 },
    { "endpointIP": "34.34.34.1", "targetPort": 80, "weight": 1, "ep_role": 2 }
  ]
}
JSON

echo "Seeding VIP-A (vLLM P/D mock) ${VIP}:${VPORT_A} (kvExactMode=1, 2 prefill + 2 decode)..."
$hexec llb1 curl -s -o /dev/null -w "  POST /config/loadbalancer (VIP-A vLLM rule) -> HTTP %{http_code}\n" \
    -X POST "${LBBASE}" -H 'Content-Type: application/json' -d "${SEED_RULE_A}"

# ── Rule 2 of 2: VIP-B — the SGLang single-role shape ──────────────────────────────────────
# kvExactMode=3 (single-role, role-LESS EPs — no ep_role fields) + kvEngineType=sglang +
# kvDpRankCount=3 + kvZmqPort=${KV_ZMQ_PORT_B} (ranks subscribe at 5561/5562/5563) +
# kvBlockSize matching the publisher's page size. kvHashAlgo DELIBERATELY OMITTED — the
# engine default drives kv_hash_algo=sha256_sglang.
# Same VIP IP as rule A (different port) — the same-VIP/different-engine WARN is
# EXPECTED in the loxilb log and the rule must still be ACCEPTED (that IS coexistence).
read -r -d '' SEED_RULE_B <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}",
    "port": ${VPORT_B},
    "protocol": "tcp",
    "sel": 0,
    "mode": 4,
    "host": "${VIP}",
    "probeRetries": 1,
    "kvExactMode": 3,
    "kvEngineType": "sglang",
    "kvDpRankCount": ${KV_DP_RANKS},
    "kvZmqPort": ${KV_ZMQ_PORT_B},
    "kvWarmupSec": ${KV_WARMUP_SEC},
    "kvBlockSize": ${KV_BLOCK_SIZE}
  },
  "endpoints": [
    { "endpointIP": "35.35.35.1", "targetPort": 80, "weight": 1 },
    { "endpointIP": "36.36.36.1", "targetPort": 80, "weight": 1 },
    { "endpointIP": "37.37.37.1", "targetPort": 80, "weight": 1 }
  ]
}
JSON

echo "Seeding VIP-B (SGLang single-role) ${VIP}:${VPORT_B} (kvExactMode=3, engine=sglang, dpRanks=${KV_DP_RANKS})..."
$hexec llb1 curl -s -o /dev/null -w "  POST /config/loadbalancer (VIP-B SGLang rule) -> HTTP %{http_code}\n" \
    -X POST "${LBBASE}" -H 'Content-Type: application/json' -d "${SEED_RULE_B}"

sleep 3

# ── Launch the baseline mock publishers ────────────────────────────────────────────────────
# Each publisher binds its EP's OWN IP from INSIDE that EP's netns (loxilb's subscriber
# dials tcp://<ep-ip>:<port> per EP/rank; the EP IPs are local ONLY in their l3epN netns).
# `ip netns exec` runs the host python3 (installed deps +
# host-FS fixtures) and only swaps the network namespace.
echo "Probing publisher python deps (pyzmq/msgpack/cbor2/xxhash/transformers)..."
if ! python3 -c "import zmq, msgpack, cbor2, xxhash, transformers" >/dev/null 2>&1; then
    echo "  installing python publisher deps (pyzmq msgpack cbor2 xxhash transformers)..."
    # Refresh apt lists first: a fresh CI runner can have stale/absent lists, which makes
    # the install below fail instantly with "Unable to locate package".
    sudo apt-get update >/dev/null 2>&1 || echo "  WARN: apt-get update failed"
    # Native modules (zmq/msgpack/cbor2/xxhash) install most reliably from apt — no
    # compiler/wheel fetch — and python3-pip bootstraps pip on hosts that ship a bare
    # python3 (no pip3 wrapper AND no ensurepip module, e.g. this Ubuntu 24 testbed).
    sudo apt-get install -y python3-pip python3-zmq python3-msgpack python3-cbor2 python3-xxhash >/dev/null 2>&1 \
        || echo "  WARN: apt install of native publisher deps failed — falling back to pip"
    # Fallback for whatever apt could not provide (transformers is never in apt; and on a
    # locked/stale-apt CI runner the native modules also land here). pip has prebuilt
    # manylinux wheels for ALL of them, so no compiler is needed. Install to the SYSTEM
    # site as root so the root publisher launched via `ip netns exec` imports them
    # directly. PEP-668 (Ubuntu 24.04) needs --break-system-packages; older pips reject
    # the flag → try plain first, then the flag.
    if ! python3 -c "import zmq, msgpack, cbor2, xxhash, transformers" >/dev/null 2>&1; then
        sudo python3 -m pip install --quiet pyzmq msgpack cbor2 xxhash transformers >/dev/null 2>&1 \
            || sudo python3 -m pip install --quiet --break-system-packages pyzmq msgpack cbor2 xxhash transformers >/dev/null 2>&1 \
            || echo "  WARN: pip install of publisher deps failed"
    fi
    # Re-probe so the outcome is visible in the log rather than failing silently at
    # publisher launch (import error → exit(2) → empty KV inventories downstream).
    if python3 -c "import zmq, msgpack, cbor2, xxhash, transformers" >/dev/null 2>&1; then
        echo "  publisher deps ready"
    else
        echo "  ERROR: publisher deps still missing after install — publishers WILL exit(2):"
        python3 -c "import zmq, msgpack, cbor2, xxhash, transformers" 2>&1 | sed 's/^/    /'
    fi
fi

# `$hexec` (sudo ip netns exec) runs python3 AS ROOT: root cannot see the invoking user's
# pip --user site-packages and sudo env-resets the environment — resolve the user-site dir
# HERE and export it INSIDE every $hexec bash -c string.
PY_USER_SITE="$(python3 -m site --user-site 2>/dev/null || echo '')"

# Anchored process tag (exec -a) so rmconfig.sh / validation.sh kill ONLY this suite's
# publishers by resolved PID — never a host-wide process-name sweep.
PUB_TAG="kvpub99"

# Baseline warms use per-EP-UNIQUE dummy prompts (never the validation corpus): a publish
# REPLACES an EP's inventory on reconnect and the Go argmax is strict-> over randomized map
# iteration, so shared baseline content would tie validation's overlap queries. The dummies
# keep inventories non-empty (sanity + subscriber-connected proof) while sharing ZERO blocks
# with any validation prompt.

# VIP-A baselines: one cbor publisher per PREFILL EP (:5557) — the unmodified vLLM shape.
for ep_pair in "31.31.31.1:l3ep1" "33.33.33.1:l3ep3"; do
    ep_ip="${ep_pair%%:*}"; ep_ns="${ep_pair##*:}"
    PUB_LOG="${CFGDIR}/.kvpub-baseline-A-${ep_ip}.log"
    BASELINE_CORPUS="${CFGDIR}/.kvpub-baseline-A-${ep_ip}.json"
    python3 -c "
import json,sys
ep=sys.argv[1]
p=('sgl99 vipA baseline warm sentinel for vllm prefill endpoint %s — filler so the kv '
   'inventory is non-empty before validation and shares no block with any scenario '
   'prompt: alpha bravo charlie delta echo foxtrot golf hotel india juliett %s') % (ep, ep)
json.dump([{'prompt': p}], open(sys.argv[2],'w'))" "${ep_ip}" "${BASELINE_CORPUS}" 2>/dev/null \
        || echo "  WARN: could not write VIP-A baseline corpus for ${ep_ip}"
    echo "Launching VIP-A baseline publisher in ${ep_ns} on ${ep_ip}:${KV_ZMQ_PORT_A} (sha256_cbor)..."
    setsid $hexec "${ep_ns}" bash -c "export PYTHONPATH='${PY_USER_SITE}' PYTHONHASHSEED=0; exec -a ${PUB_TAG} python3 '${PUBLISHER}' \
        --corpus '${BASELINE_CORPUS}' \
        --tokenizer '${TOKENIZER_SRC}' \
        --vectors '${VECTORS_SRC}' \
        --bind ${ep_ip} --port ${KV_ZMQ_PORT_A} --algo ${KV_HASH_ALGO_A} \
        --block-size ${KV_BLOCK_SIZE} --repeat 4 --repeat-interval 6 --no-vocabulary" >"${PUB_LOG}" 2>&1 &
    echo "  VIP-A baseline publisher launched in ${ep_ns} (pid=$!, log=${PUB_LOG})"
done

# VIP-B baselines: one SGLang publisher per EP for l3ep5 + l3ep6 ONLY (l3ep7 stays VIRGIN
# for the union leg — see header). --dp-ranks 3 binds 5561/5562/5563 on the EP's IP; 3
# unique dummy prompts partition one per rank so ALL rank subscribers see traffic.
for ep_pair in "35.35.35.1:l3ep5" "36.36.36.1:l3ep6"; do
    ep_ip="${ep_pair%%:*}"; ep_ns="${ep_pair##*:}"
    PUB_LOG="${CFGDIR}/.kvpub-baseline-B-${ep_ip}.log"
    BASELINE_CORPUS="${CFGDIR}/.kvpub-baseline-B-${ep_ip}.json"
    python3 -c "
import json,sys
ep=sys.argv[1]
ps=[{'prompt':('sgl99 vipB baseline rank %d warm sentinel for sglang endpoint %s — unique '
    'filler sharing no block with any scenario prompt: kilo lima mike november oscar papa '
    'quebec romeo sierra tango %s rank%d') % (r, ep, ep, r)} for r in range(3)]
json.dump(ps, open(sys.argv[2],'w'))" "${ep_ip}" "${BASELINE_CORPUS}" 2>/dev/null \
        || echo "  WARN: could not write VIP-B baseline corpus for ${ep_ip}"
    echo "Launching VIP-B baseline publisher in ${ep_ns} on ${ep_ip}:${KV_ZMQ_PORT_B}..${KV_ZMQ_PORT_B}+2 (sha256_sglang, 3 ranks)..."
    setsid $hexec "${ep_ns}" bash -c "export PYTHONPATH='${PY_USER_SITE}' PYTHONHASHSEED=0; exec -a ${PUB_TAG} python3 '${PUBLISHER}' \
        --corpus '${BASELINE_CORPUS}' \
        --tokenizer '${TOKENIZER_SRC}' \
        --vectors '${VECTORS_SRC}' \
        --bind ${ep_ip} --port ${KV_ZMQ_PORT_B} --algo sha256_sglang --dp-ranks 3 \
        --block-size ${KV_BLOCK_SIZE} --repeat 4 --repeat-interval 6 --no-vocabulary" >"${PUB_LOG}" 2>&1 &
    echo "  VIP-B baseline publisher launched in ${ep_ns} (pid=$!, log=${PUB_LOG})"
done

# Let the subscribers connect + baseline inventories converge before validation.sh starts.
# Connect happens within kvReconnectFailBackoff (5s) of the bind; the resident publishers
# (--repeat 4 --repeat-interval 6) re-emit at ~6s/12s/18s, so 15s guarantees >=1 full pass.
echo "Waiting ~15s for the KV subscribers (both VIPs) to connect + ingest the baselines..."
sleep 15

export PUB_TAG

echo "#########################################"
echo "Topology up: ONE gateway, TWO KV-exact rules (coexistence)"
echo "  VIP-A ${VIP}:${VPORT_A} -> vLLM P/D mock  (kvExactMode=1, cbor :${KV_ZMQ_PORT_A}, prefill idx 0/2 + decode idx 1/3)"
echo "  VIP-B ${VIP}:${VPORT_B} -> SGLang mock    (kvExactMode=3, engine=sglang, ranks=${KV_DP_RANKS} @ :${KV_ZMQ_PORT_B}.., role-less idx 0/1/2; idx 2 VIRGIN)"
echo "  tokenizer ${TOKENIZER_SLUG} staged; publisher tag=${PUB_TAG}; Go-log at ${GO_LOG} in llb1"
echo "#########################################"
