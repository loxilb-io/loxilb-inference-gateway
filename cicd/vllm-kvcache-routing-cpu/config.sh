#!/bin/bash
# config.sh — KV-cache-aware AI routing CICD topology (fast mock inner loop).
#
# Stands up the 6-EP routing topology + enables the Tier-1.5 KV-cache-aware path on a single
# loxilb fullproxy P/D service, then launches the contract-faithful synthetic ZMQ publisher
# (kv_event_publisher.py) so loxilb's per-prefill-EP go-zeromq subscriber populates a real
# block-hash inventory. validation.sh then drives the four overlap scenarios + the functional checks.
#
# Topology (6 EPs = 3 prefill + 3 decode, prefill at NON-ADJACENT absolute indices so the
# C<->Go bitmask index-translation is exercised; reflect-echo banners are the
# landing-proof surface — banner==serverN, NOT curl):
#
#   llb1   — loxilb (control plane + eBPF dataplane), REST on localhost:11111 (auth-off, CICD mode)
#   l3h1   — client host (drives the routing requests + the publisher)
#   l3ep1  — reflect-echo backend  31.31.31.1  ECHO_NAME=serverP0  PREFILL  (abs idx 0)  ep_role=1
#   l3ep2  — reflect-echo backend  32.32.32.1  ECHO_NAME=serverD0  DECODE   (abs idx 1)  ep_role=2
#   l3ep3  — reflect-echo backend  33.33.33.1  ECHO_NAME=serverP1  PREFILL  (abs idx 2)  ep_role=1
#   l3ep4  — reflect-echo backend  34.34.34.1  ECHO_NAME=serverD1  DECODE   (abs idx 3)  ep_role=2
#   l3ep5  — reflect-echo backend  35.35.35.1  ECHO_NAME=serverP2  PREFILL  (abs idx 4)  ep_role=1
#   l3ep6  — reflect-echo backend  36.36.36.1  ECHO_NAME=serverD2  DECODE   (abs idx 5)  ep_role=2
#
# The 3 prefill EPs sit at absolute endpoint indices 0/2/4 (non-adjacent) — decode EPs interleave at
# 1/3/5 so the prefill set is a non-contiguous bitmask. config.sh references them as EP-A / EP-B
# / EP-C (= 31.31.31.1 / 33.33.33.1 / 35.35.35.1) and decode EPs are NEVER KV-selection candidates.
#
# Feature-enable: a single P/D fullproxy service (mode=4, pd_disagg_mode) carries
# kvExactMode=1 + kvZmqPort=5557 + kvHashAlgo=sha256_cbor + kvWarmupSec + kvBlockSize=16 (the exact
# field set from deploy-kvcache.sh:119-143). The subscriber auto-starts per prefill EP (rules.go).
# serviceID seen by the subscriber == r.ruleNum (the rule ordinal, NOT the port).
#
# Tokenizer of record: the committed Qwen__Qwen3-0.6B tokenizer.json is docker-cp'd into
# /etc/loxilb/tokenizers/Qwen__Qwen3-0.6B/ so loxilb's CGO daulet path and the publisher's HF path
# tokenize IDENTICALLY (genuine non-empty inventory intersection — the token-ID-mismatch trap).
#
# Run on the REMOTE testbed (Docker + ip netns are NOT available on macOS):
#   ./scripts/remote-cicd.sh vllm-kvcache-routing-cpu
# or, on a Linux testbed directly: sudo ./config.sh && sudo ./validation.sh ; ./rmconfig.sh
#
# macOS only validates `bash -n` + `shellcheck -S error` (no Docker/eBPF/CGO build there).

# No host-side port publish: REST is driven via $hexec (in-netns curl); resident
# --net=host loxilb hosts own 8091/11111 (observed on resident-loxilb runners).
export LLB_HOST_PORTS=""
source ../common.sh

# ── paths of record (promoted fixtures + the publisher) ─────────────────────────────────────────────
CFGDIR="$(cd "$(dirname "$0")" && pwd)"

# Idempotency: a prior (interactive/aborted) run leaves the topology + llb1 counters/inventories
# behind, and spawn_docker_host silently no-ops on existing names — validation then runs against
# STALE state (live-proven: a manual probe's tier15_hits leaked into the gate's deltas). Always
# self-clean first; rmconfig is scoped to this scenario's containers/publishers.
"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true
TOKENIZER_SLUG="Qwen__Qwen3-0.6B"
TOKENIZER_SRC="${CFGDIR}/../common/kv_hash/fixtures/tokenizers/Qwen__Qwen3-0.6B/tokenizer.json"
VECTORS_SRC="${CFGDIR}/../common/kv_hash/fixtures/kv_hash_vectors.json"
PUBLISHER="${CFGDIR}/kv_event_publisher.py"
CORPUS="${CFGDIR}/prompts/corpus.json"

# ZMQ + feature-enable parameters (match the publisher + the LB rule).
KV_ZMQ_PORT=5557
KV_HASH_ALGO="sha256_cbor"
KV_WARMUP_SEC=20
KV_BLOCK_SIZE=16

# ── memory-safety knob (cap/eviction gate leg) ───────────────────────────────────────────────────────
# LOXILB_KV_MAX_BLOCKS lowers the per-EP kvInventory cap (default 1_000_000, range 1000..100_000_000 —
# kvResolveMaxBlocks in ai_kv_subscriber.go) to a small deterministic value so validation.sh's cap leg
# can drive ONE prefill EP past it with a flooding publish and observe loxilb_kv_inv_cap_evictions_total
# move while KVINV Size pins at the cap (end-to-end). 1000 is the FLOOR of the accepted
# range (kvResolveMaxBlocks rejects <1000 and silently falls back to the 1M default — so the cap leg
# would never overflow): low enough that a synthetic multi-prompt flood (>1000 distinct blocks)
# overflows it, far above the healthy corpus (~4 blocks/EP) so the byte-for-byte healthy path is
# unchanged (cap never fires in the functional legs). Exported into the llb1 container env below (read once at
# subscriber init) AND kept as a shell var so validation.sh can assert Size==cap.
KV_MAX_BLOCKS="${KV_MAX_BLOCKS:-1000}"
export KV_MAX_BLOCKS

echo "#########################################"
echo "Building the reflect-echo backend image (ghcr.io/loxilb-io/reflect-echo:latest)"
echo "#########################################"
# The `reflect-echo` dock-type (cicd/common.sh) runs ghcr.io/loxilb-io/reflect-echo:latest, a
# NET-NEW image built locally from the shared cicd/common/reflect-echo context — it is NOT pulled.
# Without this the 6 reflect-echo EP containers fail silently and the VIP has no backends (every
# routing probe then returns an empty banner). Idempotent: docker build re-uses layers.
"$(dirname "$0")/../common/reflect-echo/docker-build.sh"

echo "#########################################"
echo "Spawning all hosts (6 EPs = 3 prefill + 3 decode, non-adjacent prefill indices)"
echo "#########################################"

# LLB_KV_NONE_HASH_SEED=0 is REQUIRED (chained hashing): the C request-side
# (kv_compute_none_hash) falls back to an all-ZEROS first-block parent when this env is
# unset, while the publisher AND real vLLM (PYTHONHASHSEED=0) chain from the SEEDED
# parent hash(CBOR("0")) — block 0 diverges, every chained hash after it diverges, and
# the Go argmax scores 0 forever (no_worker guard on every request; proven live on the
# runner). Both parities are in the golden vectors (*_zeros_parent_* AND
# *_noneHashSeed0_*) so the unit layers stay green either way — ONLY this env aligns the
# live sides.
# LOXILB_KV_MAX_BLOCKS is injected here alongside LLB_KV_NONE_HASH_SEED so the lowered
# per-EP cap is in the subscriber's process env at init (kvResolveMaxBlocks reads it ONCE) —
# the cap/eviction leg in validation.sh depends on this small bound to overflow deterministically.
# LLB_KV_HASH_DEBUG=1: enables the flag-gated [KV_T15_STAGE] per-request
# structured record (content-free — stage µs + hit/miss outcome ONLY, never prompt/hash)
# emitted by pd_kv_exact_select. validation.sh's A/B microbench greps
# these lines for the per-stage tokenize/hash/CGO breakdown on BOTH the hit and miss paths.
# The always-on per-stage histogram (record_kv_stage atomic add) runs regardless; this flag
# only turns ON the optional log surface so the CPU-rig A/B can attribute per stage.
spawn_docker_host --dock-type loxilb --dock-name llb1 --docker-args "-e LLB_KV_NONE_HASH_SEED=0 -e LOXILB_KV_MAX_BLOCKS=${KV_MAX_BLOCKS} -e LLB_KV_HASH_DEBUG=1"
spawn_docker_host --dock-type host   --dock-name l3h1
# reflect-echo backends — HTTP echo whose body's leading line is "X-Echo-Backend: <ECHO_NAME>"
# (curl-probed via client_get; the validation grep reads serverP*/serverD* from that body).
# Prefill EPs at absolute idx 0/2/4 (serverP0/P1/P2), decode EPs interleaved at 1/3/5 (serverD0/D1/D2).
spawn_docker_host --dock-type reflect-echo --dock-name l3ep1 --docker-args "-e ECHO_NAME=serverP0"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep2 --docker-args "-e ECHO_NAME=serverD0"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep3 --docker-args "-e ECHO_NAME=serverP1"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep4 --docker-args "-e ECHO_NAME=serverD1"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep5 --docker-args "-e ECHO_NAME=serverP2"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep6 --docker-args "-e ECHO_NAME=serverD2"

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

sleep 5

# L3 config — each backend on its own /24 so loxilb routes to it as a distinct member.
config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 l3ep3 --host2 llb1 --ptype phy --addr 33.33.33.1/24 --gw 33.33.33.254
config_docker_host --host1 l3ep4 --host2 llb1 --ptype phy --addr 34.34.34.1/24 --gw 34.34.34.254
config_docker_host --host1 l3ep5 --host2 llb1 --ptype phy --addr 35.35.35.1/24 --gw 35.35.35.254
config_docker_host --host1 l3ep6 --host2 llb1 --ptype phy --addr 36.36.36.1/24 --gw 36.36.36.254
config_docker_host --host1 llb1 --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb1 --host2 l3ep3 --ptype phy --addr 33.33.33.254/24
config_docker_host --host1 llb1 --host2 l3ep4 --ptype phy --addr 34.34.34.254/24
config_docker_host --host1 llb1 --host2 l3ep5 --ptype phy --addr 35.35.35.254/24
config_docker_host --host1 llb1 --host2 l3ep6 --ptype phy --addr 36.36.36.254/24

sleep 5

# ── stage the tokenizer.json of record + golden vectors into the loxilb container ────────────────────
# loxilb's CGO daulet path reads /etc/loxilb/tokenizers/<slug>/tokenizer.json; the publisher reads the
# SAME committed fixture — identical token IDs => genuine inventory intersection.
# NOTE: deploy-kvcache.sh:55-57 (the GPU harness) set LLB_KV_NONE_HASH_SEED=0 on ITS deploy —
# this CICD spawn path does NOT inherit that: the env is injected explicitly via --docker-args
# at the spawn_docker_host call above (required; see the comment there). docker exec mkdir
# guards a fresh container.
echo "Staging tokenizer.json (${TOKENIZER_SLUG}) + golden vectors into llb1..."
if [[ ! -f "${TOKENIZER_SRC}" ]]; then
    echo "  WARN: tokenizer fixture missing: ${TOKENIZER_SRC} (KV intersection will be empty)"
fi
docker exec llb1 mkdir -p "/etc/loxilb/tokenizers/${TOKENIZER_SLUG}" >/dev/null 2>&1 || true
docker cp "${TOKENIZER_SRC}" "llb1:/etc/loxilb/tokenizers/${TOKENIZER_SLUG}/tokenizer.json" 2>/dev/null \
    || echo "  WARN: docker cp tokenizer.json failed"
docker cp "${VECTORS_SRC}" "llb1:/etc/loxilb/tokenizers/kv_hash_vectors.json" 2>/dev/null || true

# ── REST readiness poll (auto-memory gotcha): REST on :11111 comes up only AFTER the eBPF load (10-20s).
#    Poll GET /netlox/v1/config/loadbalancer/all to HTTP 200 BEFORE any POST so the feature-enable POST
#    is not silently dropped (a POST racing the eBPF load returns HTTP 000).
LBBASE="http://localhost:11111/netlox/v1/config/loadbalancer"
echo "Waiting for loxilb REST API (localhost:11111) to be ready..."
api_ready=0
for _ in $(seq 1 40); do
    rc=$($hexec llb1 curl -s -m 3 -o /dev/null -w "%{http_code}" "${LBBASE}/all" 2>/dev/null)
    if [[ "$rc" == "200" ]]; then api_ready=1; echo "  loxilb REST API ready"; break; fi
    sleep 1
done
[[ "$api_ready" == 1 ]] || echo "  WARN: loxilb REST API not ready after 40s — seeding anyway"

# ── Feature-enable POST — the EXACT kv_* field set from deploy-kvcache.sh:119-143 ────────────────────
# One P/D fullproxy service (mode=4, pd_disagg_mode) over the 6 EPs. Prefill EPs (31/33/35) carry
# ep_role=1 at absolute indices 0/2/4 (non-adjacent bitmask); decode EPs (32/34/36)
# carry ep_role=2 at indices 1/3/5 and are excluded from KV selection. The body is built from a fixed
# template with the IPs/ports interpolated as quoted shell vars only (no unsanitized input).
VIP="10.10.10.254"
VPORT=8080
read -r -d '' SEED_KVRULE <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}",
    "port": ${VPORT},
    "protocol": "tcp",
    "sel": 0,
    "mode": 4,
    "host": "${VIP}",
    "pd_disagg_mode": true,
    "probeRetries": 1,
    "kvExactMode": 1,
    "kvZmqPort": ${KV_ZMQ_PORT},
    "kvHashAlgo": "${KV_HASH_ALGO}",
    "kvWarmupSec": ${KV_WARMUP_SEC},
    "kvBlockSize": ${KV_BLOCK_SIZE}
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1, "ep_role": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 80, "weight": 1, "ep_role": 2 },
    { "endpointIP": "33.33.33.1", "targetPort": 80, "weight": 1, "ep_role": 1 },
    { "endpointIP": "34.34.34.1", "targetPort": 80, "weight": 1, "ep_role": 2 },
    { "endpointIP": "35.35.35.1", "targetPort": 80, "weight": 1, "ep_role": 1 },
    { "endpointIP": "36.36.36.1", "targetPort": 80, "weight": 1, "ep_role": 2 }
  ]
}
JSON

echo "Seeding KV-exact P/D service ${VIP}:${VPORT} (kvExactMode=1, 3 prefill + 3 decode) via REST..."
$hexec llb1 curl -s -o /dev/null -w "  POST /config/loadbalancer (KV-exact rule) -> HTTP %{http_code}\n" \
    -X POST "${LBBASE}" -H 'Content-Type: application/json' -d "${SEED_KVRULE}"

sleep 3

# ── Launch the contract-faithful publisher ─────────────────────────────────────────
# The publisher tokenizes the committed corpus with the SAME tokenizer.json and emits the 3-frame
# vLLM v0.17.0 envelope on the prefill EP ZMQ port (5557). It binds the PREFILL EP's OWN IP from
# inside that EP's netns — loxilb's subscriber dials tcp://<prefill-ep-ip>:5557 (rules.go:3407, ep.xIP),
# and each prefill EP IP (31/33/35.x.x.1) is a local address ONLY in its l3epN netns. (A single
# 127.0.0.1 publisher in the host netns — the prior wiring — was unreachable from those dial addresses,
# which is why subscriber_connected/tier15_hits were stuck at 0.) validation.sh re-drives the publisher
# per-EP (also netns-scoped) with prompt subsets for the four overlap scenarios; here config.sh launches a
# baseline warm per prefill EP so GET /config/ai/kv/inventory is non-empty by the time validation.sh starts.
#
# Probe-guard the python deps (the kv_hash_parity.py:50-66 idiom) before invoking the publisher.
echo "Probing publisher python deps (pyzmq/cbor2/xxhash/transformers)..."
if ! python3 -c "import zmq, cbor2, xxhash, transformers" >/dev/null 2>&1; then
    echo "  installing python publisher deps (pyzmq cbor2 xxhash transformers)..."
    # pip has prebuilt manylinux wheels for all of these (no compiler needed). Invoke pip
    # as `python3 -m pip` (NOT the pip3 wrapper, which is absent on bare-python3 hosts).
    # PEP-668 (Ubuntu 24.04): try plain first, then --break-system-packages.
    python3 -m pip install --quiet pyzmq cbor2 xxhash transformers >/dev/null 2>&1 \
        || python3 -m pip install --quiet --break-system-packages pyzmq cbor2 xxhash transformers >/dev/null 2>&1 \
        || echo "  WARN: pip install of publisher deps failed"
    # Re-probe so the outcome is visible in the log rather than failing silently at
    # publisher launch (import error → exit(2) → empty KV inventories downstream).
    if python3 -c "import zmq, cbor2, xxhash, transformers" >/dev/null 2>&1; then
        echo "  publisher deps ready"
    else
        echo "  ERROR: publisher deps still missing after install — publisher WILL exit(2):"
        python3 -c "import zmq, cbor2, xxhash, transformers" 2>&1 | sed 's/^/    /'
    fi
fi

# serviceID == r.ruleNum (the rule ordinal). The first KV-exact rule on a fresh container is ordinal 0;
# validation.sh re-resolves it from GET /config/loadbalancer/all if needed. The baseline warm publishes
# the whole corpus's full blocks to EACH prefill EP so the inventory converges.
#
# CRITICAL (root cause of the prior subscriber_connected=0 / tier15_hits=0): loxilb's subscriber dials
# tcp://<prefill-ep-ip>:5557 PER prefill EP (rules.go:3407 — ep.xIP, NOT loopback). The prefill EP IPs
# (31/33/35.x.x.1) are local ONLY inside their own l3epN netns. A single publisher bound to 127.0.0.1
# (the previous wiring) is unreachable from those dial addresses, and binding the EP IP from the host
# netns fails EADDRNOTAVAIL. So we launch one baseline publisher PER prefill EP, FROM INSIDE that EP's
# netns (`ip netns exec l3epN`), binding the EP's own IP. `ip netns exec` runs the host python3 (with
# its installed deps + host-FS fixtures) and only swaps the network namespace.
PUB_TAG="kvpub80"
# `$hexec` = `sudo ip netns exec` runs python3 AS ROOT: root cannot see the ubuntu user's
# pip --user site-packages (cbor2/pyzmq/xxhash/transformers) and sudo env-resets the outer
# environment. So resolve the invoking user's site dir HERE (as ubuntu) and export it INSIDE
# the bash -c string below, together with PYTHONHASHSEED. Without this the publisher exits 2
# ("cbor2 package is required") while the ubuntu-user probe-guard above passes — an early-run
# failure mode (.kvpub-baseline-*.log).
PY_USER_SITE="$(python3 -m site --user-site 2>/dev/null || echo '')"
# Baseline warm = a DISTINCT per-EP dummy prompt, NOT the real corpus. The subscriber CLEARS an
# EP's inventory on every reconnect (a new publisher process = clear + replace), and the Go argmax
# is strict-> over a randomized map iteration — so warming every EP with the full corpus would tie
# every overlap query and make the winners nondeterministic. The dummy keeps the inventory
# non-empty (sanity) while sharing ZERO blocks with any overlap prompt (per-EP-unique text).
for ep_pair in "31.31.31.1:l3ep1" "33.33.33.1:l3ep3" "35.35.35.1:l3ep5"; do
    ep_ip="${ep_pair%%:*}"; ep_ns="${ep_pair##*:}"
    PUB_LOG="${CFGDIR}/.kvpub-baseline-${ep_ip}.log"
    BASELINE_CORPUS="${CFGDIR}/.kvpub-baseline-corpus-${ep_ip}.json"
    python3 -c "
import json,sys
ep=sys.argv[1]
p=('loxilb phase80 baseline warm sentinel for endpoint %s — this filler text exists only so the '
   'kv inventory is non-empty before validation begins and shares no block with the d05 corpus '
   'prompts: alpha bravo charlie delta echo foxtrot golf hotel india juliett kilo lima %s') % (ep, ep)
json.dump([{'prompt': p}], open(sys.argv[2],'w'))" "${ep_ip}" "${BASELINE_CORPUS}" 2>/dev/null \
        || echo "  WARN: could not write baseline corpus for ${ep_ip}"
    echo "Launching baseline publisher (corpus warm) in netns ${ep_ns} on ${ep_ip}:${KV_ZMQ_PORT} (tag=${PUB_TAG})..."
    # Anchored process tag so rmconfig.sh / validation.sh kill ONLY these publishers (never a host-wide sweep).
    setsid $hexec "${ep_ns}" bash -c "export PYTHONPATH='${PY_USER_SITE}' PYTHONHASHSEED=0; exec -a ${PUB_TAG} python3 '${PUBLISHER}' \
        --corpus '${BASELINE_CORPUS}' \
        --tokenizer '${TOKENIZER_SRC}' \
        --vectors '${VECTORS_SRC}' \
        --service-id 0 --bind ${ep_ip} --port ${KV_ZMQ_PORT} --algo ${KV_HASH_ALGO} \
        --block-size ${KV_BLOCK_SIZE} --repeat 4 --repeat-interval 6 --no-vocabulary" >"${PUB_LOG}" 2>&1 &
    echo "  baseline publisher launched in ${ep_ns} (pid=$!, log=${PUB_LOG})"
done

# Let the subscriber connect + the inventory converge before handing off to validation.sh.
# Connect happens within kvReconnectFailBackoff (5s) of the bind; the resident publisher
# (--repeat 4 --repeat-interval 6) re-emits at ~6s/12s/18s, so 15s guarantees >=1 full pass.
echo "Waiting ~15s for the KV subscriber to connect + ingest the baseline publish..."
sleep 15

# ── chaos-matrix EP/publisher wiring (consumed by validation.sh) ─────────────────────────────────────
# The chaos legs reuse the SAME three prefill EPs + the SAME anchored PUB_TAG (kill_publisher is
# PID-scoped by this tag) — no new containers. validation.sh derives the roles below from these tags:
#   CHAOS_EP_DOWN_IP  — the EP whose publisher is NEVER (re)bound for the down-at-startup leg
#                       (its inventory must read empty → that EP drops out of argmax → Tier-2).
#   CHAOS_EP_LIVE_IP  — the sibling that STAYS up for the partial-outage graceful-degradation leg.
# EP-C (idx 4) is the down candidate (it only ever holds the noncontiguous prompt in the healthy run,
# so emptying it is the least disruptive to the other legs); EP-A (idx 0) is the live sibling.
CHAOS_EP_DOWN_IP="35.35.35.1"   # EP-C / idx 4 — never republished in the down-at-startup leg
CHAOS_EP_LIVE_IP="31.31.31.1"   # EP-A / idx 0 — sibling kept serving in the partial-outage leg
export PUB_TAG CHAOS_EP_DOWN_IP CHAOS_EP_LIVE_IP KV_MAX_BLOCKS

echo "#########################################"
echo "Topology up: KV-exact P/D VIP ${VIP}:${VPORT} -> 3 prefill {serverP0,serverP1,serverP2} (idx 0/2/4)"
echo "             + 3 decode {serverD0,serverD1,serverD2} (idx 1/3/5)"
echo "             tokenizer ${TOKENIZER_SLUG} staged on llb1; publisher tag=${PUB_TAG} on :${KV_ZMQ_PORT}"
echo "             feature: kvExactMode=1 kvHashAlgo=${KV_HASH_ALGO} kvWarmupSec=${KV_WARMUP_SEC} kvBlockSize=${KV_BLOCK_SIZE}"
echo "#########################################"
