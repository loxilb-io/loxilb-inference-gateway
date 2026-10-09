#!/bin/bash
# config.sh — security features × KV-cache-aware routing coexistence testbed.
#
# The routing half is the vllm-kvcache-routing-cpu topology (6 reflect-echo EPs, one fullproxy
# P/D service with kvExactMode=1 fed by the synthetic ZMQ publisher), reused as-is so every
# routing assertion here (Tier-1.5 hit, banner) is the one that scenario already proves. On top
# of it this scenario adds what the security half needs:
#
#   l3h1   10.10.10.1   the ALLOWED client (every KV routing probe comes from here)
#   l3h2   11.11.11.2   the OTHER client: blacklisted / rate-limited / fenced out in turn
#   -p                  the prometheus collector, so /metrics carries the XDP security series
#
# The security features themselves (ipfilter, securityrate, allowedSources, connectionLimit,
# api_key_auth) are switched on and off BY validation.sh, one at a time, so each check has a
# clean before/after; the topology stays constant.
#
# Run on a Linux testbed: sudo ./config.sh && sudo ./validation.sh ; ./rmconfig.sh
# Design: docs/security/ddos-and-admission-fullproxy.md; check matrix: README.md
export LLB_HOST_PORTS=""
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
KVCPU="${CFGDIR}/../vllm-kvcache-routing-cpu"

"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true

TOKENIZER_SLUG="Qwen__Qwen3-0.6B"
TOKENIZER_SRC="${CFGDIR}/../common/kv_hash/fixtures/tokenizers/${TOKENIZER_SLUG}/tokenizer.json"
VECTORS_SRC="${CFGDIR}/../common/kv_hash/fixtures/kv_hash_vectors.json"
PUBLISHER="${KVCPU}/kv_event_publisher.py"

KV_ZMQ_PORT=5557
KV_HASH_ALGO="sha256_cbor"
KV_WARMUP_SEC=20
KV_BLOCK_SIZE=16
KV_MODEL="${KV_MODEL:-Qwen/Qwen3-0.6B}"
export KV_MODEL

# Prometheus collector on: the ipfilter / securityrate / firewall series are what the XDP
# and TC halves of the checks read.
extra_opts="-p"

echo "#########################################"
echo "Building the reflect-echo backend image"
echo "#########################################"
"${CFGDIR}/../common/reflect-echo/docker-build.sh"

echo "#########################################"
echo "Spawning hosts (llb1, 2 clients, 3 prefill + 3 decode reflect-echo EPs)"
echo "#########################################"
# LLB_KV_NONE_HASH_SEED=0 aligns the C request-side block chaining with the publisher
# (see vllm-kvcache-routing-cpu/config.sh for the full reasoning). XDP_NATIVE, when set
# by the caller, asks for native (driver) XDP on the listed interfaces (check C10).
LLB_XDP_ARGS=""
if [[ -n "${XDP_NATIVE:-}" ]]; then
    LLB_XDP_ARGS="--xdp-native ${XDP_NATIVE}"
fi
spawn_docker_host --dock-type loxilb --dock-name llb1 --docker-args "-e LLB_KV_NONE_HASH_SEED=0 -e LLB_KV_HASH_DEBUG=1" --extra-args "${LLB_XDP_ARGS}"
spawn_docker_host --dock-type host   --dock-name l3h1
spawn_docker_host --dock-type host   --dock-name l3h2
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
connect_docker_hosts l3h2  llb1
for ep in l3ep1 l3ep2 l3ep3 l3ep4 l3ep5 l3ep6; do connect_docker_hosts $ep llb1; done
sleep 5

# l3h1 sits on the VIP's own segment (10.10.10.254 is llb1's address on that link — the
# fullproxy bind requirement). l3h2 sits on a second leaf link in its own subnet and reaches
# the VIP through llb1 like the backends do: the only thing that tells the two clients apart
# at XDP/TC is the source address, which is exactly what the ACL checks key on.
config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3h2  --host2 llb1 --ptype phy --addr 11.11.11.2/24 --gw 11.11.11.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 l3ep3 --host2 llb1 --ptype phy --addr 33.33.33.1/24 --gw 33.33.33.254
config_docker_host --host1 l3ep4 --host2 llb1 --ptype phy --addr 34.34.34.1/24 --gw 34.34.34.254
config_docker_host --host1 l3ep5 --host2 llb1 --ptype phy --addr 35.35.35.1/24 --gw 35.35.35.254
config_docker_host --host1 l3ep6 --host2 llb1 --ptype phy --addr 36.36.36.1/24 --gw 36.36.36.254
config_docker_host --host1 llb1 --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3h2  --ptype phy --addr 11.11.11.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb1 --host2 l3ep3 --ptype phy --addr 33.33.33.254/24
config_docker_host --host1 llb1 --host2 l3ep4 --ptype phy --addr 34.34.34.254/24
config_docker_host --host1 llb1 --host2 l3ep5 --ptype phy --addr 35.35.35.254/24
config_docker_host --host1 llb1 --host2 l3ep6 --ptype phy --addr 36.36.36.254/24
sleep 5

echo "Staging tokenizer.json (${TOKENIZER_SLUG}) + golden vectors into llb1..."
docker exec llb1 mkdir -p "/etc/loxilb/tokenizers/${TOKENIZER_SLUG}" >/dev/null 2>&1 || true
docker cp "${TOKENIZER_SRC}" "llb1:/etc/loxilb/tokenizers/${TOKENIZER_SLUG}/tokenizer.json" 2>/dev/null \
    || echo "  WARN: docker cp tokenizer.json failed"
docker cp "${VECTORS_SRC}" "llb1:/etc/loxilb/tokenizers/kv_hash_vectors.json" 2>/dev/null || true

LBBASE="http://localhost:11111/netlox/v1/config/loadbalancer"
echo "Waiting for loxilb REST API..."
for _ in $(seq 1 40); do
    rc=$($hexec llb1 curl -s -m 3 -o /dev/null -w "%{http_code}" "${LBBASE}/all" 2>/dev/null)
    [[ "$rc" == "200" ]] && { echo "  REST ready"; break; }
    sleep 1
done

VIP="10.10.10.254"
VPORT=8080
# The ONE rule every check routes through. validation.sh replaces it (same key) to switch
# allowedSources / connectionLimit / api_key_auth / fc_* on and off; the endpoints and the
# KV contract never change, so the inventory the publisher built stays valid across replaces.
seed_rule_json() {   # seed_rule_json <extra service-args JSON fragment, may be empty>
    local extra="$1"
    [[ -n "$extra" ]] && extra="${extra},"
    cat <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}", "port": ${VPORT}, "protocol": "tcp", "sel": 0, "mode": 4,
    "host": "${VIP}", "model_name": "${KV_MODEL}",
    ${extra}
    "pd_disagg_mode": true, "probeRetries": 1,
    "kvExactMode": 1, "kvZmqPort": ${KV_ZMQ_PORT}, "kvHashAlgo": "${KV_HASH_ALGO}",
    "kvWarmupSec": ${KV_WARMUP_SEC}, "kvBlockSize": ${KV_BLOCK_SIZE}
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
}
echo "Seeding KV-exact P/D service ${VIP}:${VPORT}..."
$hexec llb1 curl -s -o /dev/null -w "  POST /config/loadbalancer -> HTTP %{http_code}\n" \
    -X POST "${LBBASE}" -H 'Content-Type: application/json' -d "$(seed_rule_json "")"
sleep 3

echo "Probing publisher python deps (pyzmq/cbor2/xxhash/transformers)..."
if ! python3 -c "import zmq, cbor2, xxhash, transformers" >/dev/null 2>&1; then
    python3 -m pip install --quiet pyzmq cbor2 xxhash transformers >/dev/null 2>&1 \
        || python3 -m pip install --quiet --break-system-packages pyzmq cbor2 xxhash transformers >/dev/null 2>&1 \
        || echo "  WARN: pip install of publisher deps failed"
fi

PUB_TAG="kvpubsec"
PY_USER_SITE="$(python3 -m site --user-site 2>/dev/null || echo '')"
for ep_pair in "31.31.31.1:l3ep1" "33.33.33.1:l3ep3" "35.35.35.1:l3ep5"; do
    ep_ip="${ep_pair%%:*}"; ep_ns="${ep_pair##*:}"
    PUB_LOG="${CFGDIR}/.kvpub-baseline-${ep_ip}.log"
    BASELINE_CORPUS="${CFGDIR}/.kvpub-baseline-corpus-${ep_ip}.json"
    python3 -c "
import json,sys
ep=sys.argv[1]
p=('loxilb security-kv-coexist baseline warm sentinel for endpoint %s — filler so the kv '
   'inventory is non-empty before validation begins: alpha bravo charlie delta echo foxtrot '
   'golf hotel india juliett kilo lima %s') % (ep, ep)
json.dump([{'prompt': p}], open(sys.argv[2],'w'))" "${ep_ip}" "${BASELINE_CORPUS}" 2>/dev/null
    echo "Launching baseline publisher in ${ep_ns} on ${ep_ip}:${KV_ZMQ_PORT} (tag=${PUB_TAG})..."
    setsid $hexec "${ep_ns}" bash -c "export PYTHONPATH='${PY_USER_SITE}' PYTHONHASHSEED=0; exec -a ${PUB_TAG} python3 '${PUBLISHER}' \
        --corpus '${BASELINE_CORPUS}' --tokenizer '${TOKENIZER_SRC}' --vectors '${VECTORS_SRC}' \
        --service-id 0 --bind ${ep_ip} --port ${KV_ZMQ_PORT} --algo ${KV_HASH_ALGO} \
        --block-size ${KV_BLOCK_SIZE} --repeat 4 --repeat-interval 6 --no-vocabulary" >"${PUB_LOG}" 2>&1 &
done
echo "Waiting ~15s for the KV subscriber to connect + ingest the baseline publish..."
sleep 15

export PUB_TAG
echo "#########################################"
echo "Topology up: KV-exact P/D VIP ${VIP}:${VPORT}; clients l3h1 (allowed) / l3h2 (other)"
echo "             prometheus on (-p); XDP native: ${XDP_NATIVE:-off (generic)}"
echo "#########################################"
