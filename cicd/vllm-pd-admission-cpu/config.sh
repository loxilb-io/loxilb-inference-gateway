#!/bin/bash
# config.sh — P/D bounded-admission topology (GPU-free, mock P/D bed).
#
# Stands up a plain P/D disaggregation service over 6 reflect-echo EPs and arms the
# bounded-admission layer, which is the ONLY way its three counter families can be
# driven at all. Both knobs are process-env and read getenv-once at start
# (pd_max_inflight_per_ep / pd_queue_depth_per_ep, sockproxy_pd.c), so they cannot be
# toggled on a live gateway the way a per-rule field can — the fixture IS the gateway
# process, and that is why this scenario exists separately from
# vllm-kvcache-routing-cpu rather than as more stages inside it.
#
#   LLB_PD_MAX_INFLIGHT_PER_EP  (ADM_CAP)          per-EP in-flight prefill cap; 0 = layer off
#   LLB_PD_QUEUE_DEPTH_PER_EP   (ADM_QUEUE_DEPTH)  parked-FIFO depth;            0 = hold-don't-drop off
#
# ── why this is a SEPARATE scenario, and why it is configured TWICE ────────────────
#
# The three admission families are MUTUALLY EXCLUSIVE within one gateway process.
# The all-capped branch (sockproxy_pd.c) reads:
#
#     if (healthy_elig > 0 && under_cap == 0) {
#       depth = pd_queue_depth_per_ep();
#       if (depth == 0) { pd_admission_shed_total++;  return NO_CAPACITY; }   // site A
#       ... park ...    { pd_admission_queued_total++; return PARKED; }        // site B
#                         pd_admission_overflow_shed_total++;                  // site C
#
# Site A is reachable ONLY at depth 0; sites B and C ONLY at depth > 0. No single env
# configuration can drive all three, so validation.sh runs TWO gateway lifecycles and
# re-invokes this script between them. That mutual exclusion is itself asserted rather
# than assumed: each phase asserts the OTHER phase's sites stayed at zero, which is the
# attribution oracle for a family whose delta would otherwise be indistinguishable.
#
# It is also why arming these knobs in vllm-kvcache-routing-cpu/config.sh was rejected:
# that scenario's HOL stage drives 12 CONCURRENT shared-prefix requests, cache affinity
# lands them on one prefill EP owner, and any cap low enough to be drivable here sheds
# most of them as 429. Because that stage scores p99 LATENCY and a 429 returns fast, it
# would have kept passing while measuring nothing — a vacuous oracle, not a red gate.
#
# Topology (6 EPs = 3 prefill + 3 decode, prefill at NON-ADJACENT absolute indices so the
# prefill set is a non-contiguous bitmask, matching vllm-kvcache-routing-cpu):
#
#   llb1   — loxilb (control plane + eBPF dataplane), REST on localhost:11111 (auth-off, CICD mode)
#   l3h1   — client host
#   l3ep1  — reflect-echo backend  31.31.31.1  ECHO_NAME=serverP0  PREFILL  (abs idx 0)  ep_role=1
#   l3ep2  — reflect-echo backend  32.32.32.1  ECHO_NAME=serverD0  DECODE   (abs idx 1)  ep_role=2
#   l3ep3  — reflect-echo backend  33.33.33.1  ECHO_NAME=serverP1  PREFILL  (abs idx 2)  ep_role=1
#   l3ep4  — reflect-echo backend  34.34.34.1  ECHO_NAME=serverD1  DECODE   (abs idx 3)  ep_role=2
#   l3ep5  — reflect-echo backend  35.35.35.1  ECHO_NAME=serverP2  PREFILL  (abs idx 4)  ep_role=1
#   l3ep6  — reflect-echo backend  36.36.36.1  ECHO_NAME=serverD2  DECODE   (abs idx 5)  ep_role=2
#
# The EP netns names and the :80 listener are load-bearing: validation.sh holds prefill
# EPs in-flight with ../vllm-kvcache-routing-cpu/pd-fault-swap.sh, which REDIRECTs :80 to
# a hanging stub inside the EP netns. Cross-scenario asset reuse is the established idiom
# here (see sglang-loxilb-kvcache/config.sh, which sources this repo's kv_event_publisher.py
# the same way) and keeps a single copy of the fault machinery.
#
# Run on the REMOTE testbed (Docker + ip netns are NOT available on macOS):
#   sudo ./config.sh && sudo ./validation.sh ; ./rmconfig.sh
# macOS only validates `bash -n` + `shellcheck -S error`.

# No host-side port publish: REST is driven via $hexec (in-netns curl); resident
# --net=host loxilb hosts own 8091/11111.
export LLB_HOST_PORTS=""
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"

# Idempotency: a prior (interactive/aborted) run leaves the topology + llb1 counters
# behind, and spawn_docker_host silently no-ops on existing names — validation would then
# run against STALE state. Always self-clean first; rmconfig is scoped to this scenario.
"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true

# ── the admission fixture ─────────────────────────────────────────────────────────────
# ADM_CAP=1 is the smallest cap that still exercises the real exclusion loop, and it makes
# the drive cheap: filling the pool needs exactly one in-flight request per prefill EP
# (3 holders) instead of cap*3. ADM_QUEUE_DEPTH defaults to 0 = phase A (plain shed);
# validation.sh re-invokes this script with ADM_QUEUE_DEPTH=2 for phase B.
#
# Depth 2 (not 1) is deliberate: at depth 1 the FIFO fills on the first parked request per
# EP, so "parked" and "overflowed" would be one request apart on every EP and a drive that
# was off by one would still land in the branch it was aiming for. At depth 2 the park
# capacity is 3 EPs x 2 = 6, so phase B can assert an exact SIX parks before the first
# overflow — a prediction a one-request error cannot satisfy.
ADM_CAP="${ADM_CAP:-1}"
ADM_QUEUE_DEPTH="${ADM_QUEUE_DEPTH:-0}"
export ADM_CAP ADM_QUEUE_DEPTH

echo "#########################################"
echo "P/D admission fixture: cap=${ADM_CAP} queue_depth=${ADM_QUEUE_DEPTH}"
echo "#########################################"

echo "#########################################"
echo "Building the reflect-echo backend image (ghcr.io/loxilb-io/reflect-echo:latest)"
echo "#########################################"
# The `reflect-echo` dock-type (cicd/common.sh) runs a NET-NEW image built locally from the
# shared cicd/common/reflect-echo context — it is NOT pulled. Idempotent: layers are re-used.
"${CFGDIR}/../common/reflect-echo/docker-build.sh"

echo "#########################################"
echo "Spawning all hosts (6 EPs = 3 prefill + 3 decode, non-adjacent prefill indices)"
echo "#########################################"

# The two admission knobs are injected HERE because they are read getenv-once at process
# start. Re-reading them later, or POSTing a rule field, cannot change them — recreating
# this container is the only way, which is exactly what validation.sh does between phases.
spawn_docker_host --dock-type loxilb --dock-name llb1 \
    --docker-args "-e LLB_PD_MAX_INFLIGHT_PER_EP=${ADM_CAP} -e LLB_PD_QUEUE_DEPTH_PER_EP=${ADM_QUEUE_DEPTH}"
spawn_docker_host --dock-type host   --dock-name l3h1
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

# ── REST readiness poll: REST on :11111 comes up only AFTER the eBPF load (10-20s).
#    Poll to HTTP 200 BEFORE any POST so the seed is not silently dropped (a POST racing
#    the eBPF load returns HTTP 000, which is a failed spawn and not a gateway answer).
LBBASE="http://localhost:11111/netlox/v1/config/loadbalancer"
echo "Waiting for loxilb REST API (localhost:11111) to be ready..."
api_ready=0
for _ in $(seq 1 40); do
    rc=$($hexec llb1 curl -s -m 3 -o /dev/null -w "%{http_code}" "${LBBASE}/all" 2>/dev/null)
    if [[ "$rc" == "200" ]]; then
        api_ready=1; echo "  loxilb REST API ready (HTTP ${rc})"; break
    fi
    sleep 1
done
[[ "$api_ready" == 1 ]] || { echo "  FATAL: loxilb REST API not ready after 40s"; exit 1; }

# ── Seed the P/D service ───────────────────────────────────────────────────────────────
# Plain pd_disagg (no kvExactMode): the admission gate sits in pd_select_prefill ABOVE
# every tier, so it fires regardless of which tier would have chosen the EP. Leaving
# KV-exact off keeps the fixture free of the ZMQ publisher and tokenizer staging, and
# removes an unrelated failure surface from a scenario whose subject is admission.
#
# No "host"/"model_name": those are required only for kvExactMode, and a rule carrying
# them needs the /hosturl/{host} delete key rather than the plain path — an avoidable
# sharp edge in a fixture that is recreated on every phase.
VIP="10.10.10.254"
VPORT=8080
read -r -d '' SEED_PDRULE <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}",
    "port": ${VPORT},
    "protocol": "tcp",
    "sel": 0,
    "mode": 4,
    "pd_disagg_mode": true,
    "probeRetries": 1
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

echo "Seeding P/D service ${VIP}:${VPORT} (3 prefill + 3 decode)..."
seed_rc=$($hexec llb1 curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${LBBASE}" -H 'Content-Type: application/json' -d "${SEED_PDRULE}")
echo "  POST /config/loadbalancer (P/D rule) -> HTTP ${seed_rc}"
# An empty code is a failed curl SPAWN, never a gateway answer — fail loudly rather than
# letting validation.sh discover a rule-less VIP as a product defect.
[[ "$seed_rc" == "200" ]] || { echo "  FATAL: P/D rule seed answered '${seed_rc}' (expected 200)"; exit 1; }

sleep 3

# Prove the rule is actually serving before handing over: a seeded-but-unprobed rule
# answers nothing, and validation.sh would read that as an admission shed.
echo "Waiting for the VIP to serve..."
vip_ok=0
for _ in $(seq 1 30); do
    vrc=$($hexec l3h1 curl -s -m 5 -o /dev/null -w "%{http_code}" \
        -X POST "http://${VIP}:${VPORT}/v1/completions" \
        -H 'Content-Type: application/json' \
        -d '{"model":"mock","prompt":"warmup","max_tokens":4}' 2>/dev/null)
    if [[ "$vrc" == "200" ]]; then vip_ok=1; echo "  VIP serving (HTTP 200)"; break; fi
    sleep 2
done
[[ "$vip_ok" == 1 ]] || { echo "  FATAL: VIP ${VIP}:${VPORT} never served a 200"; exit 1; }

echo "#########################################"
echo "vllm-pd-admission-cpu config done (cap=${ADM_CAP} queue_depth=${ADM_QUEUE_DEPTH})"
echo "#########################################"
