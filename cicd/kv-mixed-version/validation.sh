#!/bin/bash
# validation.sh — the seven §10.3 mixed-version cases (see README.md).
#
# Case order minimizes llb2 respawns (a registry stage or image change
# always means a respawn — the registry loads once at init):
#   phase A (llb2=OLD):        case 1, case 3, case 2
#   phase B (llb2=NEW diverg): case 4a (mismatch hold)
#   phase C (llb2=NEW corrupt): case 5
#   phase D (llb2=NEW full):   case 4b (converge -> READY, the eligible=1
#                              GPU-free positive), case 6 (failover), then
#   phase E (llb2=OLD again):  case 7 (post-downgrade bypass)
# Case 6 deliberately sacrifices llb1's data plane (docker stop/start kills
# veths) — llb1-dependent asserts never follow it.

source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
KVHASH="${CFGDIR}/../common/kv_hash"
code=0

# Image resolution mirrors config.sh (validation runs as a SIBLING process —
# config.sh's exports never reach it, so it must resolve from the same
# user-facing env vars itself).
NEW_IMAGE="${KV_MV_NEW_IMAGE:-${LOXILB_DOCKER_IMAGE:-kv-p6-ci}}"
OLD_IMAGE="${KV_MV_OLD_IMAGE:-${KV_OLD_IMAGE:-v0.9.8.9-rc.1-u24}}"
[[ "$NEW_IMAGE" != *"/"* && "$NEW_IMAGE" != *":"* ]] && NEW_IMAGE="ghcr.io/loxilb-io/loxilb-inference-gateway:$NEW_IMAGE"
[[ "$OLD_IMAGE" != *"/"* && "$OLD_IMAGE" != *":"* ]] && OLD_IMAGE="ghcr.io/loxilb-io/loxilb-inference-gateway:$OLD_IMAGE"

LB="netlox/v1/config/loadbalancer"
VIP1="10.10.10.254"   # llb1's strict rule VIP (client-facing)
VIP2="20.20.20.254"   # llb2's rule VIP
PORT=8080
MODEL="Qwen/Qwen3-0.6B"
PROF="qwen3-06b-completions-v1"
ENC_MODEL=$(python3 -c "import urllib.parse;print(urllib.parse.quote('${MODEL}',safe=''))")
CADENCE=5

EPS_LLB1='{ "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1, "ep_role": 1 }, { "endpointIP": "32.32.32.1", "targetPort": 80, "weight": 1, "ep_role": 2 }'
EPS_LLB2='{ "endpointIP": "61.61.61.1", "targetPort": 80, "weight": 1, "ep_role": 1 }, { "endpointIP": "62.62.62.1", "targetPort": 80, "weight": 1, "ep_role": 2 }'

chk() { # chk <label> <extended-regex> <value>
    local label="$1" want="$2" got="$3"
    if [[ "$got" =~ $want ]]; then
        echo "  [OK] $label"
    else
        echo "  [FAILED] $label — want /$want/ got '$got'"
        code=1
    fi
}

jfield() { echo "$1" | jq -r "$2" 2>/dev/null; }

# sim_pids: /proc-scan for the attestation simulators. External kill/pkill
# binaries are DISABLED stubs on the CI host — every signal must go through
# the shell BUILTIN kill against explicit pids, or the action silently
# no-ops (observed live: a "frozen" simulator kept answering probes and the
# standby stayed READY through the whole expiry leg).
sim_pids() {
    local d p
    for d in /proc/[0-9]*/cmdline; do
        if tr "\0" " " < "$d" 2>/dev/null | grep -q "vllm_attest_sim.py"; then
            p="${d#/proc/}"; echo "${p%/cmdline}"
        fi
    done
}
# NOTE: bare builtin kill — `sudo kill` execs the DISABLED /bin/kill stub
# (this exact no-op slipped through once: sudo'd "builtin" is no builtin).
sims_signal() { local s="$1" p; for p in $(sim_pids); do kill "-${s}" "$p" 2>/dev/null; done; }

# post_strict <node> <vip> <eps> -> "HTTPCODE|body". The SAME strict body
# shape goes to old and new nodes — the version skew in what each build
# does with it IS the subject under test.
post_strict() {
    local node="$1" vip="$2" eps="$3" body http
    body=$(cat <<JSON
{
  "serviceArguments": {
    "externalIP": "${vip}", "port": ${PORT}, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "${vip}",
    "pd_disagg_mode": true, "probeRetries": 1,
    "kvExactMode": 1, "kvZmqPort": 5557, "kvBlockSize": 16,
    "kvEngineType": "vllm", "model_name": "${MODEL}",
    "kvExactApiMode": "completions", "kvModelProfile": "${PROF}"
  },
  "endpoints": [ ${eps} ]
}
JSON
)
    http=$($hexec "$node" curl -s -m 10 -o /tmp/kvmv-resp.json -w "%{http_code}" \
        -X POST "http://localhost:11111/${LB}" -H 'Content-Type: application/json' -d "${body}")
    echo "${http}|$(tr -d '\n' < /tmp/kvmv-resp.json 2>/dev/null)"
}

# kvstatus <node> <vip> -> raw status JSON (empty/404 body passes through)
kvstatus() {
    $hexec "$1" curl -s -m 5 \
        "http://localhost:11111/${LB}/externalipaddress/$2/port/${PORT}/protocol/tcp/kvexactstatus"
}

kvstatus_http() {
    $hexec "$1" curl -s -m 5 -o /dev/null -w "%{http_code}" \
        "http://localhost:11111/${LB}/externalipaddress/$2/port/${PORT}/protocol/tcp/kvexactstatus"
}

# wait_enforced <node> <vip> <state-regex> <timeout-s> -> last enforcedState
wait_enforced() {
    local node="$1" vip="$2" want="$3" tmo="$4" st got=""
    local deadline=$((SECONDS + tmo))
    while (( SECONDS < deadline )); do
        st=$(kvstatus "$node" "$vip")
        got=$(jfield "$st" '.kvExactStatusAttr[0].enforcedState')
        [[ "$got" =~ $want ]] && { echo "$got"; return 0; }
        sleep 2
    done
    echo "$got"
}

# reason_codes <node> <vip> -> comma-joined reasonCodes
reason_codes() {
    jfield "$(kvstatus "$1" "$2")" '.kvExactStatusAttr[0].reasonCodes | join(",")'
}

# wait_reason <node> <vip> <substr> <timeout-s> -> last reasons string
wait_reason() {
    local node="$1" vip="$2" want="$3" tmo="$4" got=""
    local deadline=$((SECONDS + tmo))
    while (( SECONDS < deadline )); do
        got=$(reason_codes "$node" "$vip")
        [[ "$got" == *"$want"* ]] && { echo "$got"; return 0; }
        sleep 2
    done
    echo "$got"
}

# traffic <vip> -> HTTP code of a completions POST from the client through
# the given VIP (L7 rules need model + Host; a bare GET is no_route).
# Retries for up to ~20s: a freshly created rule's endpoint pool needs a
# health-probe cycle before the proxy serves — a transient 5xx during
# warmup is not the continuity verdict; a PERSISTENT one is.
traffic() {
    local code=""
    for _ in $(seq 1 10); do
        code=$($hexec l3h1 curl -s -m 8 -o /tmp/kvmv-traffic.json -w "%{http_code}" \
            -X POST "http://$1:${PORT}/v1/completions" -H "Host: $1" \
            -H 'Content-Type: application/json' \
            -d "{\"model\": \"${MODEL}\", \"prompt\": \"mixed version continuity probe\", \"max_tokens\": 1}")
        [[ "$code" == "200" ]] && break
        sleep 2
    done
    echo "$code"
}

# traffic_old <vip> -> verdict for continuity THROUGH AN OLD-RELEASE node.
# Old releases before the vhost find_endpoint_lpm fix cannot route
# vhost-keyed rules at all — they answer a deterministic
# 503 {"error":"model_unavailable"} for ANY model. That is the old build's
# own routing posture, not a version-skew regression: this suite's subject
# is the KV field skew, so the leg pins EXACTLY the known signature (or a
# real 200 on old builds that carry the fix) and stays red for anything
# novel (hang, crash, other 5xx, wrong body).
traffic_old() {
    local code; code=$(traffic "$1")
    if [[ "$code" == "200" ]]; then
        echo "200"
    elif [[ "$code" == "503" ]] && grep -q '"error":"model_unavailable"' /tmp/kvmv-traffic.json 2>/dev/null; then
        echo "known-f-rag-1-503"
    else
        echo "novel:$code:$(head -c 120 /tmp/kvmv-traffic.json 2>/dev/null)"
    fi
}

# llb2_respawn <image> <stage-dir> — teardown + fresh spawn of the peer with
# a different build/registry identity. The bridge IP must come back exactly
# where llb1's --cluster expects it.
llb2_respawn() {
    local image="$1" stage="$2"
    delete_docker_host llb2
    sleep 2
    # Scrub stale plumbing: a stopped container's netns OBJECT can survive
    # via the /var/run/netns bind-mount, keeping the old veth pairs (and the
    # peers' ends + addresses) alive — the next connect then fails with
    # "File exists" and the respawned node comes up with NO dataplane
    # (observed live: C4b standby stuck PENDING_DATAPLANE_CONTRACT with
    # dataplane_setter_failed). Delete the peer-side ends (kills the pair
    # wherever the other end lives) and drop any stale netns registration.
    for peer in l3h1 l3ep1 l3ep2; do
        sudo ip -n "$peer" link del "e${peer}llb2" 2>/dev/null
    done
    sudo umount /var/run/netns/llb2 2>/dev/null
    sudo rm -f /var/run/netns/llb2
    local LLB_ENV="-e LLB_KV_NONE_HASH_SEED=0 -e LOXILB_KV_ATTEST_PROBE_CADENCE_S=${CADENCE}"
    local LLB_TOK="-v ${CFGDIR}/.tokenizers-stage:/etc/loxilb/tokenizers:ro"
    lxdocker="$image"
    spawn_docker_host --dock-type loxilb --dock-name llb2 --with-ka in \
        --docker-args "${LLB_ENV} ${LLB_TOK} -v ${stage}:/etc/loxilb/kvprofiles:ro"
    lxdocker="$NEW_IMAGE"
    local wantip actual
    wantip=$(cat "${CFGDIR}/.llb2-bridge-ip")
    actual=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' llb2)
    if [[ "$actual" != "$wantip" ]]; then
        echo "  [FAILED] llb2 respawn bridge IP $actual != $wantip — peering dark, aborting"
        code=1
        exit $code
    fi
    connect_docker_hosts l3h1  llb2
    connect_docker_hosts l3ep1 llb2
    connect_docker_hosts l3ep2 llb2
    sleep 3
    config_docker_host --host1 l3h1  --host2 llb2 --ptype phy --addr 20.20.20.1/24
    config_docker_host --host1 l3ep1 --host2 llb2 --ptype phy --addr 61.61.61.1/24
    config_docker_host --host1 l3ep2 --host2 llb2 --ptype phy --addr 62.62.62.1/24
    config_docker_host --host1 llb2 --host2 l3h1  --ptype phy --addr 20.20.20.254/24
    config_docker_host --host1 llb2 --host2 l3ep1 --ptype phy --addr 61.61.61.254/24
    config_docker_host --host1 llb2 --host2 l3ep2 --ptype phy --addr 62.62.62.254/24
    $hexec l3ep1 ip route replace 20.20.20.0/24 via 61.61.61.254
    $hexec l3ep2 ip route replace 20.20.20.0/24 via 62.62.62.254
    # Loud plumbing verification — a silent connect failure must never let
    # legs run against a dataplane-less node again.
    for want in ellb2l3h1 ellb2l3ep1 ellb2l3ep2; do
        if ! sudo ip -n llb2 link show "$want" >/dev/null 2>&1; then
            echo "  [FAILED] respawned llb2 missing veth $want — aborting"
            code=1
            exit $code
        fi
    done
    if ! sudo ip -n llb2 -4 addr show | grep -q "20.20.20.254"; then
        echo "  [FAILED] respawned llb2 missing VIP-side address — aborting"
        code=1
        exit $code
    fi
    local ok=0
    for _ in $(seq 1 60); do
        rc=$($hexec llb2 curl -s -m 3 -o /dev/null -w "%{http_code}" "http://localhost:11111/${LB}/all" 2>/dev/null)
        [[ "$rc" == "200" ]] && { ok=1; break; }
        sleep 1
    done
    [[ "$ok" == 1 ]] || { echo "  [FAILED] respawned llb2 API never came up"; code=1; exit $code; }
}

#################################################################################
echo "=== Case 1: new-active / old-standby — strict holds, never READY ==="
#################################################################################
r=$(post_strict llb1 "$VIP1" "$EPS_LLB1")
chk "C1 strict POST to new active -> 200" '^200\|' "$r"

got=$(wait_enforced llb1 "$VIP1" '^ENGINE_HASH_ATTESTED$' 90)
chk "C1 rungs 1-2 earned through the simulator (ENGINE_HASH_ATTESTED)" \
    '^ENGINE_HASH_ATTESTED$' "$got"
reasons=$(wait_reason llb1 "$VIP1" "peer_capability_mismatch" 30)
chk "C1 hold reason is the peer gate (peer_capability_mismatch)" \
    'peer_capability_mismatch' "$reasons"

sleep $((3 * CADENCE))
st=$(kvstatus llb1 "$VIP1")
chk "C1 still held after 3 cadences (never READY)" '^ENGINE_HASH_ATTESTED$' \
    "$(jfield "$st" '.kvExactStatusAttr[0].enforcedState')"
# (goFenced is the Go bridge deny-set — it lifts on the contract-install
# ACK by design; exact ELIGIBILITY is the READY state itself, asserted
# above. The admission suite's W leg pins the fence/ACK semantics.)
chk "C1 Tier-2 continuity: completions through new active -> 200" '^200$' "$(traffic "$VIP1")"

#################################################################################
echo "=== Case 3: the old peer's refusal is RPC-level (peer_incapable) ==="
#################################################################################
# Distinct from a digest mismatch: the old build answers gRPC Unimplemented
# / net-rpc method-not-found, and THAT (not any comparison) must be the
# recorded mechanism.
chk "C3 reasonCodes carry peer_incapable (RPC prohibition, not a digest diff)" \
    'peer_incapable' "$(reason_codes llb1 "$VIP1")"
chk "C3 no digest-comparison reason present against an incapable peer" '^0$' \
    "$(reason_codes llb1 "$VIP1" | grep -c 'digest_mismatch')"

#################################################################################
echo "=== Case 2: old-active / new-standby — strict body lands LEGACY ==="
#################################################################################
r=$(post_strict llb2 "$VIP2" "$EPS_LLB2")
chk "C2 strict POST to old active -> 200 (unknown fields dropped)" '^200\|' "$r"
lbdump=$($hexec llb2 curl -s -m 5 "http://localhost:11111/${LB}/all")
prof=$(echo "$lbdump" | jq -r ".lbAttr[]? | select(.serviceArguments.externalIP==\"${VIP2}\") | .serviceArguments.kvModelProfile // \"ABSENT\"")
chk "C2 old build kept no kvModelProfile (rule is legacy)" '^ABSENT$' "$prof"
chk "C2 old build makes no strict status claims (no sub-resource)" '^404$' \
    "$(kvstatus_http llb2 "$VIP2")"
chk "C2 Tier-2 continuity: old active answers deterministically (200 or its own known vhost-503)" \
    '^(200|known-f-rag-1-503)$' "$(traffic_old "$VIP2")"

#################################################################################
echo "=== Case 4a: both new, DIVERGENT profile sets — digest mismatch hold ==="
#################################################################################
llb2_respawn "$NEW_IMAGE" "${CFGDIR}/.stage-divergent"
reasons=$(wait_reason llb1 "$VIP1" "profile_set_digest_mismatch" $((6 * CADENCE)))
chk "C4a hold reason names the divergence (profile_set_digest_mismatch)" \
    'profile_set_digest_mismatch' "$reasons"
chk "C4a still ENGINE_HASH_ATTESTED, never READY" '^ENGINE_HASH_ATTESTED$' \
    "$(jfield "$(kvstatus llb1 "$VIP1")" '.kvExactStatusAttr[0].enforcedState')"

#################################################################################
echo "=== Case 5: standby artifact corrupt — refuses publish, cluster holds ==="
#################################################################################
llb2_respawn "$NEW_IMAGE" "${CFGDIR}/.stage-corrupt"
r=$(post_strict llb2 "$VIP2" "$EPS_LLB2")
chk "C5 corrupt-registry node refuses its own strict POST (400)" '^400\|' "$r"
reasons=$(wait_reason llb1 "$VIP1" "profile_set_digest_mismatch" $((6 * CADENCE)))
chk "C5 active holds against the artifact-less peer (profile_set_digest_mismatch)" \
    'profile_set_digest_mismatch' "$reasons"
chk "C5 active never READY" '^ENGINE_HASH_ATTESTED$' \
    "$(jfield "$(kvstatus llb1 "$VIP1")" '.kvExactStatusAttr[0].enforcedState')"

#################################################################################
echo "=== Case 4b: converge digests — READY, eligible=1 flips GPU-free ==="
#################################################################################
llb2_respawn "$NEW_IMAGE" "${CFGDIR}/.stage-full"
r=$(post_strict llb2 "$VIP2" "$EPS_LLB2")
chk "C4b strict POST to converged standby -> 200" '^200\|' "$r"

got=$(wait_enforced llb1 "$VIP1" '^READY$' 120)
chk "C4b ACTIVE rule earns READY once the cluster converges" '^READY$' "$got"
st=$(kvstatus llb1 "$VIP1")
chk "C4b eligible=1: exact fence LIFTED (goFenced=false)" '^false$' \
    "$(jfield "$st" '.kvExactStatusAttr[0].enforcement.goFenced')"
ack1=$(jfield "$st" '.kvExactStatusAttr[0].enforcement.lastAckAt')
chk "C4b READY is ACKed by the data plane (lastAckAt set)" '^..*$' \
    "$([[ -n "$ack1" && "$ack1" != "null" ]] && echo "$ack1")"

got=$(wait_enforced llb2 "$VIP2" '^READY$' 120)
chk "C4b standby's own rule also earns READY (own ladder, own receipts)" '^READY$' "$got"
chk "C4b traffic through READY active -> 200" '^200$' "$(traffic "$VIP1")"

#################################################################################
echo "=== Case 6: attestation expires right before failover — re-earn, never inherit ==="
#################################################################################
ack2_before=$(jfield "$(kvstatus llb2 "$VIP2")" '.kvExactStatusAttr[0].enforcement.lastAckAt')

# Expire attestation on BOTH nodes: freeze the simulators so probes fail
# and receipts go stale. The fence lands after the next cadence tick PLUS
# the probes' own client timeouts against the frozen sims — poll for it
# rather than assuming a fixed delay.
sims_signal STOP
expired=""
for _ in $(seq 1 30); do
    expired=$(jfield "$(kvstatus llb2 "$VIP2")" '.kvExactStatusAttr[0].enforcedState')
    [[ -n "$expired" && "$expired" != "READY" ]] && break
    sleep 3
done
chk "C6 pre-failover: standby's attestation expired (not READY)" \
    '^(ENGINE_HASH_ATTESTED|TOKEN_PARITY_VERIFIED|PROFILE_VALIDATED|DEGRADED|DEGRADING|ENFORCEMENT_FAULT)$' \
    "$expired"

# Failover: the active goes dark entirely.
docker stop llb1 >/dev/null
sleep 5
sims_signal CONT

# The survivor re-earns rungs 1-2 through its own probes but holds
# fail-closed at the peer gate — the configured peer is dark, and READY was
# never inherited from anyone.
got=$(wait_enforced llb2 "$VIP2" '^ENGINE_HASH_ATTESTED$' 90)
chk "C6 survivor re-earns rungs 1-2 (ENGINE_HASH_ATTESTED)" '^ENGINE_HASH_ATTESTED$' "$got"
reasons=$(wait_reason llb2 "$VIP2" "peer_incapable" 30)
chk "C6 survivor holds fail-closed while the peer is dark (peer_incapable)" \
    'peer_incapable' "$reasons"
sleep $((3 * CADENCE))
chk "C6 survivor never claims READY solo" '^ENGINE_HASH_ATTESTED$' \
    "$(jfield "$(kvstatus llb2 "$VIP2")" '.kvExactStatusAttr[0].enforcedState')"
chk "C6 Tier-2 continuity through the new master -> 200" '^200$' "$(traffic "$VIP2")"

# Peer recovery: restart llb1's container + process (its veths are dead —
# that sacrifices only ITS data plane; the capability answer is what the
# survivor's gate needs). Fresh state = no rules = no binding to echo:
# the survivor must STILL hold (binding_not_converged_on_peer) until the
# operator re-applies config on the recovered node.
docker start llb1 >/dev/null
sleep 3
# Re-register llb1's netns handle: the /var/run/netns bind-mount still
# points at the STOPPED container's dead namespace — every $hexec llb1
# would silently run in a stale ns without this.
sudo umount /var/run/netns/llb1 2>/dev/null
sudo rm -f /var/run/netns/llb1
llb1pid=$(docker inspect --format '{{.State.Pid}}' llb1)
sudo touch /var/run/netns/llb1
sudo mount -o bind "/proc/${llb1pid}/ns/net" /var/run/netns/llb1
get_llb_peerIP llb1
docker exec -dt llb1 /root/loxilb-io/loxilb/loxilb $cluster_opts $ka_opts
ok=0
for _ in $(seq 1 60); do
    rc=$($hexec llb1 curl -s -m 3 -o /dev/null -w "%{http_code}" "http://localhost:11111/${LB}/all" 2>/dev/null)
    [[ "$rc" == "200" ]] && { ok=1; break; }
    sleep 1
done
chk "C6 recovered peer API up" '^1$' "$ok"

# The restarted container REPLAYS its own write-through snapshot at boot:
# the strict rule (profile attached) restores itself, which re-registers
# the composed binding — cluster convergence needs no operator re-apply.
# The 409 on a config replay is the receipt that the self-restore happened
# (an empty-state peer would answer 200 and, until it knew the binding,
# hold the survivor at binding_not_converged_on_peer — that window is not
# reliably observable here, so the replay receipt is the assert).
# The boot gate refuses config writes (503 "Maintenance mode") until the
# snapshot replay settles — poll through it; the settled answer for a
# replayed rule is the 409 receipt.
r=""
for _ in $(seq 1 30); do
    r=$(post_strict llb1 "$VIP1" "$EPS_LLB1")
    [[ "$r" == *"Maintenance mode"* ]] || break
    sleep 2
done
chk "C6 recovered peer self-restored its config (replay 409 receipt)" '^409\|' "$r"
prof_re=""
for _ in $(seq 1 15); do
    prof_re=$(jfield "$(kvstatus llb1 "$VIP1")" '.kvExactStatusAttr[0].modelProfileId')
    [[ "$prof_re" == "$PROF" ]] && break
    sleep 2
done
chk "C6 self-restored rule kept its profile binding" "^${PROF}\$" "$prof_re"
got=$(wait_enforced llb2 "$VIP2" '^READY$' 120)
chk "C6 survivor re-earns READY only after full cluster convergence" '^READY$' "$got"
ack2_after=$(jfield "$(kvstatus llb2 "$VIP2")" '.kvExactStatusAttr[0].enforcement.lastAckAt')
chk "C6 READY rides FRESH receipts (lastAckAt advanced, nothing inherited)" '^1$' \
    "$([[ -n "$ack2_after" && "$ack2_after" != "null" && "$ack2_after" != "$ack2_before" ]] && echo 1 || echo 0)"

#################################################################################
echo "=== Case 7: post-downgrade bypass — same config, old build, zero claims ==="
#################################################################################
llb2_respawn "$OLD_IMAGE" "${CFGDIR}/.stage-full"
r=$(post_strict llb2 "$VIP2" "$EPS_LLB2")
chk "C7 config replay on downgraded node -> 200" '^200\|' "$r"
lbdump=$($hexec llb2 curl -s -m 5 "http://localhost:11111/${LB}/all")
prof=$(echo "$lbdump" | jq -r ".lbAttr[]? | select(.serviceArguments.externalIP==\"${VIP2}\") | .serviceArguments.kvModelProfile // \"ABSENT\"")
chk "C7 downgraded build dropped the profile binding (legacy rule)" '^ABSENT$' "$prof"
chk "C7 downgraded build claims NO strict status (404)" '^404$' \
    "$(kvstatus_http llb2 "$VIP2")"
chk "C7 Tier-2 continuity: downgraded node answers deterministically (200 or its own known vhost-503)" \
    '^(200|known-f-rag-1-503)$' "$(traffic_old "$VIP2")"

#################################################################################
echo "==============================================================="
if [[ $code -eq 0 ]]; then
    echo "kv-mixed-version: ALL CASES PASSED"
else
    echo "kv-mixed-version: FAILURES PRESENT"
fi
exit $code
