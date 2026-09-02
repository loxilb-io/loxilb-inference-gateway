#!/bin/bash
# config.sh — kv-mixed-version two-node topology (GPU-free).
#
# llb1 (NEW image, fixed for the whole run) + llb2 (image varies per case —
# validation.sh respawns it via llb2_respawn) + 1 client + 2 endpoint
# containers whose netns run the contract-faithful vLLM attestation
# simulator (host python, cicd/common/kv_hash/vllm_attest_sim.py). The
# simulator self-test gates this config: a dishonest simulator would turn
# the hold-state legs green for the wrong reason.
#
# Registry stages (host-side, root-owned, mounted RO before spawn — the
# registry loads ONCE at init, so a stage change always means a respawn):
#   .stage-full     profiles + artifacts + manifests + probefixtures (llb1,
#                   and llb2 in the converged/failover phases)
#   .stage-divergent  same minus the second profile (different set digest)
#   .stage-corrupt  artifact bytes flipped (secure loader refuses ⇒ the
#                   node publishes NO profile generation)

export LLB_HOST_PORTS=""
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
KVHASH="${CFGDIR}/../common/kv_hash"

NEW_IMAGE="${LOXILB_DOCKER_IMAGE:-kv-p6-ci}"
OLD_IMAGE="${KV_OLD_IMAGE:-v0.9.8.9-rc.1-u24}"
# Normalize bare tags the way common.sh does.
[[ "$NEW_IMAGE" != *"/"* && "$NEW_IMAGE" != *":"* ]] && NEW_IMAGE="ghcr.io/loxilb-io/loxilb-inference-gateway:$NEW_IMAGE"
[[ "$OLD_IMAGE" != *"/"* && "$OLD_IMAGE" != *":"* ]] && OLD_IMAGE="ghcr.io/loxilb-io/loxilb-inference-gateway:$OLD_IMAGE"
export KV_MV_NEW_IMAGE="$NEW_IMAGE"
export KV_MV_OLD_IMAGE="$OLD_IMAGE"

# Idempotency: always self-clean a prior aborted run first.
"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true

TOK_A_SLUG="Qwen__Qwen3-0.6B"
TOK_A_SRC="${KVHASH}/fixtures/tokenizers/${TOK_A_SLUG}/tokenizer.json"
TOK_B_SLUG="Qwen__Qwen2.5-7B-Instruct"
TOK_B_SRC="${KVHASH}/fixtures/tokenizers/${TOK_B_SLUG}/tokenizer.json"
PROFILE_ID="qwen3-06b-completions-v1"
PROBE_FIX_SRC="${KVHASH}/fixtures/probefixtures/${PROFILE_ID}"

for f in "${TOK_A_SRC}" "${TOK_B_SRC}" "${PROBE_FIX_SRC}/basic-ascii.request.json"; do
    [[ -f "$f" ]] || { echo "FATAL: committed fixture missing: $f"; exit 1; }
done

echo "#########################################"
echo "Gate: simulator self-test (honesty proof)"
echo "#########################################"
if ! python3 "${KVHASH}/vllm_attest_sim_selftest.py" > /tmp/kvmv-sim-selftest.log 2>&1; then
    echo "FATAL: vllm_attest_sim_selftest FAILED — refusing to run legs on an unproven simulator"
    tail -30 /tmp/kvmv-sim-selftest.log
    exit 1
fi
echo "  simulator self-test PASS ($(grep -c '^\[OK\]' /tmp/kvmv-sim-selftest.log) checks)"

echo "#########################################"
echo "Staging the registry variants (host side)"
echo "#########################################"
TOK_A_SHA=$(sha256sum "${TOK_A_SRC}" | cut -d' ' -f1)
TOK_B_SHA=$(sha256sum "${TOK_B_SRC}" | cut -d' ' -f1)

stage_full() {
    local S="$1"
    sudo rm -rf "$S"
    mkdir -p "$S/artifacts/sha256" "$S/manifests" "$S/probefixtures/${PROFILE_ID}"
    cp "${TOK_A_SRC}" "$S/artifacts/sha256/${TOK_A_SHA}"
    cp "${TOK_B_SRC}" "$S/artifacts/sha256/${TOK_B_SHA}"
    cat > "$S/${PROFILE_ID}.yaml" <<EOF
profileId: ${PROFILE_ID}
baseModel: Qwen/Qwen3-0.6B
tokenizerArtifact: sha256/${TOK_A_SHA}
tokenizerSha256: ${TOK_A_SHA}
supportedApis:
  - completions
aliasPolicy: base_model_only
EOF
    cat > "$S/qwen25-7bi-completions-v1.yaml" <<EOF
profileId: qwen25-7bi-completions-v1
baseModel: Qwen/Qwen2.5-7B-Instruct
tokenizerArtifact: sha256/${TOK_B_SHA}
tokenizerSha256: ${TOK_B_SHA}
supportedApis:
  - completions
aliasPolicy: base_model_only
EOF
    # §6.4 trust root: without it every strict rule plateaus at
    # ENGINE_HASH_ATTESTED (manifest_missing) and the peer gate would never
    # be the observed hold reason. engineVersion pins the simulator's
    # /version answer.
    cat > "$S/manifests/${PROFILE_ID}.yaml" <<EOF
profileId: ${PROFILE_ID}
imageDigest: sha256:0000000000000000000000000000000000000000000000000000000000000001
engineVersion: "0.28.0"
EOF
    cp "${PROBE_FIX_SRC}"/*.json "$S/probefixtures/${PROFILE_ID}/"
    sudo chown -R root:root "$S"
    sudo find "$S" -type d -exec chmod 0755 {} \;
    sudo find "$S" -type f -exec chmod 0644 {} \;
}

STAGE_FULL="${CFGDIR}/.stage-full"
STAGE_DIVERGENT="${CFGDIR}/.stage-divergent"
STAGE_CORRUPT="${CFGDIR}/.stage-corrupt"

stage_full "${STAGE_FULL}"

stage_full "${STAGE_DIVERGENT}"
sudo rm -f "${STAGE_DIVERGENT}/qwen25-7bi-completions-v1.yaml" \
           "${STAGE_DIVERGENT}/artifacts/sha256/${TOK_B_SHA}"

stage_full "${STAGE_CORRUPT}"
# Flip one byte of the profile-A artifact: digest no longer matches the
# profile's pinned tokenizerSha256 ⇒ the secure loader refuses the profile
# ⇒ the node publishes no generation (empty set digest).
sudo python3 - "$STAGE_CORRUPT/artifacts/sha256/${TOK_A_SHA}" <<'PYEOF'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[0] ^= 0xFF
open(p, "wb").write(bytes(b))
PYEOF
sudo chown root:root "$STAGE_CORRUPT/artifacts/sha256/${TOK_A_SHA}"
sudo chmod 0644 "$STAGE_CORRUPT/artifacts/sha256/${TOK_A_SHA}"

# Raw tokenizer stage for LEGACY (profile-less) kv-exact rules — the
# common-core tokenizer admission (old and new builds alike) resolves
# /etc/loxilb/tokenizers/<slug>/tokenizer.json.
TOKSTAGE="${CFGDIR}/.tokenizers-stage"
sudo rm -rf "${TOKSTAGE}"
mkdir -p "${TOKSTAGE}/${TOK_A_SLUG}" "${TOKSTAGE}/${TOK_B_SLUG}"
cp "${TOK_A_SRC}" "${TOKSTAGE}/${TOK_A_SLUG}/tokenizer.json"
cp "${TOK_B_SRC}" "${TOKSTAGE}/${TOK_B_SLUG}/tokenizer.json"
sudo chown -R root:root "${TOKSTAGE}"

echo "#########################################"
echo "Spawning hosts (llb1 NEW + llb2 OLD to start, client, 2 sim EPs)"
echo "#########################################"
# Short probe cadence so ladders climb (and staleness fences) within
# suite-scale waits; seed 0 satisfies vllm seed-parity admission.
LLB_ENV="-e LLB_KV_NONE_HASH_SEED=0 -e LOXILB_KV_ATTEST_PROBE_CADENCE_S=5"
LLB_TOK="-v ${TOKSTAGE}:/etc/loxilb/tokenizers:ro"

lxdocker="$NEW_IMAGE"
spawn_docker_host --dock-type loxilb --dock-name llb1 --with-ka in \
    --docker-args "${LLB_ENV} ${LLB_TOK} -v ${STAGE_FULL}:/etc/loxilb/kvprofiles:ro"
# Phase A peer: the OLD build (cases 1/2/3). The registry mount is staged
# anyway — the old build simply ignores it (that asymmetry IS the case).
lxdocker="$OLD_IMAGE"
spawn_docker_host --dock-type loxilb --dock-name llb2 --with-ka in \
    --docker-args "${LLB_ENV} ${LLB_TOK} -v ${STAGE_FULL}:/etc/loxilb/kvprofiles:ro"
lxdocker="$NEW_IMAGE"

spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1
spawn_docker_host --dock-type host --dock-name l3ep2

# llb1's --cluster peer address was predicted as its own bridge IP + 1 at
# spawn time; hold every later llb2 respawn to that same address.
get_llb_peerIP llb1
echo "${llb2IP}" > "${CFGDIR}/.llb2-bridge-ip"
actual=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' llb2)
if [[ "$actual" != "$llb2IP" ]]; then
    echo "FATAL: llb2 bridge IP $actual != predicted $llb2IP (cluster peering would be dark)"
    exit 1
fi

echo "#########################################"
echo "Connecting and configuring links"
echo "#########################################"
connect_docker_hosts l3h1  llb1
connect_docker_hosts l3h1  llb2
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep1 llb2
connect_docker_hosts l3ep2 llb1
connect_docker_hosts l3ep2 llb2

sleep 5

config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3h1  --host2 llb2 --ptype phy --addr 20.20.20.1/24
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep1 --host2 llb2 --ptype phy --addr 61.61.61.1/24
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 l3ep2 --host2 llb2 --ptype phy --addr 62.62.62.1/24
config_docker_host --host1 llb1 --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb2 --host2 l3h1  --ptype phy --addr 20.20.20.254/24
config_docker_host --host1 llb2 --host2 l3ep1 --ptype phy --addr 61.61.61.254/24
config_docker_host --host1 llb2 --host2 l3ep2 --ptype phy --addr 62.62.62.254/24
# Replies from the llb2-side endpoint addresses back to the llb2-side client net.
$hexec l3ep1 ip route add 20.20.20.0/24 via 61.61.61.254
$hexec l3ep2 ip route add 20.20.20.0/24 via 62.62.62.254

echo "#########################################"
echo "Starting the attestation simulators (host python in EP netns)"
echo "#########################################"
sim_start() {
    local ns="$1"
    nohup sudo ip netns exec "$ns" python3 "${KVHASH}/vllm_attest_sim.py" \
        --tokenizer "${TOK_A_SRC}" --model "Qwen/Qwen3-0.6B" \
        --http-port 80 --zmq-port 5557 --block-size 16 \
        --algo sha256_cbor --none-hash-seed 0 --engine-version 0.28.0 \
        > "/tmp/kvmv-sim-${ns}.log" 2>&1 &
    echo $! >> "${CFGDIR}/.sim-pids"
}
rm -f "${CFGDIR}/.sim-pids"
sim_start l3ep1
sim_start l3ep2
sleep 3
for ns in l3ep1 l3ep2; do
    v=$($hexec "$ns" curl -s -m 3 http://127.0.0.1:80/version | grep -c '0.28.0' || true)
    [[ "$v" == "1" ]] || { echo "FATAL: simulator in $ns not serving"; cat "/tmp/kvmv-sim-${ns}.log"; exit 1; }
done
echo "  simulators up (l3ep1, l3ep2)"

echo "#########################################"
echo "Waiting for both REST APIs"
echo "#########################################"
for n in llb1 llb2; do
    ok=0
    for _ in $(seq 1 60); do
        rc=$($hexec "$n" curl -s -m 3 -o /dev/null -w "%{http_code}" "http://localhost:11111/netlox/v1/config/loadbalancer/all" 2>/dev/null)
        [[ "$rc" == "200" ]] && { ok=1; break; }
        sleep 1
    done
    [[ "$ok" == 1 ]] || { echo "FATAL: $n REST API not ready"; exit 1; }
done
echo "kv-mixed-version config done (llb1=NEW $NEW_IMAGE, llb2=OLD $OLD_IMAGE)"
