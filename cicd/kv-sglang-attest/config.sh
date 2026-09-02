#!/bin/bash
# config.sh — kv-sglang-attest single-node topology (GPU-free).
#
# llb1 (build under test) + 1 client + 2 endpoint containers whose netns
# run the contract-faithful SGLang attestation simulator (host python,
# cicd/common/kv_hash/sglang_attest_sim.py). The simulator self-test gates
# this config: a dishonest simulator would turn hold-state legs green for
# the wrong reason.
#
# The registry stage is host-side, root-owned, mounted RO before spawn (the
# registry loads ONCE at init). SGLang probe fixtures live in the
# ENGINE-SCOPED subdirectory probefixtures/<profile>/sglang — staged from
# the same committed fixture sources (a {"model","prompt"} /tokenize
# request is byte-valid against SGLang's /v1/tokenize, and the Qwen3
# tokenizer yields identical ids either way); the engine scoping itself is
# a registry-layout property the suite's T-scope case pins.
#
# validation.sh restarts the simulators per case with fault flags — this
# config only proves them up in positive mode.

export LLB_HOST_PORTS=""
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
KVHASH="${CFGDIR}/../common/kv_hash"

# Idempotency: always self-clean a prior aborted run first.
"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true

TOK_SLUG="Qwen__Qwen3-0.6B"
TOK_SRC="${KVHASH}/fixtures/tokenizers/${TOK_SLUG}/tokenizer.json"
PROFILE_ID="qwen3-06b-completions-v1"
PROBE_FIX_SRC="${KVHASH}/fixtures/probefixtures/${PROFILE_ID}"
SGL_REVISION="c1899de289a04d12100db370d81485cdf75e47ca"

for f in "${TOK_SRC}" "${PROBE_FIX_SRC}/basic-ascii.request.json"; do
    [[ -f "$f" ]] || { echo "FATAL: committed fixture missing: $f"; exit 1; }
done

echo "#########################################"
echo "Gate: simulator self-test (honesty proof)"
echo "#########################################"
if ! python3 "${KVHASH}/sglang_attest_sim_selftest.py" > /tmp/kvsgl-sim-selftest.log 2>&1; then
    echo "FATAL: sglang_attest_sim_selftest FAILED — refusing to run legs on an unproven simulator"
    tail -30 /tmp/kvsgl-sim-selftest.log
    exit 1
fi
echo "  simulator self-test PASS ($(grep -c '^\[OK\]' /tmp/kvsgl-sim-selftest.log) checks)"

echo "#########################################"
echo "Staging the profile registry (host side)"
echo "#########################################"
TOK_SHA=$(sha256sum "${TOK_SRC}" | cut -d' ' -f1)
STAGE="${CFGDIR}/.stage-full"
sudo rm -rf "${STAGE}"
mkdir -p "${STAGE}/artifacts/sha256" "${STAGE}/manifests" \
         "${STAGE}/probefixtures/${PROFILE_ID}/sglang"
cp "${TOK_SRC}" "${STAGE}/artifacts/sha256/${TOK_SHA}"
cat > "${STAGE}/${PROFILE_ID}.yaml" <<EOF
profileId: ${PROFILE_ID}
baseModel: Qwen/Qwen3-0.6B
tokenizerArtifact: sha256/${TOK_SHA}
tokenizerSha256: ${TOK_SHA}
supportedApis:
  - completions
aliasPolicy: base_model_only
EOF
# §6.4 trust root. engineVersion pins the simulator's /get_server_info
# answer; modelRevision arms the SGLang adapter's revision read-back (the
# revision-lie case flips the sim side, this pin stays).
cat > "${STAGE}/manifests/${PROFILE_ID}.yaml" <<EOF
profileId: ${PROFILE_ID}
imageDigest: sha256:0000000000000000000000000000000000000000000000000000000000000002
engineVersion: "0.5.18"
modelRevision: "${SGL_REVISION}"
EOF
# Engine-scoped fixture staging (see header). The T-scope case depends on
# the FLAT profile dir carrying NO fixtures — only sglang/ does.
cp "${PROBE_FIX_SRC}"/*.json "${STAGE}/probefixtures/${PROFILE_ID}/sglang/"
sudo chown -R root:root "${STAGE}"
sudo find "${STAGE}" -type d -exec chmod 0755 {} \;
sudo find "${STAGE}" -type f -exec chmod 0644 {} \;

# Raw tokenizer stage — the gateway's challenge prompt tokenizes through
# the data-plane cache path, which resolves /etc/loxilb/tokenizers/<slug>/.
TOKSTAGE="${CFGDIR}/.tokenizers-stage"
sudo rm -rf "${TOKSTAGE}"
mkdir -p "${TOKSTAGE}/${TOK_SLUG}"
cp "${TOK_SRC}" "${TOKSTAGE}/${TOK_SLUG}/tokenizer.json"
sudo chown -R root:root "${TOKSTAGE}"

echo "#########################################"
echo "Spawning hosts (llb1, client, 2 sim EPs)"
echo "#########################################"
# Short probe cadence so ladders climb (and fences land) within suite-scale
# waits.
spawn_docker_host --dock-type loxilb --dock-name llb1 \
    --docker-args "-e LOXILB_KV_ATTEST_PROBE_CADENCE_S=5 -v ${TOKSTAGE}:/etc/loxilb/tokenizers:ro -v ${STAGE}:/etc/loxilb/kvprofiles:ro"
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1
spawn_docker_host --dock-type host --dock-name l3ep2

echo "#########################################"
echo "Connecting and configuring links"
echo "#########################################"
connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1

sleep 5

config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 llb1 --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24

echo "#########################################"
echo "Starting the attestation simulators (positive mode)"
echo "#########################################"
# sims_start/sims_stop live in lib.sh — validation.sh reuses them per case.
source "${CFGDIR}/lib.sh"
sims_start "" 1
for ns in l3ep1 l3ep2; do
    v=$($hexec "$ns" curl -s -m 3 http://127.0.0.1:80/get_server_info | grep -c '0.5.18' || true)
    [[ "$v" == "1" ]] || { echo "FATAL: simulator in $ns not serving"; cat "/tmp/kvsgl-sim-${ns}.log"; exit 1; }
done
echo "  simulators up (l3ep1, l3ep2)"

echo "#########################################"
echo "Waiting for the REST API"
echo "#########################################"
ok=0
for _ in $(seq 1 60); do
    rc=$($hexec llb1 curl -s -m 3 -o /dev/null -w "%{http_code}" "http://localhost:11111/netlox/v1/config/loadbalancer/all" 2>/dev/null)
    [[ "$rc" == "200" ]] && { ok=1; break; }
    sleep 1
done
[[ "$ok" == 1 ]] || { echo "FATAL: llb1 REST API not ready"; exit 1; }
echo "kv-sglang-attest config done"
