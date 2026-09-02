#!/bin/bash
# config.sh — kv-profile-admission topology (GPU-free).
#
# Single loxilb (llb1) + 1 client + 3 reflect-echo backends. Two
# ModelPromptProfiles are staged into a host-side registry root that is
# volume-mounted at llb1's trusted path (/etc/loxilb/kvprofiles) BEFORE the
# gateway starts — the registry is read once at init, so the stage must
# exist first (the same stage-then-start order a production operator
# follows). Tokenizer artifacts are content-addressed from the committed
# kv_hash fixtures, so strict (profile-bound) KV-exact rules admit against
# the compiled engine-contract registry without any GPU or live engine.
# validation.sh then drives the admission matrix: strict admits, typed 4xx
# refusals with zero-state sweeps, immutability, binding-generation,
# contract-ACK enforcement and status/evidence legs.

export LLB_HOST_PORTS=""
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"

# Idempotency: a prior aborted run leaves topology + rule state behind and
# spawn_docker_host silently no-ops on existing names — always self-clean.
"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true

TOK_A_SLUG="Qwen__Qwen3-0.6B"
TOK_A_SRC="${CFGDIR}/../common/kv_hash/fixtures/tokenizers/Qwen__Qwen3-0.6B/tokenizer.json"
TOK_B_SLUG="Qwen__Qwen2.5-7B-Instruct"
TOK_B_SRC="${CFGDIR}/../common/kv_hash/fixtures/tokenizers/Qwen__Qwen2.5-7B-Instruct/tokenizer.json"

for f in "${TOK_A_SRC}" "${TOK_B_SRC}"; do
    if [[ ! -f "$f" ]]; then
        echo "FATAL: committed tokenizer fixture missing: $f"
        exit 1
    fi
done

echo "#########################################"
echo "Staging the trusted ModelPromptProfile registry (host side)"
echo "#########################################"
# Registry trust rules (enforced by the gateway's secure loader): regular
# files, owned by root (the gateway's euid in-container), mode <= 0644,
# non-group/world-writable directories; tokenizer artifacts are
# content-addressed (sha256/<digest>) with the digest pinned in the profile.
STAGE="${CFGDIR}/.kvprofiles-stage"
sudo rm -rf "${STAGE}"
mkdir -p "${STAGE}/artifacts/sha256"

TOK_A_SHA=$(sha256sum "${TOK_A_SRC}" | cut -d' ' -f1)
TOK_B_SHA=$(sha256sum "${TOK_B_SRC}" | cut -d' ' -f1)
cp "${TOK_A_SRC}" "${STAGE}/artifacts/sha256/${TOK_A_SHA}"
cp "${TOK_B_SRC}" "${STAGE}/artifacts/sha256/${TOK_B_SHA}"

cat > "${STAGE}/qwen3-06b-completions-v1.yaml" <<EOF
profileId: qwen3-06b-completions-v1
baseModel: Qwen/Qwen3-0.6B
tokenizerArtifact: sha256/${TOK_A_SHA}
tokenizerSha256: ${TOK_A_SHA}
supportedApis:
  - completions
aliasPolicy: base_model_only
EOF

cat > "${STAGE}/qwen25-7bi-completions-v1.yaml" <<EOF
profileId: qwen25-7bi-completions-v1
baseModel: Qwen/Qwen2.5-7B-Instruct
tokenizerArtifact: sha256/${TOK_B_SHA}
tokenizerSha256: ${TOK_B_SHA}
supportedApis:
  - completions
aliasPolicy: base_model_only
EOF

sudo chown -R root:root "${STAGE}"
sudo chmod 0755 "${STAGE}" "${STAGE}/artifacts" "${STAGE}/artifacts/sha256"
sudo chmod 0644 "${STAGE}"/*.yaml "${STAGE}/artifacts/sha256/"*

# Raw tokenizer path for the legacy (profile-less) matrix rules — they pass
# the common-core tokenizer admission the way production legacy deployments
# do, via /etc/loxilb/tokenizers/<slug>/tokenizer.json.
TOKSTAGE="${CFGDIR}/.tokenizers-stage"
sudo rm -rf "${TOKSTAGE}"
mkdir -p "${TOKSTAGE}/${TOK_A_SLUG}" "${TOKSTAGE}/${TOK_B_SLUG}"
cp "${TOK_A_SRC}" "${TOKSTAGE}/${TOK_A_SLUG}/tokenizer.json"
cp "${TOK_B_SRC}" "${TOKSTAGE}/${TOK_B_SLUG}/tokenizer.json"
sudo chown -R root:root "${TOKSTAGE}"

echo "#########################################"
echo "Building the reflect-echo backend image"
echo "#########################################"
"$(dirname "$0")/../common/reflect-echo/docker-build.sh"

echo "#########################################"
echo "Spawning hosts (1 client + 3 echo EPs)"
echo "#########################################"

# LLB_KV_NONE_HASH_SEED=0 satisfies the vllm seed-parity admission input for
# every strict vllm rule in the matrix (the seed-absent refusal itself is
# covered at the unit layer where the env can be controlled per-case).
spawn_docker_host --dock-type loxilb --dock-name llb1 --docker-args "-e LLB_KV_NONE_HASH_SEED=0 -v ${STAGE}:/etc/loxilb/kvprofiles:ro -v ${TOKSTAGE}:/etc/loxilb/tokenizers:ro"
spawn_docker_host --dock-type host   --dock-name l3h1
spawn_docker_host --dock-type reflect-echo --dock-name l3ep1 --docker-args "-e ECHO_NAME=serverP0"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep2 --docker-args "-e ECHO_NAME=serverD0"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep3 --docker-args "-e ECHO_NAME=serverP1"

echo "#########################################"
echo "Connecting and configuring hosts"
echo "#########################################"

connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1
connect_docker_hosts l3ep3 llb1

sleep 5

config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 l3ep3 --host2 llb1 --ptype phy --addr 33.33.33.1/24 --gw 33.33.33.254
config_docker_host --host1 llb1 --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb1 --host2 l3ep3 --ptype phy --addr 33.33.33.254/24

sleep 5

LBBASE="http://localhost:11111/netlox/v1/config/loadbalancer"
echo "Waiting for loxilb REST API (localhost:11111) to be ready..."
api_ready=0
for _ in $(seq 1 60); do
    rc=$($hexec llb1 curl -s -m 3 -o /dev/null -w "%{http_code}" "${LBBASE}/all" 2>/dev/null)
    if [[ "$rc" == "200" ]]; then api_ready=1; echo "  loxilb REST API ready"; break; fi
    sleep 1
done
[[ "$api_ready" == 1 ]] || { echo "FATAL: loxilb REST API not ready"; exit 1; }

# Registry publication receipt — BEHAVIORAL, not log-scrape (the gateway
# process runs under a detached exec, so neither docker logs nor the file
# logger reliably carries the loader's line). A strict probe rule that only
# admits when the staged profile resolved and the compiled engine contract
# is registered is the receipt; it is deleted immediately after.
probe_body='{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 9999, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "10.10.10.254",
    "pd_disagg_mode": true, "probeRetries": 1,
    "kvExactMode": 1, "kvZmqPort": 5557, "kvBlockSize": 16,
    "kvEngineType": "vllm", "model_name": "Qwen/Qwen3-0.6B",
    "kvExactApiMode": "completions", "kvModelProfile": "qwen3-06b-completions-v1"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1, "ep_role": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 80, "weight": 1, "ep_role": 2 }
  ]
}'
rc=$($hexec llb1 curl -s -m 10 -o /tmp/kvpa-probe.json -w "%{http_code}" \
    -X POST "${LBBASE}" -H 'Content-Type: application/json' -d "${probe_body}")
if [[ "$rc" == "200" ]]; then
    echo "  profile registry receipt: strict probe rule admitted (HTTP 200)"
    $hexec llb1 curl -s -m 5 -o /dev/null -X DELETE \
        "${LBBASE}/externalipaddress/10.10.10.254/port/9999/protocol/tcp?model_name=Qwen%2FQwen3-0.6B"
else
    echo "FATAL: strict probe rule refused (HTTP $rc) — registry/contract not serving:"
    cat /tmp/kvpa-probe.json 2>/dev/null; echo
    exit 1
fi

echo "kv-profile-admission config done"
