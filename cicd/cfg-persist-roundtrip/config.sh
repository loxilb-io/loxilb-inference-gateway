#!/bin/bash
# config.sh — cfg-persist-roundtrip topology (GPU-free).
#
# One gateway (llb1, BGP-enabled, config volume host-mounted so
# snapshot.json is inspectable), one client (l3h1), three reflect-echo
# backends. The fixture populates every restartable configuration class
# this suite verifies: a plain L4 LB rule, an API-key-gated L7 rule, a
# strict KV-exact P/D rule (profile registry staged before start, as a
# production operator would), a standalone endpoint, firewall, policy,
# session + ULCL, ipfilter, securityrate and a BGP neighbor with
# non-default transport settings. validation.sh then proves the whole set
# survives persist + in-place restart FIELD-identically (canonical
# deep-diff, not probe re-runs) with datapath probes on top.

export LLB_HOST_PORTS=""
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"

# Idempotency: always self-clean a prior aborted run first.
"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true
# Stale evidence from a prior run must not masquerade as this run's.
sudo rm -rf "${CFGDIR}/artifacts" >/dev/null 2>&1 || true

TOK_SLUG="Qwen__Qwen3-0.6B"
TOK_SRC="${CFGDIR}/../common/kv_hash/fixtures/tokenizers/${TOK_SLUG}/tokenizer.json"
if [[ ! -f "${TOK_SRC}" ]]; then
    echo "FATAL: committed tokenizer fixture missing: ${TOK_SRC}"
    exit 1
fi

echo "#########################################"
echo "Staging the trusted ModelPromptProfile registry (host side)"
echo "#########################################"
STAGE="${CFGDIR}/.kvprofiles-stage"
sudo rm -rf "${STAGE}"
mkdir -p "${STAGE}/artifacts/sha256"
TOK_SHA=$(sha256sum "${TOK_SRC}" | cut -d' ' -f1)
cp "${TOK_SRC}" "${STAGE}/artifacts/sha256/${TOK_SHA}"
cat > "${STAGE}/qwen3-06b-completions-v1.yaml" <<EOF
profileId: qwen3-06b-completions-v1
baseModel: Qwen/Qwen3-0.6B
tokenizerArtifact: sha256/${TOK_SHA}
tokenizerSha256: ${TOK_SHA}
supportedApis:
  - completions
aliasPolicy: base_model_only
EOF
sudo chown -R root:root "${STAGE}"
sudo chmod 0755 "${STAGE}" "${STAGE}/artifacts" "${STAGE}/artifacts/sha256"
sudo chmod 0644 "${STAGE}"/*.yaml "${STAGE}/artifacts/sha256/"*

echo "#########################################"
echo "Building the reflect-echo backend image"
echo "#########################################"
"${CFGDIR}/../common/reflect-echo/docker-build.sh"

echo "#########################################"
echo "Spawning hosts (llb1 + client + 3 echo EPs)"
echo "#########################################"

# pick_config mounts ./llb1_config at /etc/loxilb so the persisted
# snapshot.json is host-inspectable and survives in-place restarts.
pick_config="yes"
mkdir -p "${CFGDIR}/llb1_config"

spawn_docker_host --dock-type loxilb --dock-name llb1 --with-bgp yes \
    --docker-args "-e LLB_KV_NONE_HASH_SEED=0 -v ${STAGE}:/etc/loxilb/kvprofiles:ro"
pick_config=""
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type reflect-echo --dock-name l3ep1 --docker-args "-e ECHO_NAME=serverA"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep2 --docker-args "-e ECHO_NAME=serverB"
spawn_docker_host --dock-type reflect-echo --dock-name l3ep3 --docker-args "-e ECHO_NAME=serverC"

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

API="http://localhost:11111/netlox/v1"
echo "Waiting for loxilb REST API to be ready..."
api_ready=0
for _ in $(seq 1 60); do
    rc=$($hexec llb1 curl -s -m 3 -o /dev/null -w "%{http_code}" "${API}/config/loadbalancer/all" 2>/dev/null)
    if [[ "$rc" == "200" ]]; then api_ready=1; echo "  loxilb REST API ready"; break; fi
    sleep 1
done
[[ "$api_ready" == 1 ]] || { echo "FATAL: loxilb REST API not ready"; exit 1; }

post_json() { # post_json <path> <body> — echoes http code
    $hexec llb1 curl -s -m 10 -o /tmp/cfgp-post.json -w "%{http_code}" \
        -X POST "${API}$1" -H 'Content-Type: application/json' -d "$2"
}
must_200() { # must_200 <label> <code>
    if [[ "$2" != "200" && "$2" != "204" ]]; then
        echo "FATAL: fixture $1 refused (HTTP $2):"
        cat /tmp/cfgp-post.json 2>/dev/null; echo
        exit 1
    fi
    echo "  fixture: $1 [OK]"
}

echo "#########################################"
echo "Building the restartable-config fixture"
echo "#########################################"

# Plain L4 LB rule: hash selector, health-monitored endpoint, source
# allowlist wide enough for the client probes. Its endpoint deliberately
# does NOT overlap the L7 rules' endpoints: epHost options are shared per
# endpoint key and first-writer-wins, so a non-monitored rule applying
# first would silently strip this rule's probe config (a pre-existing
# shared-endpoint precedence gap, tracked separately from persistence).
rc=$(post_json /config/loadbalancer '{
  "serviceArguments": {
    "externalIP": "20.20.20.1", "port": 2020, "protocol": "tcp",
    "sel": 1, "mode": 2, "name": "rt-l4-full",
    "monitor": true, "probetype": "tcp", "probeport": 80,
    "inactiveTimeout": 240, "persistTimeout": 0
  },
  "allowedSources": [ { "prefix": "10.10.10.0/24" } ],
  "endpoints": [
    { "endpointIP": "33.33.33.1", "targetPort": 80, "weight": 1 }
  ]
}')
must_200 "L4 LB rule" "$rc"

# API-key-gated L7 rule: enforcement must hold across a restart.
rc=$(post_json /config/loadbalancer '{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 8080, "protocol": "tcp",
    "sel": 0, "mode": 4, "name": "rt-l7-apikey", "host": "10.10.10.254",
    "model_name": "test-model", "api_key_auth": "required"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 80, "weight": 1 }
  ]
}')
must_200 "API-key L7 rule" "$rc"

# Strict KV-exact P/D rule: creates a kvexactbinding entry, the domain
# that used to be invisible to restore verification.
rc=$(post_json /config/loadbalancer '{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 8081, "protocol": "tcp",
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
}')
must_200 "KV-exact P/D rule" "$rc"

# Standalone (non-rule-managed) endpoint on the third backend.
rc=$(post_json /config/endpoint '{
  "hostName": "33.33.33.1", "name": "rt-ep-standalone",
  "inactiveReTries": 2, "probeType": "ping", "probeDuration": 10
}')
must_200 "standalone endpoint" "$rc"

# Firewall drop rule for a source that never appears in probes.
rc=$(post_json /config/firewall '{
  "ruleArguments": { "sourceIP": "77.77.77.7/32", "destinationIP": "20.20.20.1/32" },
  "opts": { "drop": true }
}')
must_200 "firewall drop rule" "$rc"

# QoS policy object attached to the third backend's port.
rc=$(post_json /config/policy '{
  "policyIdent": "rt-pol1",
  "policyInfo": { "type": 0, "colorAware": false,
                  "committedInfoRate": 100, "peakInfoRate": 200 },
  "targetObject": { "attachment": 1, "polObjName": "ellb1l3ep3" }
}')
must_200 "policy" "$rc"

# SPAN mirror: monitor the client port, mirror to the third backend port.
rc=$(post_json /config/mirror '{
  "mirrorIdent": "rt-mirr1",
  "mirrorInfo": { "type": 0, "port": "ellb1l3ep3" },
  "targetObject": { "attachment": 1, "mirrObjName": "ellb1l3h1" }
}')
must_200 "mirror" "$rc"

# Session + ULCL classification (CLI path, same recipe as the ulcl suites).
$dexec llb1 loxicmd create session rt-user1 88.88.88.88 \
    --accessNetworkTunnel 1:10.10.10.56 --coreNetworkTunnel=1:10.10.10.59 || {
    echo "FATAL: fixture session refused"; exit 1; }
echo "  fixture: session [OK]"
$dexec llb1 loxicmd create sessionulcl rt-user1 --ulclArgs=11:33.33.33.1 || {
    echo "FATAL: fixture sessionulcl refused"; exit 1; }
echo "  fixture: sessionulcl [OK]"

# ipfilter blacklist for a prefix that never appears in probes.
rc=$(post_json /config/ipfilter '{
  "filterType": "blacklist", "cidr": "77.77.77.0/24",
  "action": "drop", "priority": 200
}')
must_200 "ipfilter blacklist" "$rc"

# securityrate config (valid shape from the secfilter suite).
rc=$(post_json /config/securityrate '{
  "synEnabled": true, "synThreshold": 200, "cookieThreshold": 50,
  "connRateEnabled": false, "ratePerSec": 50,
  "udpEnabled": false, "udpPktThreshold": 1000, "udpBandwidthMB": 100
}')
must_200 "securityrate config" "$rc"

# BGP global config first (a neighbor cannot be added to a speaker with
# no local AS / router id), then a neighbor with NON-default transport
# (port + multihop): the fields that used to silently revert to defaults
# across a restart.
rc=$(post_json /config/bgp/global '{ "localAs": 64511, "routerId": "10.10.10.254" }')
must_200 "BGP global config" "$rc"

rc=$(post_json /config/bgp/neigh '{
  "ipAddress": "10.10.10.1", "remoteAs": 64512,
  "remotePort": 1790, "setMultiHop": true
}')
must_200 "BGP neighbor (port 1790, multihop)" "$rc"

echo "cfg-persist-roundtrip config done"
