#!/bin/bash

source ../common.sh

# Ensure a shared HuggingFace cache on the host BEFORE spawning endpoints.
# common.sh mounts /tmp/hf-cache into every vllm-server container when it exists,
# so all endpoints share ONE model cache. Without it each endpoint downloads the
# model into its own ephemeral overlay; the second (anonymous) download commonly
# stalls, leaving that endpoint stuck and never serving /v1/models -- which makes
# the round-robin /v1/models probes in validation fail. Creating it once means
# the model is downloaded a single time and reused (and warmed across runs).
mkdir -p /tmp/hf-cache

# vllm_fullproxy_install_lb_rules <target>
# Install the 4 vllm-fullproxy LB rules (ports 2020 rr / 2021 CHWBL L1 /
# 2022 CHWBL L2 / 2023 CHWBL L3) on the given loxilb container. Idempotent —
# re-POSTing overwrites prior config. Called once for llb1 in default mode;
# called for both llb1 and llb2 in PHASE_L_HA=1 mode so post-failover traffic
# can land on either node without rule drift.
vllm_fullproxy_install_lb_rules() {
    local target="$1"
    # REST API: sel=0=rr, sel=8=chwbl, mode=4=fullproxy, security=1=https
    # probetype=http probeTimeout=10 probeRetries=1: fast health detection (~10s failover)
    # Port 2020: round-robin, HTTPS fullproxy
    if [[ "$USE_CLI" == "1" ]]; then
        create_lb_rule "$target" 10.10.10.254 --tcp=2020:8000 --endpoints=31.31.31.1:1,32.32.32.1:1 --mode=fullproxy --security=https --host=10.10.10.254 --select=rr --monitor --probetype=http --probeport=8000 --probereq=/v1/models --probetimeout=10 --proberetries=1
    else
    $dexec "$target" wget -qO- \
        --header='Content-Type: application/json' \
        --method=POST \
        --body-data='{"serviceArguments":{"externalIP":"10.10.10.254","port":2020,"protocol":"tcp","sel":0,"mode":4,"security":1,"monitor":true,"host":"10.10.10.254","probetype":"http","probeport":8000,"probereq":"/v1/models","probeTimeout":10,"probeRetries":1},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8000,"weight":1},{"endpointIP":"32.32.32.1","targetPort":8000,"weight":1}]}' \
        http://127.0.0.1:11111/netlox/v1/config/loadbalancer
    fi
    # Port 2021: CHWBL Level1 (hash on model name only)
    if [[ "$USE_CLI" == "1" ]]; then
        create_lb_rule "$target" 10.10.10.254 --tcp=2021:8000 --endpoints=31.31.31.1:1,32.32.32.1:1 --mode=fullproxy --security=https --host=10.10.10.254 --select=chwbl --chwbl-hash-level=1 --monitor --probetype=http --probeport=8000 --probereq=/v1/models --probetimeout=10 --proberetries=1
    else
    $dexec "$target" wget -qO- \
        --header='Content-Type: application/json' \
        --method=POST \
        --body-data='{"serviceArguments":{"externalIP":"10.10.10.254","port":2021,"protocol":"tcp","sel":8,"mode":4,"security":1,"monitor":true,"host":"10.10.10.254","chwbl_prefix_hash_level":1,"probetype":"http","probeport":8000,"probereq":"/v1/models","probeTimeout":10,"probeRetries":1},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8000,"weight":1},{"endpointIP":"32.32.32.1","targetPort":8000,"weight":1}]}' \
        http://127.0.0.1:11111/netlox/v1/config/loadbalancer
    fi
    # Port 2022: CHWBL Level2 (model+prompt prefix, load-factor=125, replication=100)
    if [[ "$USE_CLI" == "1" ]]; then
        create_lb_rule "$target" 10.10.10.254 --tcp=2022:8000 --endpoints=31.31.31.1:1,32.32.32.1:1 --mode=fullproxy --security=https --host=10.10.10.254 --select=chwbl --chwbl-hash-level=2 --chwbl-load-factor=125 --chwbl-replication=100 --monitor --probetype=http --probeport=8000 --probereq=/v1/models --probetimeout=10 --proberetries=1
    else
    $dexec "$target" wget -qO- \
        --header='Content-Type: application/json' \
        --method=POST \
        --body-data='{"serviceArguments":{"externalIP":"10.10.10.254","port":2022,"protocol":"tcp","sel":8,"mode":4,"security":1,"monitor":true,"host":"10.10.10.254","chwbl_prefix_hash_level":2,"chwbl_mean_load_factor":125,"chwbl_replication":100,"probetype":"http","probeport":8000,"probereq":"/v1/models","probeTimeout":10,"probeRetries":1},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8000,"weight":1},{"endpointIP":"32.32.32.1","targetPort":8000,"weight":1}]}' \
        http://127.0.0.1:11111/netlox/v1/config/loadbalancer
    fi
    # Port 2023: CHWBL Level3 (full hash, load-factor=250, replication=200)
    if [[ "$USE_CLI" == "1" ]]; then
        create_lb_rule "$target" 10.10.10.254 --tcp=2023:8000 --endpoints=31.31.31.1:1,32.32.32.1:1 --mode=fullproxy --security=https --host=10.10.10.254 --select=chwbl --chwbl-hash-level=3 --chwbl-load-factor=250 --chwbl-replication=200 --monitor --probetype=http --probeport=8000 --probereq=/v1/models --probetimeout=10 --proberetries=1
    else
    $dexec "$target" wget -qO- \
        --header='Content-Type: application/json' \
        --method=POST \
        --body-data='{"serviceArguments":{"externalIP":"10.10.10.254","port":2023,"protocol":"tcp","sel":8,"mode":4,"security":1,"monitor":true,"host":"10.10.10.254","chwbl_prefix_hash_level":3,"chwbl_mean_load_factor":250,"chwbl_replication":200,"probetype":"http","probeport":8000,"probereq":"/v1/models","probeTimeout":10,"probeRetries":1},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8000,"weight":1},{"endpointIP":"32.32.32.1","targetPort":8000,"weight":1}]}' \
        http://127.0.0.1:11111/netlox/v1/config/loadbalancer
    fi
}

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

# Spawn llb1 with HA cluster keepalive flags when PHASE_L_HA=1,
# plain otherwise. Cannot restart-in-place after the fact — leaves stale eBPF
# state. Source: cicd/vllm-pd-disagg/config.sh:68-72.
if [ "${PHASE_L_HA:-0}" = "1" ]; then
  spawn_docker_host --dock-type loxilb --dock-name llb1 \
    --extra-args "--cluster=10.10.10.253 --self=0 --ka=10.10.10.253:10.10.10.254"
else
  spawn_docker_host --dock-type loxilb --dock-name llb1
fi
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type vllm-server --dock-name l3ep1
spawn_docker_host --dock-type vllm-server --dock-name l3ep2

echo "#########################################"
echo "Connecting and configuring hosts"
echo "#########################################"

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1

sleep 5

# L3 configuration
config_docker_host --host1 l3h1 --host2 llb1 --ptype phy --addr 10.10.10.1/24 
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24
config_docker_host --host1 llb1 --host2 l3h1 --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24

add_route l3h1 31.31.31.0/24 10.10.10.254
add_route l3h1 32.32.32.0/24 10.10.10.254
add_route l3ep1 10.10.10.0/24 31.31.31.254
add_route l3ep2 10.10.10.0/24 32.32.32.254

$dexec llb1 ip addr add 10.10.10.3/32 dev lo

echo "#########################################"
echo "Preparing TLS certificates"
echo "#########################################"

# Generate certificates for loxilb (HTTPS frontend) with IP SAN.
# minica (github.com/jsha/minica) is fetched on demand — no binary is committed.
MINICA="$(command -v minica || echo "$(go env GOPATH)/bin/minica")"
[ -x "$MINICA" ] || { go install github.com/jsha/minica@latest; MINICA="$(go env GOPATH)/bin/minica"; }
"$MINICA" --ip-addresses 10.10.10.254
docker cp minica.pem llb1:/opt/loxilb/cert/rootCA.crt
docker cp 10.10.10.254/cert.pem llb1:/opt/loxilb/cert/server.crt
docker cp 10.10.10.254/key.pem llb1:/opt/loxilb/cert/server.key

# Copy CA certificate to client for verification
docker cp minica.pem l3h1:/tmp/minica.pem

echo "#########################################"
echo "Installing HuggingFace token (optional)"
echo "#########################################"

# Set your HuggingFace token here if needed
HF_TOKEN="${LOXILB_HF_TOKEN:-}"
# HF_TOKEN fallback: export LOXILB_HF_TOKEN=<your-token> in the runner environment

# Poll a vLLM endpoint until it actually serves /v1/models, or fail hard.
# A fixed sleep is not enough: on a cold HF cache the model download can take
# minutes (or stall), and proceeding against a half-ready backend makes the
# round-robin /v1/models probes in validation fail spuriously.
wait_vllm_ready() {
    local ctr=$1 logf=$2 timeout=${3:-600} waited=0
    echo "Waiting for $ctr to serve /v1/models (timeout ${timeout}s)..."
    while [ $waited -lt $timeout ]; do
        if $dexec $ctr curl -s --max-time 5 http://localhost:8000/v1/models 2>/dev/null | grep -q "Qwen/Qwen3-0.6B"; then
            echo "  $ctr ready after ${waited}s"
            return 0
        fi
        sleep 5
        waited=$(( waited + 5 ))
    done
    echo "  ERROR: $ctr not ready after ${timeout}s -- last log lines:"
    $dexec $ctr tail -n 20 "$logf" 2>/dev/null
    return 1
}

echo "#########################################"
echo "Starting vLLM servers on endpoints"
echo "#########################################"

# Start vLLM servers on each endpoint (HTTP on port 8000)
# Using small model Qwen3-0.6B for testing
# Start servers sequentially to avoid race conditions during model download
# Each server gets dedicated CPU cores to prevent resource contention

echo "Starting vLLM server on l3ep1 (CPU core 0) - will download model..."
if [[ -n "$HF_TOKEN" ]]; then
    $dexec l3ep1 bash -c "cd /workspace && HF_TOKEN='$HF_TOKEN' HUGGINGFACE_HUB_TOKEN='$HF_TOKEN' VLLM_CPU_OMP_THREADS_BIND='0' VLLM_USE_V1=0 VLLM_CPU_KVCACHE_SPACE=1 python -m vllm.entrypoints.openai.api_server --model Qwen/Qwen3-0.6B --device cpu --dtype float32 --max-model-len 1024 --host 0.0.0.0 --port 8000 --enable-request-id-headers > /tmp/vllm-server1.log 2>&1 &"
else
    $dexec l3ep1 bash -c "cd /workspace && VLLM_CPU_OMP_THREADS_BIND='0' VLLM_USE_V1=0 VLLM_CPU_KVCACHE_SPACE=1 python -m vllm.entrypoints.openai.api_server --model Qwen/Qwen3-0.6B --device cpu --dtype float32 --max-model-len 1024 --host 0.0.0.0 --port 8000 --enable-request-id-headers > /tmp/vllm-server1.log 2>&1 &"
fi

wait_vllm_ready l3ep1 /tmp/vllm-server1.log 600 || { echo "ERROR: l3ep1 vLLM failed to start"; exit 1; }

echo "Starting vLLM server on l3ep2 (CPU core 1) - will use cached model..."
if [[ -n "$HF_TOKEN" ]]; then
    $dexec l3ep2 bash -c "cd /workspace && HF_TOKEN='$HF_TOKEN' HUGGINGFACE_HUB_TOKEN='$HF_TOKEN' VLLM_CPU_OMP_THREADS_BIND='1' VLLM_USE_V1=0 VLLM_CPU_KVCACHE_SPACE=1 python -m vllm.entrypoints.openai.api_server --model Qwen/Qwen3-0.6B --device cpu --dtype float32 --max-model-len 1024 --host 0.0.0.0 --port 8000 --enable-request-id-headers > /tmp/vllm-server2.log 2>&1 &"
else
    $dexec l3ep2 bash -c "cd /workspace && VLLM_CPU_OMP_THREADS_BIND='1' VLLM_USE_V1=0 VLLM_CPU_KVCACHE_SPACE=1 python -m vllm.entrypoints.openai.api_server --model Qwen/Qwen3-0.6B --device cpu --dtype float32 --max-model-len 1024 --host 0.0.0.0 --port 8000 --enable-request-id-headers > /tmp/vllm-server2.log 2>&1 &"
fi

wait_vllm_ready l3ep2 /tmp/vllm-server2.log 600 || { echo "ERROR: l3ep2 vLLM failed to start"; exit 1; }

echo "#########################################"
echo "Both vLLM servers are serving /v1/models"
echo "#########################################"

echo "#########################################"
echo "Creating LoxiLB load balancer rule"
echo "#########################################"

# config path: drive the inference-gateway loxicmd as the load-bearing config
# path when present (subject-under-test); fall back to raw REST for old/absent CLI.
cli_preflight llb1 && USE_CLI=1 || USE_CLI=0
vllm_fullproxy_install_lb_rules llb1

echo "#########################################"
echo "Configuration complete"
echo "#########################################"
echo "LoxiLB VIP: https://10.10.10.254:2020"
echo "Backend vLLM servers:"
echo "  - server1: http://31.31.31.1:8000"
echo "  - server2: http://32.32.32.1:8000"
echo ""
echo "Test endpoints:"
echo "  - List models: curl -sk https://10.10.10.254:2020/v1/models | jq ."
echo "  - Completion: curl -sk https://10.10.10.254:2020/v1/completions -d '{...}'"

########################################################################
# HA mode (PHASE_L_HA=1) — 2-loxilb HA topology via cluster keepalive
# ----------------------------------------------------------------------
# Wire HA between llb1 (.254, self=0, initial MASTER) and llb2 (.253, self=1,
# initial BACKUP) using loxilb's built-in cluster flags. Then deploy the
# LOCALLY-BUILT ./loxilb binary into both containers via `docker cp` so the
# harness tests the current code (closes the harness-fidelity gap;
# stale registry image otherwise has no SockproxySync).
#
# Source patterns:
#   - cicd/vllm-pd-disagg/config.sh:244-388 (PHASE_L_HA reference; l3ep3/l3ep4
#     dropped, virtual-VIP rewrite via netfilter NAT dropped — vllm-fullproxy
#     is 2-EP and uses direct curls to the current-master IP).
#   - scripts/probe-sockproxy-sync-wiring.sh:79-92 (docker cp binary overlay
#     + stdout-redirect loxilb restart).
#
# Default mode (no PHASE_L_HA env var) skips this block entirely.
########################################################################

if [ "${PHASE_L_HA:-0}" = "1" ]; then

echo "#########################################"
echo "HA: spawning llb2 + deploying local binary"
echo "#########################################"

echo "[HA] Spawning llb2 container (no host-port mappings — uses container IPs)"
# CANNOT use `spawn_docker_host --dock-type loxilb` for llb2 because it always
# publishes host ports 8091/11111/22222 already owned by llb1 → "port is
# already allocated". llb2 uses its own container IP (10.10.10.253) on the
# l3h1<->llb2 bridge instead; cluster sync to llb1 over port 22222 works
# because both loxilbs share the docker network.
docker run -u root --cap-add SYS_ADMIN --restart unless-stopped --privileged \
  -dt --entrypoint /bin/bash \
  -v /dev/log:/dev/log -v "$(pwd)/cert:/opt/loxilb/cert/" \
  --name llb2 "${lxdocker:-ghcr.io/loxilb-io/loxilb-inference-gateway:latest}" 2>&1 || \
  echo "WARN: llb2 docker run failed (container may already exist)"
sleep 2

# Register llb2 netns so connect_docker_hosts can wire links.
llb2_pid=$(docker inspect -f '{{.State.Pid}}' llb2 2>/dev/null || echo "")
if [ -n "$llb2_pid" ] && [ "$llb2_pid" != "0" ]; then
  sudo mkdir -p /var/run/netns
  sudo touch /var/run/netns/llb2
  sudo mount -o bind /proc/${llb2_pid}/ns/net /var/run/netns/llb2 2>/dev/null || true
  sudo ip netns exec llb2 ip link set lo up 2>/dev/null || true
  sudo ip netns exec llb2 sysctl net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
  echo "[HA] llb2 netns registered (pid=$llb2_pid)"
else
  echo "WARN: llb2 PID could not be determined; subsequent network setup will fail"
fi

# Append llb2 to global loxilbs array so common.sh helpers know about it.
loxilbs+=("llb2")

connect_docker_hosts l3h1  llb2
connect_docker_hosts l3ep1 llb2
connect_docker_hosts l3ep2 llb2

# llb2 takes the .253 last-octet on each subnet (llb1 has .254).
config_docker_host --host1 llb2 --host2 l3h1  --ptype phy --addr 10.10.10.253/24
config_docker_host --host1 llb2 --host2 l3ep1 --ptype phy --addr 31.31.31.253/24
config_docker_host --host1 llb2 --host2 l3ep2 --ptype phy --addr 32.32.32.253/24

# Proxy ARP + IPv4 forwarding on l3h1 + each EP netns. DO NOT use a Linux
# bridge — broke pd_disagg HTTP/0.9; expected to break vllm-
# fullproxy HTTPS termination similarly.
sudo ip netns exec l3h1 sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sudo ip netns exec l3h1 sysctl -w net.ipv4.conf.all.proxy_arp=1 >/dev/null 2>&1 || true
sudo ip netns exec l3h1 sysctl -w net.ipv4.conf.el3h1llb1.proxy_arp=1 >/dev/null 2>&1 || true
sudo ip netns exec l3h1 sysctl -w net.ipv4.conf.el3h1llb2.proxy_arp=1 >/dev/null 2>&1 || true
sudo ip -n l3h1 route add 10.10.10.253/32 dev el3h1llb2 proto static 2>/dev/null || true
sudo ip -n l3h1 route add 10.10.10.254/32 dev el3h1llb1 proto static 2>/dev/null || true

# Same forwarding setup for the 2 EP subnets (vllm-fullproxy has 2 EPs only —
# l3ep3 and l3ep4 are pd_disagg-specific). For each l3ep<n>: enable forwarding
# + proxy_arp so llb1 (.254) and llb2 (.253) can both reach .1 (the vLLM
# server) and the EP's reply can route back to either loxilb.
for n in 1 2; do
  sudo ip netns exec l3ep${n} sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  sudo ip netns exec l3ep${n} sysctl -w net.ipv4.conf.all.proxy_arp=1 >/dev/null 2>&1 || true
  sudo ip netns exec l3ep${n} sysctl -w net.ipv4.conf.el3ep${n}llb1.proxy_arp=1 >/dev/null 2>&1 || true
  sudo ip netns exec l3ep${n} sysctl -w net.ipv4.conf.el3ep${n}llb2.proxy_arp=1 >/dev/null 2>&1 || true
  sub="3${n}.3${n}.3${n}"
  sudo ip -n l3ep${n} route add ${sub}.253/32 dev el3ep${n}llb2 proto static 2>/dev/null || true
  sudo ip -n l3ep${n} route add ${sub}.254/32 dev el3ep${n}llb1 proto static 2>/dev/null || true
done

# Binary overlay — deploy the LOCALLY-BUILT ./loxilb into both containers,
# replacing the (potentially stale) registry image binary. Harness-
# fidelity gate. Pattern from scripts/probe-sockproxy-sync-wiring.sh:79-85.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ -f "$REPO_ROOT/loxilb" ]; then
  for LLB in llb1 llb2; do
    docker exec "$LLB" pkill -9 -f /root/loxilb-io/loxilb/loxilb 2>/dev/null || true
    docker exec "$LLB" mkdir -p /var/log/loxilb 2>/dev/null || true
    docker cp "$REPO_ROOT/loxilb" "$LLB:/root/loxilb-io/loxilb/loxilb"
    echo "[HA] $LLB: binary overlaid from $REPO_ROOT/loxilb"
  done
  # Binary-fidelity assertion — locally-built binary must contain
  # SockproxySync code (verified via embedded format strings).
  for LLB in llb1 llb2; do
    MARKER_COUNT=$(docker exec "$LLB" sh -c 'strings /root/loxilb-io/loxilb/loxilb 2>/dev/null | grep -c SOCKPROXY_SYNC' 2>/dev/null || echo 0)
    echo "[HA] $LLB: SOCKPROXY_SYNC markers in binary = $MARKER_COUNT (must be >= 3)"
    if [ "${MARKER_COUNT:-0}" -lt 3 ]; then
      echo "FATAL: $LLB binary lacks SockproxySync markers — make build first"
      exit 1
    fi
  done
else
  echo "FATAL: $REPO_ROOT/loxilb not found — run 'make build' first"
  exit 1
fi

# Restart loxilb in both containers with stdout redirected to a file inside
# the container. CRITICAL: the container entrypoint is /bin/bash, NOT loxilb,
# so `docker logs <name>` returns empty. We must redirect to a file and read
# it back via `docker exec <name> cat` (memory entry
# loxilb_docker_logs_vs_loxilb_stdout).
docker exec -dt llb1 bash -c '/root/loxilb-io/loxilb/loxilb --cluster=10.10.10.253 --self=0 --ka=10.10.10.253:10.10.10.254 > /var/log/loxilb/loxilb-stdout.log 2>&1'
docker exec -dt llb2 bash -c '/root/loxilb-io/loxilb/loxilb --cluster=10.10.10.254 --self=1 --ka=10.10.10.254:10.10.10.253 > /var/log/loxilb/loxilb-stdout.log 2>&1'
sleep 5

# Re-install LB rules on BOTH nodes — after failover, llb2 must
# already have the 4 rules so traffic continues without a control-plane
# round-trip. LB rules are NOT persisted across loxilb process restart, so
# we re-install after the docker-cp binary overlay restart.
vllm_fullproxy_install_lb_rules llb1
vllm_fullproxy_install_lb_rules llb2

# Cistate convergence poll — wait up to 30s for both loxilbs to elect roles
# via BFD keepalive. cluster.go default instance name is "llb-inst0" (NOT
# "default"); treat NOT_DEFINED as pre-election initializing state.
read_cistate() {
  $dexec "$1" curl -s 'http://127.0.0.1:11111/netlox/v1/config/cistate/all' 2>/dev/null | \
    python3 -c "import sys,json
try:
  d=json.load(sys.stdin)
  for a in d.get('Attr',[]):
    if a.get('instance')=='llb-inst0':
      print(a.get('state','UNKNOWN'))
      break
except: print('UNKNOWN')" 2>/dev/null || echo UNKNOWN
}

echo "[HA] Waiting up to 30s for cluster keepalive election to converge..."
MASTER_LLB1=""
MASTER_LLB2=""
for i in $(seq 1 30); do
  MASTER_LLB1=$(read_cistate llb1)
  MASTER_LLB2=$(read_cistate llb2)
  if [ -n "$MASTER_LLB1" ] && [ "$MASTER_LLB1" != "UNKNOWN" ] && [ "$MASTER_LLB1" != "NOT_DEFINED" ] && \
     [ -n "$MASTER_LLB2" ] && [ "$MASTER_LLB2" != "UNKNOWN" ] && [ "$MASTER_LLB2" != "NOT_DEFINED" ] && \
     [ "$MASTER_LLB1" != "$MASTER_LLB2" ]; then
    echo "[HA] Converged after ${i}s: llb1=$MASTER_LLB1, llb2=$MASTER_LLB2"
    break
  fi
  sleep 1
done
echo "[HA] Final cistate: llb1=$MASTER_LLB1, llb2=$MASTER_LLB2 (expect llb1=MASTER, llb2=BACKUP via --self ordinal)"

fi  # PHASE_L_HA
