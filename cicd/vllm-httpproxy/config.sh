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

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1
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

# Create LB rule: HTTP (frontend) -> HTTP (backend)
# VIP: 10.10.10.254:2020 (HTTP) - round-robin for general validation
# Backends: 31.31.31.1:8000, 32.32.32.1:8000 (HTTP)
$dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2020,
    "protocol": "tcp",
    "sel": 0,
    "mode": 4,
    "host": "10.10.10.254"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8000, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8000, "weight": 1 }
  ]
}'
# Level1
$dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2021,
    "protocol": "tcp",
    "sel": 8,
    "mode": 4,
    "host": "10.10.10.254",
    "chwbl_prefix_hash_level": 1
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8000, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8000, "weight": 1 }
  ]
}'
# Level2
$dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2022,
    "protocol": "tcp",
    "sel": 8,
    "mode": 4,
    "host": "10.10.10.254",
    "chwbl_prefix_hash_level": 2,
    "chwbl_mean_load_factor": 125,
    "chwbl_replication": 100
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8000, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8000, "weight": 1 }
  ]
}'
# Level3
$dexec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2023,
    "protocol": "tcp",
    "sel": 8,
    "mode": 4,
    "host": "10.10.10.254",
    "chwbl_prefix_hash_level": 3,
    "chwbl_mean_load_factor": 250,
    "chwbl_replication": 200
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8000, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8000, "weight": 1 }
  ]
}'
echo "#########################################"
echo "Configuration complete"
echo "#########################################"
echo "LoxiLB VIP: http://10.10.10.254:2020"
echo "Backend vLLM servers:"
echo "  - server1: http://31.31.31.1:8000"
echo "  - server2: http://32.32.32.1:8000"
echo ""
echo "Test endpoints:"
echo "  - List models: curl -sk http://10.10.10.254:2020/v1/models | jq ."
echo "  - Completion: curl -sk http://10.10.10.254:2020/v1/completions -d '{...}'"
