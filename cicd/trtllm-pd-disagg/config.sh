#!/bin/bash
# cicd/trtllm-pd-disagg/config.sh — TensorRT-LLM P/D disaggregation CICD
# scenario. Tests the SEQUENTIAL context-first rewriter dialect
# (pd_dialect_trtllm) using mock_trtllm.py (no GPU required). The mock
# enforces extra="forbid" (any unknown request field 400s) and requires the
# generation leg to carry an encoded_opaque_state the context mock actually
# issued — a proxy that reconstructs instead of relaying the extracted span
# fails this scenario by construction.
#
# Topology (the sglang-pd-disagg layout):
#   l3h1  (10.10.10.1/24)  ── llb1 (loxilb, 10.10.10.254/24)
#   l3ep1 (31.31.31.1/24)  ── llb1 (31.31.31.254/24)  [trtllm CONTEXT + vllm prefill + sglang prefill A]
#   l3ep2 (32.32.32.1/24)  ── llb1 (32.32.32.254/24)  [trtllm CONTEXT + sglang prefill B]
#   l3ep3 (33.33.33.1/24)  ── llb1 (33.33.33.254/24)  [trtllm GENERATION + vllm decode + sglang decode]
#
# Mocks per EP (tri-engine coexistence, one process per engine flavor):
#   :8355 mock_trtllm   (context/context/generation, admin 127.0.0.1:9600)
#   :8100 mock_sglang_pd (prefill A/B bootstrap :9998, decode; admin :9100)
#   :8000 mock_vllm     (prefill/prefill/decode, nixl 9001/9003/9002; admin :9000)
#
# LB rules (REST):
#   Port 2040 — TRT-LLM P/D (subject under test): pd_disagg_mode +
#               kvEngineType=trtllm + kvExactMode=1 + kvBlockSize=32
#               (the polled-drain KV plane subscribes the CONTEXT EPs'
#               serving ports — SOLE consumer of :8355 /kv_cache_events).
#   Port 2042 — SGLang P/D coexistence rule (dual-dispatch machine).
#   Port 2043 — vLLM P/D coexistence rule (the sibling sequential machine).

source ../common.sh
exec < /dev/null

VIP="10.10.10.254"

echo "#########################################"
echo "Spawning Docker hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1
spawn_docker_host --dock-type host   --dock-name l3ep1
spawn_docker_host --dock-type host   --dock-name l3ep2
spawn_docker_host --dock-type host   --dock-name l3ep3
spawn_docker_host --dock-type host   --dock-name l3h1

echo "#########################################"
echo "Connecting Docker hosts"
echo "#########################################"

connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1
connect_docker_hosts l3ep3 llb1

echo "#########################################"
echo "Installing python3 in endpoint containers"
echo "#########################################"

# Must run BEFORE the EP default routes move to llb1 below (no internet
# egress afterwards; sglang-pd-disagg precedent).
for ep in l3ep1 l3ep2 l3ep3; do
  if ! $dexec $ep python3 --version > /dev/null 2>&1; then
    $dexec $ep bash -c "sed -i 's|//archive.ubuntu.com|//kr.archive.ubuntu.com|g' /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true; apt-get update > /dev/null 2>&1 && apt-get install -y python3 > /dev/null 2>&1"
  fi
  $dexec $ep python3 --version || { echo "FATAL: python3 install failed on $ep"; exit 1; }
done

echo "#########################################"
echo "Configuring IP addresses and routes"
echo "#########################################"

config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 llb1  --host2 l3h1 --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 l3ep3 --host2 llb1 --ptype phy --addr 33.33.33.1/24 --gw 33.33.33.254
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1  --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb1  --host2 l3ep3 --ptype phy --addr 33.33.33.254/24

echo "#########################################"
echo "Preparing TLS certificates"
echo "#########################################"

# Pre-shipped certs are honored (runner boxes without a Go toolchain).
if [ ! -f minica.pem ] || [ ! -f 10.10.10.254/cert.pem ]; then
  MINICA="$(command -v minica || echo "$(go env GOPATH)/bin/minica")"
  [ -x "$MINICA" ] || { go install github.com/jsha/minica@latest; MINICA="$(go env GOPATH)/bin/minica"; }
  "$MINICA" --ip-addresses 10.10.10.254
fi
docker cp minica.pem llb1:/opt/loxilb/cert/rootCA.crt
docker cp 10.10.10.254/cert.pem llb1:/opt/loxilb/cert/server.crt
docker cp 10.10.10.254/key.pem  llb1:/opt/loxilb/cert/server.key
docker cp minica.pem l3h1:/tmp/minica.pem

echo "#########################################"
echo "Starting mock TRT-LLM servers (subject under test)"
echo "#########################################"

for ep in l3ep1 l3ep2 l3ep3; do
  docker cp "$(dirname "$0")/mock_trtllm.py" $ep:/tmp/mock_trtllm.py
done
$dexec l3ep1 bash -c "nohup python3 /tmp/mock_trtllm.py --role context    --port 8355 --ep-idx 1 > /tmp/trtllm-ctx1.log 2>&1 &"
$dexec l3ep2 bash -c "nohup python3 /tmp/mock_trtllm.py --role context    --port 8355 --ep-idx 2 > /tmp/trtllm-ctx2.log 2>&1 &"
$dexec l3ep3 bash -c "nohup python3 /tmp/mock_trtllm.py --role generation --port 8355 --ep-idx 3 > /tmp/trtllm-gen3.log 2>&1 &"

echo "#########################################"
echo "Starting mock SGLang + vLLM servers (tri-engine coexistence)"
echo "#########################################"

for ep in l3ep1 l3ep2 l3ep3; do
  docker cp "$(dirname "$0")/../sglang-pd-disagg/mock_sglang_pd.py" $ep:/tmp/mock_sglang_pd.py
  docker cp "$(dirname "$0")/../vllm-pd-disagg/mock_vllm.py" $ep:/tmp/mock_vllm.py
done
$dexec l3ep1 bash -c "nohup python3 /tmp/mock_sglang_pd.py --role prefill --port 8100 --bootstrap-port 9998 --expect-host 31.31.31.1 --ep-idx 1 > /tmp/sglang-prefill1.log 2>&1 &"
$dexec l3ep2 bash -c "nohup python3 /tmp/mock_sglang_pd.py --role prefill --port 8100 --bootstrap-port 9998 --expect-host 32.32.32.1 --ep-idx 2 > /tmp/sglang-prefill2.log 2>&1 &"
$dexec l3ep3 bash -c "nohup python3 /tmp/mock_sglang_pd.py --role decode --port 8100 --ep-idx 3 > /tmp/sglang-decode3.log 2>&1 &"
$dexec l3ep1 bash -c "nohup python3 /tmp/mock_vllm.py --role prefill --port 8000 --nixl-port 9001 --ep-idx 1 > /tmp/vllm-prefill1.log 2>&1 &"
$dexec l3ep2 bash -c "nohup python3 /tmp/mock_vllm.py --role prefill --port 8000 --nixl-port 9003 --ep-idx 2 > /tmp/vllm-prefill2.log 2>&1 &"
$dexec l3ep3 bash -c "nohup python3 /tmp/mock_vllm.py --role decode --port 8000 --nixl-port 9002 --ep-idx 3 > /tmp/vllm-decode3.log 2>&1 &"

echo "Waiting for mock servers to answer /health..."
for spec in "l3ep1 8355" "l3ep2 8355" "l3ep3 8355" "l3ep1 8100" "l3ep2 8100" "l3ep3 8100" "l3ep1 8000" "l3ep2 8000" "l3ep3 8000"; do
  set -- $spec
  ep="$1"; port="$2"
  ok=0
  for i in $(seq 1 20); do
    if $dexec $ep curl -sf http://localhost:$port/health > /dev/null 2>&1; then
      ok=1; break
    fi
    sleep 1
  done
  [ "$ok" = "1" ] && echo "  $ep:$port healthy" || echo "  WARNING: $ep:$port did not answer /health"
done

echo "#########################################"
echo "Installing LB rules on llb1 (ports 2040/2042/2043)"
echo "#########################################"

# Port 2040 — TRT-LLM P/D (subject under test). REST path: loxicmd carries
# no kvEngineType flag yet. kvExactMode=1 subscribes the CONTEXT EPs over
# the HTTP-polled drain (kvZmqPort deliberately absent — rejected non-
# default for this engine).
$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H 'Content-Type: application/json' \
  -d '{"serviceArguments":{"externalIP":"'"$VIP"'","port":2040,"protocol":"tcp","sel":0,"mode":4,"security":1,"pd_disagg_mode":true,"kvEngineType":"trtllm","kvExactMode":1,"kvBlockSize":32,"kvWarmupSec":5,"sse_mode":true,"host":"'"$VIP"'","monitor":true,"cb_enable":true,"probetype":"http","probeport":8355,"probereq":"/health","probeTimeout":5,"probeRetries":2},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8355,"weight":1,"ep_role":1},{"endpointIP":"32.32.32.1","targetPort":8355,"weight":1,"ep_role":1},{"endpointIP":"33.33.33.1","targetPort":8355,"weight":1,"ep_role":2}]}'
echo ""

# Port 2042 — SGLang P/D coexistence rule (dual-dispatch machine).
$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H 'Content-Type: application/json' \
  -d '{"serviceArguments":{"externalIP":"'"$VIP"'","port":2042,"protocol":"tcp","sel":0,"mode":4,"security":1,"pd_disagg_mode":true,"kvEngineType":"sglang","pdBootstrapPort":9998,"sse_mode":true,"host":"'"$VIP"'","monitor":true,"cb_enable":true,"probetype":"http","probeport":8100,"probereq":"/health","probeTimeout":5,"probeRetries":2},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8100,"weight":1,"ep_role":1},{"endpointIP":"32.32.32.1","targetPort":8100,"weight":1,"ep_role":1},{"endpointIP":"33.33.33.1","targetPort":8100,"weight":1,"ep_role":2}]}'
echo ""

# Port 2043 — vLLM P/D coexistence rule (default engine).
$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H 'Content-Type: application/json' \
  -d '{"serviceArguments":{"externalIP":"'"$VIP"'","port":2043,"protocol":"tcp","sel":0,"mode":4,"security":1,"pd_disagg_mode":true,"sse_mode":true,"host":"'"$VIP"'","monitor":true,"cb_enable":true,"probetype":"http","probeport":8000,"probereq":"/health","probeTimeout":5,"probeRetries":2},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8000,"weight":1,"ep_role":1,"nixl_port":9001},{"endpointIP":"32.32.32.1","targetPort":8000,"weight":1,"ep_role":1,"nixl_port":9003},{"endpointIP":"33.33.33.1","targetPort":8000,"weight":1,"ep_role":2,"nixl_port":9002}]}'
echo ""

echo "#########################################"
echo "Enabling Prometheus metrics"
echo "#########################################"

$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/metrics
echo ""

sleep 5

echo "Waiting for health probes to mark all endpoints active (up to 60s)..."
for i in $(seq 1 60); do
  INACTIVE_COUNT=$($hexec llb1 curl -s "http://localhost:11111/netlox/v1/config/loadbalancer/all" 2>/dev/null | \
    grep -c '"state":"inactive"' 2>/dev/null || echo "999")
  if [ "$INACTIVE_COUNT" = "0" ]; then
    echo "  All endpoints active after ${i}s"
    break
  fi
  sleep 1
done

echo "#########################################"
echo "Configuration complete"
echo "#########################################"
echo "  Port 2040: TRT-LLM P/D (l3ep1+l3ep2 CONTEXT :8355, l3ep3 GENERATION :8355; kvExactMode=1)"
echo "  Port 2042: SGLang P/D coexistence (:8100, bootstrap :9998)"
echo "  Port 2043: vLLM P/D coexistence (:8000, nixl 9001/9003/9002)"
