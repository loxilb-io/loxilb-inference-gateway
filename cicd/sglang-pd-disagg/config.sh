#!/bin/bash
# cicd/sglang-pd-disagg/config.sh — SGLang P/D disaggregation CICD scenario
# Tests the CONCURRENT dual-dispatch orchestrator using mock_sglang_pd.py
# (no GPU required). The mock prefill BLOCKS its response until a decode
# request with the same bootstrap room joins its bootstrap listener — a
# sequential proxy therefore fails this scenario by construction, pinning
# the dual-dispatch requirement forever (design §3.6.2).
#
# Topology:
#   l3h1  (10.10.10.1/24)  ── llb1 (loxilb, 10.10.10.254/24)
#   l3ep1 (31.31.31.1/24)  ── llb1 (31.31.31.254/24)  [sglang prefill A + vllm prefill]
#   l3ep2 (32.32.32.1/24)  ── llb1 (32.32.32.254/24)  [sglang prefill B]
#   l3ep3 (33.33.33.1/24)  ── llb1 (33.33.33.254/24)  [sglang decode + vllm decode]
#
# EP containers get a default route via their llb1-side .254 address: the
# decode mock must reach the PREFILL's bootstrap listener across subnets
# (e.g. 33.33.33.1 -> 31.31.31.1:9998) exactly like a real SGLang decode
# engine contacts the prefill's --disaggregation-bootstrap-port.
#
# Mocks per EP (two processes where coexistence needs both flavors):
#   l3ep1: mock_sglang_pd --role prefill :8100 (bootstrap :9998)  +  mock_vllm --role prefill :8000 (nixl 9001)
#   l3ep2: mock_sglang_pd --role prefill :8100 (bootstrap :9998)
#   l3ep3: mock_sglang_pd --role decode  :8100                    +  mock_vllm --role decode  :8000 (nixl 9002)
#
# LB rules (installed via REST — loxicmd has no --pd-bootstrap-port flag yet):
#   Port 2030 — SGLang P/D: pd_disagg_mode + kvEngineType=sglang +
#               pdBootstrapPort=9998 (NON-default on purpose: proves the knob
#               plumbs through; SGLang's default is 8998), eps 2P+1D on :8100.
#   Port 2031 — vLLM P/D coexistence rule: default engine, eps 1P+1D on :8000.

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
echo "Configuring IP addresses and routes"
echo "#########################################"

config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 llb1  --host2 l3h1 --ptype phy --addr 10.10.10.254/24
# EPs need --gw so decode can reach the prefill bootstrap port across subnets
# (llb1 routes between its directly-attached /24s).
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 l3ep3 --host2 llb1 --ptype phy --addr 33.33.33.1/24 --gw 33.33.33.254
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1  --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb1  --host2 l3ep3 --ptype phy --addr 33.33.33.254/24

echo "#########################################"
echo "Preparing TLS certificates"
echo "#########################################"

# minica (github.com/jsha/minica) is fetched on demand — no binary is committed.
MINICA="$(command -v minica || echo "$(go env GOPATH)/bin/minica")"
[ -x "$MINICA" ] || { go install github.com/jsha/minica@latest; MINICA="$(go env GOPATH)/bin/minica"; }
"$MINICA" --ip-addresses 10.10.10.254
docker cp minica.pem llb1:/opt/loxilb/cert/rootCA.crt
docker cp 10.10.10.254/cert.pem llb1:/opt/loxilb/cert/server.crt
docker cp 10.10.10.254/key.pem  llb1:/opt/loxilb/cert/server.key
docker cp minica.pem l3h1:/tmp/minica.pem

echo "#########################################"
echo "Installing python3 in endpoint containers"
echo "#########################################"

for ep in l3ep1 l3ep2 l3ep3; do
  # Prefer the image-baked python3; apt only as fallback with the Korean
  # mirror (recurring archive.ubuntu.com flakiness on this infra).
  if ! $dexec $ep python3 --version > /dev/null 2>&1; then
    $dexec $ep bash -c "sed -i 's|//archive.ubuntu.com|//kr.archive.ubuntu.com|g' /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true; apt-get update > /dev/null 2>&1 && apt-get install -y python3 > /dev/null 2>&1"
  fi
  $dexec $ep python3 --version || { echo "FATAL: python3 install failed on $ep"; exit 1; }
done

echo "#########################################"
echo "Starting mock SGLang P/D servers"
echo "#########################################"

docker cp "$(dirname "$0")/mock_sglang_pd.py" l3ep1:/tmp/mock_sglang_pd.py
docker cp "$(dirname "$0")/mock_sglang_pd.py" l3ep2:/tmp/mock_sglang_pd.py
docker cp "$(dirname "$0")/mock_sglang_pd.py" l3ep3:/tmp/mock_sglang_pd.py
# --expect-host pins the gateway-injected bootstrap_host to THIS EP's own IP.
$dexec l3ep1 bash -c "nohup python3 /tmp/mock_sglang_pd.py --role prefill --port 8100 --bootstrap-port 9998 --expect-host 31.31.31.1 --ep-idx 1 > /tmp/sglang-prefill1.log 2>&1 &"
$dexec l3ep2 bash -c "nohup python3 /tmp/mock_sglang_pd.py --role prefill --port 8100 --bootstrap-port 9998 --expect-host 32.32.32.1 --ep-idx 2 > /tmp/sglang-prefill2.log 2>&1 &"
$dexec l3ep3 bash -c "nohup python3 /tmp/mock_sglang_pd.py --role decode --port 8100 --ep-idx 3 > /tmp/sglang-decode3.log 2>&1 &"

echo "#########################################"
echo "Starting mock vLLM servers (coexistence rule)"
echo "#########################################"

docker cp "$(dirname "$0")/../vllm-pd-disagg/mock_vllm.py" l3ep1:/tmp/mock_vllm.py
docker cp "$(dirname "$0")/../vllm-pd-disagg/mock_vllm.py" l3ep3:/tmp/mock_vllm.py
# mock_vllm admin binds 127.0.0.1:9000 (fixed); mock_sglang_pd admin uses
# 9100 — no collision inside the shared containers.
$dexec l3ep1 bash -c "nohup python3 /tmp/mock_vllm.py --role prefill --port 8000 --nixl-port 9001 --ep-idx 1 > /tmp/vllm-prefill1.log 2>&1 &"
$dexec l3ep3 bash -c "nohup python3 /tmp/mock_vllm.py --role decode --port 8000 --nixl-port 9002 --ep-idx 3 > /tmp/vllm-decode3.log 2>&1 &"

echo "Waiting for mock servers to answer /health..."
for spec in "l3ep1 8100" "l3ep2 8100" "l3ep3 8100" "l3ep1 8000" "l3ep3 8000"; do
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
echo "Installing LB rules on llb1 (ports 2030/2031)"
echo "#########################################"

# Port 2030 — SGLang P/D (the subject under test). REST path: loxicmd does
# not carry kvEngineType/pdBootstrapPort flags yet.
$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H 'Content-Type: application/json' \
  -d '{"serviceArguments":{"externalIP":"'"$VIP"'","port":2030,"protocol":"tcp","sel":0,"mode":4,"security":1,"pd_disagg_mode":true,"kvEngineType":"sglang","pdBootstrapPort":9998,"sse_mode":true,"host":"'"$VIP"'","monitor":true,"cb_enable":true,"probetype":"http","probeport":8100,"probereq":"/health","probeTimeout":5,"probeRetries":2},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8100,"weight":1,"ep_role":1},{"endpointIP":"32.32.32.1","targetPort":8100,"weight":1,"ep_role":1},{"endpointIP":"33.33.33.1","targetPort":8100,"weight":1,"ep_role":2}]}'
echo ""

# Port 2031 — vLLM P/D coexistence rule (default engine).
$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H 'Content-Type: application/json' \
  -d '{"serviceArguments":{"externalIP":"'"$VIP"'","port":2031,"protocol":"tcp","sel":0,"mode":4,"security":1,"pd_disagg_mode":true,"sse_mode":true,"host":"'"$VIP"'","monitor":true,"probetype":"http","probeport":8000,"probereq":"/health","probeTimeout":5,"probeRetries":2},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8000,"weight":1,"ep_role":1,"nixl_port":9001},{"endpointIP":"33.33.33.1","targetPort":8000,"weight":1,"ep_role":2,"nixl_port":9002}]}'
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
    grep -c '"inActiveEP":true' 2>/dev/null || echo "999")
  if [ "$INACTIVE_COUNT" = "0" ]; then
    echo "  All endpoints active after ${i}s"
    break
  fi
  sleep 1
done

echo "#########################################"
echo "Configuration complete"
echo "#########################################"
echo "  Port 2030: SGLang P/D (l3ep1+l3ep2 prefill :8100 bootstrap :9998, l3ep3 decode :8100)"
echo "  Port 2031: vLLM P/D coexistence (l3ep1 prefill :8000/nixl 9001, l3ep3 decode :8000/nixl 9002)"
