#!/bin/bash
# cicd/llamacpp-lb/config.sh — llama.cpp plain-LB CICD scenario. Tests the
# fourth typed engine's ONLY supported rule shape (plain L7 LB with
# CHWBL/session affinity — no KV plane, no P/D) using mock_llamacpp.py
# (no GPU required). The mock speaks the live-pinned b10524 contract:
# silent-unknown-fields, malformed-JSON -> 500, ":" SSE ping comments,
# cached_tokens receipts from a per-process prefix store, /props for the
# phase-1 warn-probe.
#
# Topology (the trtllm-pd-disagg layout, all four engines per EP where the
# quad-coexistence leg needs them):
#   l3h1  (10.10.10.1/24)  ── llb1 (loxilb, 10.10.10.254/24)
#   l3ep1 (31.31.31.1/24)  ── llb1 (31.31.31.254/24)
#   l3ep2 (32.32.32.1/24)  ── llb1 (32.32.32.254/24)
#   l3ep3 (33.33.33.1/24)  ── llb1 (33.33.33.254/24)
#
# Mocks per EP:
#   :8085 mock_llamacpp  (subject; admin 127.0.0.1:9700; l3ep3 runs a
#         MISMATCHED --build so the typed-rule admission probe has a real
#         build_mismatch warning to surface — leg J's fixture)
#   :8355 mock_trtllm    (context/context/generation; quad-coexistence)
#   :8100 mock_sglang_pd (prefill A/B bootstrap :9998, decode)
#   :8000 mock_vllm      (prefill/prefill/decode, nixl 9001/9003/9002)
#
# LB rules (REST):
#   Port 2044 — llamacpp typed CHWBL (subject under test): sel=8 +
#               kvEngineType=llamacpp. Creation fires the /props warn-probe.
#   Port 2045 — llamacpp RR + session_header_name=x-session-id (stickiness
#               + hold-out/demotion legs run here: rotation makes EP
#               avoidance assertable).
#   Port 2040/2042/2043 — trtllm/sglang/vllm P/D coexistence rules.

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
echo "Starting mock llama.cpp servers (subject under test)"
echo "#########################################"

for ep in l3ep1 l3ep2 l3ep3; do
  docker cp "$(dirname "$0")/mock_llamacpp.py" $ep:/tmp/mock_llamacpp.py
done
# l3ep3 runs a mismatched build on purpose: the typed-rule /props admission
# probe must have a real fleet-skew warning to surface (leg J).
$dexec l3ep1 bash -c "nohup python3 /tmp/mock_llamacpp.py --port 8085 --ep-idx 1 --build b10524-mock > /tmp/llamacpp-ep1.log 2>&1 &"
$dexec l3ep2 bash -c "nohup python3 /tmp/mock_llamacpp.py --port 8085 --ep-idx 2 --build b10524-mock > /tmp/llamacpp-ep2.log 2>&1 &"
$dexec l3ep3 bash -c "nohup python3 /tmp/mock_llamacpp.py --port 8085 --ep-idx 3 --build b10525-mock > /tmp/llamacpp-ep3.log 2>&1 &"

echo "#########################################"
echo "Starting mock TRT-LLM + SGLang + vLLM servers (quad coexistence)"
echo "#########################################"

for ep in l3ep1 l3ep2 l3ep3; do
  docker cp "$(dirname "$0")/../trtllm-pd-disagg/mock_trtllm.py" $ep:/tmp/mock_trtllm.py
  docker cp "$(dirname "$0")/../sglang-pd-disagg/mock_sglang_pd.py" $ep:/tmp/mock_sglang_pd.py
  docker cp "$(dirname "$0")/../vllm-pd-disagg/mock_vllm.py" $ep:/tmp/mock_vllm.py
done
$dexec l3ep1 bash -c "nohup python3 /tmp/mock_trtllm.py --role context    --port 8355 --ep-idx 1 > /tmp/trtllm-ctx1.log 2>&1 &"
$dexec l3ep2 bash -c "nohup python3 /tmp/mock_trtllm.py --role context    --port 8355 --ep-idx 2 > /tmp/trtllm-ctx2.log 2>&1 &"
$dexec l3ep3 bash -c "nohup python3 /tmp/mock_trtllm.py --role generation --port 8355 --ep-idx 3 > /tmp/trtllm-gen3.log 2>&1 &"
$dexec l3ep1 bash -c "nohup python3 /tmp/mock_sglang_pd.py --role prefill --port 8100 --bootstrap-port 9998 --expect-host 31.31.31.1 --ep-idx 1 > /tmp/sglang-prefill1.log 2>&1 &"
$dexec l3ep2 bash -c "nohup python3 /tmp/mock_sglang_pd.py --role prefill --port 8100 --bootstrap-port 9998 --expect-host 32.32.32.1 --ep-idx 2 > /tmp/sglang-prefill2.log 2>&1 &"
$dexec l3ep3 bash -c "nohup python3 /tmp/mock_sglang_pd.py --role decode --port 8100 --ep-idx 3 > /tmp/sglang-decode3.log 2>&1 &"
$dexec l3ep1 bash -c "nohup python3 /tmp/mock_vllm.py --role prefill --port 8000 --nixl-port 9001 --ep-idx 1 > /tmp/vllm-prefill1.log 2>&1 &"
$dexec l3ep2 bash -c "nohup python3 /tmp/mock_vllm.py --role prefill --port 8000 --nixl-port 9003 --ep-idx 2 > /tmp/vllm-prefill2.log 2>&1 &"
$dexec l3ep3 bash -c "nohup python3 /tmp/mock_vllm.py --role decode --port 8000 --nixl-port 9002 --ep-idx 3 > /tmp/vllm-decode3.log 2>&1 &"

echo "Waiting for mock servers to answer /health..."
for spec in "l3ep1 8085" "l3ep2 8085" "l3ep3 8085" "l3ep1 8355" "l3ep2 8355" "l3ep3 8355" "l3ep1 8100" "l3ep2 8100" "l3ep3 8100" "l3ep1 8000" "l3ep2 8000" "l3ep3 8000"; do
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
echo "Installing LB rules on llb1 (2044/2045 + coexistence 2040/2042/2043)"
echo "#########################################"

# Port 2044 — llamacpp typed CHWBL (subject under test). sel=8 = CHWBL
# (content prefix-hash on the SYSTEM prompt — HAVE_LLM_SYSTEM_PROMPT_HASH
# builds). Creation fires the /props admission warn-probe (l3ep3's
# mismatched build must tick loxilb_ai_llamacpp_probe_warnings_total).
$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H 'Content-Type: application/json' \
  -d '{"serviceArguments":{"externalIP":"'"$VIP"'","port":2044,"protocol":"tcp","sel":8,"mode":4,"security":1,"kvEngineType":"llamacpp","sse_mode":true,"host":"'"$VIP"'","monitor":true,"cb_enable":true,"probetype":"http","probeport":8085,"probereq":"/health","probeTimeout":5,"probeRetries":2},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8085,"weight":1},{"endpointIP":"32.32.32.1","targetPort":8085,"weight":1},{"endpointIP":"33.33.33.1","targetPort":8085,"weight":1}]}'
echo ""

# Port 2045 — llamacpp RR + session header (stickiness leg; rotation also
# makes the hold-out/demotion legs' EP-avoidance assertable).
$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H 'Content-Type: application/json' \
  -d '{"serviceArguments":{"externalIP":"'"$VIP"'","port":2045,"protocol":"tcp","sel":0,"mode":4,"security":1,"kvEngineType":"llamacpp","session_header_name":"x-session-id","sse_mode":true,"host":"'"$VIP"'","monitor":true,"cb_enable":true,"probetype":"http","probeport":8085,"probereq":"/health","probeTimeout":5,"probeRetries":2},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8085,"weight":1},{"endpointIP":"32.32.32.1","targetPort":8085,"weight":1},{"endpointIP":"33.33.33.1","targetPort":8085,"weight":1}]}'
echo ""

# Port 2040 — TRT-LLM P/D coexistence rule (sequential rewriter machine).
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
echo "  Port 2044: llamacpp typed CHWBL (subject; :8085, admission probe fired)"
echo "  Port 2045: llamacpp RR + session_header_name=x-session-id"
echo "  Port 2040/2042/2043: trtllm/sglang/vllm P/D coexistence"
