#!/bin/bash
# cicd/vllm-pd-disagg/config.sh — P/D disaggregation CICD scenario
# Tests P/D orchestration using mock_vllm.py (no GPU required)
# mock_vllm.py simulates OpenAI-compatible API with prefill/decode roles;
# validates sockproxy C routing, body rewriting, and P/D state machine.
# To switch to real vLLM (GPU testbed): swap mock_vllm.py for real vLLM servers on the EP hosts.
#
# Topology:
#   l3h1  (10.10.10.1/24)   ── llb1 (loxilb, 10.10.10.254/24)   [+ llb2 .253 for Phase L]
#   l3ep1 (31.31.31.1/24)   ── llb1 (31.31.31.254/24)  [prefill, epRole=1, --ep-idx 1]
#   l3ep2 (32.32.32.1/24)   ── llb1 (32.32.32.254/24)  [decode,  epRole=2, --ep-idx 2]
#   l3ep3 (33.33.33.1/24)   ── llb1 (33.33.33.254/24)  [prefill, --ep-idx 3]
#   l3ep4 (34.34.34.1/24)   ── llb1 (34.34.34.254/24)  [decode,  --ep-idx 4]
#
# LB rules: port 2020 / 2021 / 2022 / 2023 (see end of file)
#
# Phase L extension (sockproxy HA sync):
#   - llb2 spawned and wired identically with .253 addresses on every subnet.
#   - HA wired via loxilb cluster keepalive flags (canonical pattern per
#     cicd/common.sh:get_llb_peerIP + pkg/loxinet/utils.go:KAString2Mode):
#       --cluster=<PEER_IP>  --self=<0|1>  --ka=<PEER_IP>:<SELF_IP>
#     sync flows over port 22222 (default sync port). Role election runs over
#     BFD (started by --ka): cluster.go assigns initial role from --self
#     ordinal (0 ⇒ MASTER, 1 ⇒ BACKUP) and switches over on BFD heartbeat
#     loss to peer. No separate BFD/cistate REST POSTs needed.
#   - iptables DNAT on l3h1 maps virtual master IP 10.10.10.99 → 10.10.10.254 initially;
#     validation.sh Phase L re-writes this rule after each failover via `update_master_dnat`.
#   - All four mock_vllm.py spawns pass `--ep-idx N` so X-Prefill-Ep / X-Decode-Ep response
#     headers are populated for restore_rate measurement.

source ../common.sh
exec < /dev/null

# install_lb_rules <target_loxilb_container>
# POST the 4 P/D LB rules (ports 2020/2021/2022/2023) to a loxilb instance.
# Idempotent: re-POST overwrites prior config. Called once for llb1 (single-
# node phases A-K), and again for llb1 + llb2 in Phase L after the loxilb
# processes restart with cluster keepalive flags (LB rules are not persisted
# across loxilb process restart, so they must be re-installed).
install_lb_rules() {
  local target="$1"
  # externalIP is parameterised via
  # ${LB_EXTERNAL_IP:-10.10.10.254} so the vrrp branch can override to
  # 11.11.11.11 (VIP on shared vlan11). Default 10.10.10.254 preserves the
  # legacy bfd-mode externalIP byte-for-byte under PHASE_L_HA_MODE != vrrp.
  local xip="${LB_EXTERNAL_IP:-10.10.10.254}"
  # Endpoint IPs: parameterised so the vrrp branch can override to vlan11 bridge
  # addresses (11.11.11.3-6) via EP1_IP/EP2_IP/EP3_IP/EP4_IP exports.
  # Defaults preserve the legacy bfd-mode /24 EP subnet IPs byte-for-byte.
  local ep1="${EP1_IP:-31.31.31.1}"
  local ep2="${EP2_IP:-32.32.32.1}"
  local ep3="${EP3_IP:-33.33.33.1}"
  local ep4="${EP4_IP:-34.34.34.1}"
  # Port 2020 — P/D disaggregation (l3ep1=prefill, l3ep2=decode).
  $hexec "$target" curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
    -H 'Content-Type: application/json' \
    -d '{"serviceArguments":{"externalIP":"'"$xip"'","port":2020,"protocol":"tcp","sel":0,"mode":4,"security":1,"pd_disagg_mode":true,"sse_mode":true,"host":"'"$xip"'","monitor":true,"probetype":"http","probeport":8000,"probereq":"/health","probeTimeout":5,"probeRetries":2},"endpoints":[{"endpointIP":"'"$ep1"'","targetPort":8000,"weight":1,"ep_role":1,"nixl_port":9001},{"endpointIP":"'"$ep2"'","targetPort":8000,"weight":1,"ep_role":2,"nixl_port":9002}]}' >/dev/null
  # Port 2021 — non-P/D baseline (round-robin).
  $hexec "$target" curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
    -H 'Content-Type: application/json' \
    -d '{"serviceArguments":{"externalIP":"'"$xip"'","port":2021,"protocol":"tcp","sel":0,"mode":4,"security":1,"pd_disagg_mode":false,"sse_mode":true,"host":"'"$xip"'","monitor":true,"probetype":"http","probeport":8000,"probereq":"/health","probeTimeout":5,"probeRetries":2},"endpoints":[{"endpointIP":"'"$ep2"'","targetPort":8000,"weight":1,"ep_role":0}]}' >/dev/null
  # Port 2022 — 2P+2D P/D.
  $hexec "$target" curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
    -H 'Content-Type: application/json' \
    -d '{"serviceArguments":{"externalIP":"'"$xip"'","port":2022,"protocol":"tcp","sel":0,"mode":4,"security":1,"pd_disagg_mode":true,"sse_mode":true,"host":"'"$xip"'","monitor":true,"probetype":"http","probeport":8000,"probereq":"/health","probeTimeout":5,"probeRetries":2},"endpoints":[{"endpointIP":"'"$ep1"'","targetPort":8000,"weight":1,"ep_role":1,"nixl_port":9001},{"endpointIP":"'"$ep3"'","targetPort":8000,"weight":1,"ep_role":1,"nixl_port":9003},{"endpointIP":"'"$ep2"'","targetPort":8000,"weight":1,"ep_role":2,"nixl_port":9002},{"endpointIP":"'"$ep4"'","targetPort":8000,"weight":1,"ep_role":2,"nixl_port":9004}]}' >/dev/null
  # Port 2023 — 2P+2D cache-aware P/D.
  $hexec "$target" curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
    -H 'Content-Type: application/json' \
    -d '{"serviceArguments":{"externalIP":"'"$xip"'","port":2023,"protocol":"tcp","sel":0,"mode":4,"security":1,"pd_disagg_mode":true,"pd_cache_aware_mode":true,"sse_mode":true,"host":"'"$xip"'","monitor":true,"probetype":"http","probeport":8000,"probereq":"/health","probeTimeout":5,"probeRetries":2},"endpoints":[{"endpointIP":"'"$ep1"'","targetPort":8000,"weight":1,"ep_role":1,"nixl_port":9001},{"endpointIP":"'"$ep3"'","targetPort":8000,"weight":1,"ep_role":1,"nixl_port":9003},{"endpointIP":"'"$ep2"'","targetPort":8000,"weight":1,"ep_role":2,"nixl_port":9002},{"endpointIP":"'"$ep4"'","targetPort":8000,"weight":1,"ep_role":2,"nixl_port":9004}]}' >/dev/null
  # Port 2024 — PLAIN session stickiness by X-Conversation-Id (NOT P/D). Exercises
  # conversation_mapping (conv_map): sel=rr + session_header_name pins each conv to
  # one backend; that binding is what sockproxy xSync replicates to the BACKUP, so a
  # conversation survives MASTER failover (validation-convsync.sh). l3ep1/l3ep2 act
  # as plain backends (ep_role=0). externalIP is $xip so the synced service_key
  # matches on both nodes (11.11.11.11 under vrrp).
  $hexec "$target" curl -s -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
    -H 'Content-Type: application/json' \
    -d '{"serviceArguments":{"externalIP":"'"$xip"'","port":2024,"protocol":"tcp","sel":0,"mode":4,"security":1,"session_header_name":"X-Conversation-Id","host":"'"$xip"'","monitor":true,"probetype":"http","probeport":8000,"probereq":"/health","probeTimeout":5,"probeRetries":2},"endpoints":[{"endpointIP":"'"$ep1"'","targetPort":8000,"weight":1,"ep_role":0},{"endpointIP":"'"$ep2"'","targetPort":8000,"weight":1,"ep_role":0}]}' >/dev/null
}

echo "#########################################"
echo "Spawning Docker hosts"
echo "#########################################"

# Phase L: when running Phase L HA test, spawn llb1 with the cluster
# keepalive flags from the start. Restart-in-place leaves stale eBPF state and
# breaks the LB rules' pd_disagg path. Phase A-K (default, no PHASE_L_HA) spawn
# llb1 plain.
# Under PHASE_L_HA_MODE=vrrp the
# llb1 spawn must be plain — keepalived owns HA externally; internal BFD
# (--cluster/--self/--ka) would compete.
# Legacy PHASE_L_HA=1 bfd mode keeps the --extra-args line byte-for-byte.
if [ "${PHASE_L_HA:-0}" = "1" ] && [ "${PHASE_L_HA_MODE:-bfd}" = "bfd" ]; then
  spawn_docker_host --dock-type loxilb  --dock-name llb1 \
    --extra-args "--cluster=10.10.10.253 --self=0 --ka=10.10.10.253:10.10.10.254"
else
  spawn_docker_host --dock-type loxilb  --dock-name llb1
fi
spawn_docker_host --dock-type host    --dock-name l3ep1
spawn_docker_host --dock-type host    --dock-name l3ep2
spawn_docker_host --dock-type host    --dock-name l3ep3
spawn_docker_host --dock-type host    --dock-name l3ep4
spawn_docker_host --dock-type host    --dock-name l3h1

echo "#########################################"
echo "Connecting Docker hosts"
echo "#########################################"

# Under VRRP mode l3h1 and EPs connect via r1's vlan11 bridge, not directly to llb1.
# Gate direct veths on non-VRRP mode only.
if [ "${PHASE_L_HA_MODE:-bfd}" != "vrrp" ]; then
connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1
connect_docker_hosts l3ep3 llb1
connect_docker_hosts l3ep4 llb1
fi

echo "#########################################"
echo "Configuring IP addresses and routes"
echo "#########################################"

# EP /24 subnet addresses only exist in non-VRRP mode.
# Under VRRP all nodes (llb1, llb2, l3ep1-4) share vlan11 (11.11.11.0/24) via r1.
if [ "${PHASE_L_HA_MODE:-bfd}" != "vrrp" ]; then
# l3h1 client address — requires gateway pointing at VIP so traffic flows via
# the direct el3h1llb1 veth. loxilb also needs 10.10.10.254/24 on ellb1l3h1
# so the kernel responds to ARP for the VIP; XDP then intercepts the LB flow.
config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 llb1  --host2 l3h1 --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24
config_docker_host --host1 l3ep3 --host2 llb1 --ptype phy --addr 33.33.33.1/24
config_docker_host --host1 l3ep4 --host2 llb1 --ptype phy --addr 34.34.34.1/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1  --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb1  --host2 l3ep3 --ptype phy --addr 33.33.33.254/24
config_docker_host --host1 llb1  --host2 l3ep4 --ptype phy --addr 34.34.34.254/24
fi

echo "#########################################"
echo "Preparing TLS certificates"
echo "#########################################"

# In VRRP mode the VIP is 11.11.11.11 so we generate the correct cert later
# in the VRRP section (after r1/vlan11 topology is wired) and copy it to the
# shared cert/ bind-mount before the binary overlay restart.
# minica (github.com/jsha/minica) is fetched on demand — no binary is committed.
MINICA="$(command -v minica || echo "$(go env GOPATH)/bin/minica")"
[ -x "$MINICA" ] || { go install github.com/jsha/minica@latest; MINICA="$(go env GOPATH)/bin/minica"; }
if [ "${PHASE_L_HA_MODE:-bfd}" != "vrrp" ]; then
"$MINICA" --ip-addresses 10.10.10.254
docker cp minica.pem llb1:/opt/loxilb/cert/rootCA.crt
docker cp 10.10.10.254/cert.pem llb1:/opt/loxilb/cert/server.crt
docker cp 10.10.10.254/key.pem  llb1:/opt/loxilb/cert/server.key
docker cp minica.pem l3h1:/tmp/minica.pem
fi

echo "#########################################"
echo "Installing python3 in endpoint containers"
echo "#########################################"

for ep in l3ep1 l3ep2 l3ep3 l3ep4; do
  # Skip apt entirely when the image already ships python3 — on hosts whose container
  # egress is broken (observed finding: resident --net=host loxilb eats
  # bridge-NAT return traffic) apt hangs forever; bake python3 into the nettest image
  # via a --network=host build instead. When apt MUST run, prefer the Korean mirror
  # (recurring archive.ubuntu.com flakiness on this infra).
  if ! $dexec $ep python3 --version > /dev/null 2>&1; then
    $dexec $ep bash -c "sed -i 's|//archive.ubuntu.com|//kr.archive.ubuntu.com|g' /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true; apt-get update > /dev/null 2>&1 && apt-get install -y python3 > /dev/null 2>&1"
  fi
  $dexec $ep python3 --version || { echo "FATAL: python3 install failed on $ep"; exit 1; }
done

echo "#########################################"
echo "Starting mock vLLM on l3ep1 (prefill role)"
echo "#########################################"

docker cp "$(dirname "$0")/mock_vllm.py" l3ep1:/tmp/mock_vllm.py
# pass --ep-idx so X-Prefill-Ep response header carries ep1 identity.
$dexec l3ep1 bash -c "nohup python3 /tmp/mock_vllm.py --role prefill --port 8000 --nixl-port 9001 --ep-idx 1 > /tmp/vllm-server1.log 2>&1 &"

echo "Waiting for mock vLLM to start on l3ep1..."
sleep 3
$dexec l3ep1 curl -sf http://localhost:8000/health || echo "WARNING: mock vLLM on l3ep1 did not respond to /health"

echo "#########################################"
echo "Starting mock vLLM on l3ep2 (decode role)"
echo "#########################################"

docker cp "$(dirname "$0")/mock_vllm.py" l3ep2:/tmp/mock_vllm.py
# pass --ep-idx so X-Decode-Ep response header carries ep2 identity.
$dexec l3ep2 bash -c "nohup python3 /tmp/mock_vllm.py --role decode --port 8000 --nixl-port 9002 --ep-idx 2 > /tmp/vllm-server2.log 2>&1 &"

echo "Waiting for mock vLLM to start on l3ep2..."
sleep 3
$dexec l3ep2 curl -sf http://localhost:8000/health || echo "WARNING: mock vLLM on l3ep2 did not respond to /health"

echo "#########################################"
echo "Starting mock vLLM on l3ep3 (prefill role)"
echo "#########################################"

docker cp "$(dirname "$0")/mock_vllm.py" l3ep3:/tmp/mock_vllm.py
# --ep-idx 3 (prefill).
$dexec l3ep3 bash -c "nohup python3 /tmp/mock_vllm.py --role prefill --port 8000 --nixl-port 9003 --ep-idx 3 > /tmp/vllm-server3.log 2>&1 &"

echo "Waiting for mock vLLM to start on l3ep3..."
sleep 3
$dexec l3ep3 curl -sf http://localhost:8000/health || echo "WARNING: mock vLLM on l3ep3 did not respond to /health"

echo "#########################################"
echo "Starting mock vLLM on l3ep4 (decode role)"
echo "#########################################"

docker cp "$(dirname "$0")/mock_vllm.py" l3ep4:/tmp/mock_vllm.py
# --ep-idx 4 (decode).
$dexec l3ep4 bash -c "nohup python3 /tmp/mock_vllm.py --role decode --port 8000 --nixl-port 9004 --ep-idx 4 > /tmp/vllm-server4.log 2>&1 &"

echo "Waiting for mock vLLM to start on l3ep4..."
sleep 3
$dexec l3ep4 curl -sf http://localhost:8000/health || echo "WARNING: mock vLLM on l3ep4 did not respond to /health"

echo "#########################################"
echo "Verifying vLLM servers are running"
echo "#########################################"

for ep in l3ep1 l3ep2 l3ep3 l3ep4; do
    echo "Checking $ep..."
    $dexec $ep curl -s http://localhost:8000/v1/models || echo "$ep: vLLM server may not be ready yet"
    sleep 2
done

echo "#########################################"
echo "Installing P/D LB rules on llb1 (ports 2020/2021/2022/2023)"
echo "#########################################"

# In VRRP mode the initial rules are skipped here — they are installed with the
# correct VIP (11.11.11.11) and bridge EP IPs after the binary overlay + keepalived
# sidecar spawn in the VRRP section below (Step 10).
if [ "${PHASE_L_HA_MODE:-bfd}" != "vrrp" ]; then
install_lb_rules llb1

echo "#########################################"
echo "Enabling Prometheus metrics"
echo "#########################################"

$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/metrics

sleep 5

# Wait for all 4 EPs on port 2022 to be probed active (health probe readiness)
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
fi

echo "#########################################"
echo "Configuration complete"
echo "#########################################"
echo "  Port 2020: P/D disaggregation (l3ep1=prefill/http:8000/nixl:9001, l3ep2=decode/http:8000/nixl:9002)"
echo "  Port 2021: Non-P/D baseline (round-robin)"
echo "  Port 2022: 2P+2D P/D (l3ep1+l3ep3 prefill nixl:9001/9003, l3ep2+l3ep4 decode nixl:9002/9004)"
echo "  Port 2023: 2P+2D cache-aware P/D (pd_cache_aware_mode=true)"

########################################################################
# Phase L — 2-loxilb HA topology via cluster keepalive
# ----------------------------------------------------------------------
# Wire HA between llb1 (.254, self=0, initial MASTER) and llb2 (.253, self=1,
# initial BACKUP) using loxilb's built-in cluster flags:
#     --cluster=<self_ip>  --self=<0|1>  --ka=<self_ip>:<peer_ip>
# Sync + keepalive flow over loxilb's default sync port (22222). cluster.go
# initializes role from --self ordinal and switches over on keepalive loss to
# peer — no BFD/cistate POSTs required.
#
# Then install iptables DNAT on l3h1: 10.10.10.99 → current-master IP
# (rewritten by validation.sh after each failover via update_master_dnat).
#
# All changes below are GATED on env var PHASE_L_HA=1 so Phase A-K runs
# (validation.sh phases A-K) remain on the original 1-loxilb topology and
# do NOT regress. validation.sh Phase L exports PHASE_L_HA=1 before calling
# this block via the wrapper helpers defined here.
########################################################################

if [ "${PHASE_L_HA:-0}" = "1" ] && [ "${PHASE_L_HA_MODE:-bfd}" = "vrrp" ]; then

# ── vrrp branch ──
# ha1-style topology: external keepalived sidecars (osixia/keepalived:2.0.20)
# own a single VIP 11.11.11.11 on a shared vlan11 bridge anchored at r1.
#
# Spawn-order invariant:
#   1. defensive image pull
#   2. (llb1 plain spawn happens at the top of this file via the gated
#       --extra-args block — vrrp arm leaves llb1 with no HA flags)
#   3. llb2 direct `docker run` (port-conflict workaround)
#   4. r1 host router
#   5. connect_docker_hosts r1↔llb1, r1↔llb2, l3h1↔r1 (NEW)
#   6. VLAN-11 wiring (4 create_docker_host_vlan calls)
#   7. EP /24 subnets to both llbs (preserved)
#   8-11: binary overlay + sidecar spawn + LB rules + cistate poll —
#         convergence is read via the read_cistate
#         helper which GETs /netlox/v1/config/cistate/all
#         (re-uses the existing polling primitive).

echo "#########################################"
echo "Phase L (vrrp): switching to ha1-style 2-loxilb + r1 topology"
echo "#########################################"

# defensive pull of the sole new image so a fresh testbed without
# any prior HA scenario doesn't hang on first VRRP bringup.
docker pull osixia/keepalived:2.0.20 >/dev/null 2>&1 || true

# Step 3 — Direct docker run for llb2 (port-conflict workaround
# is mode-agnostic; the
# spawn_docker_host loxilb helper always publishes 8091/11111/22222 which llb1
# already owns).
echo "[Phase L vrrp] Spawning llb2 container (no host-port mappings — uses container IPs)"
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
  echo "[Phase L vrrp] llb2 netns registered (pid=$llb2_pid)"
else
  echo "WARN: llb2 PID could not be determined; subsequent network setup will fail"
fi
loxilbs+=("llb2")

# Step 4 — r1 host router (single-purpose route + ARP forwarder, no NAT, no
# iptables). Spawned via spawn_docker_host --dock-type host so
# common.sh registers its netns.
spawn_docker_host --dock-type host --dock-name r1

# Step 5 — wire l3h1↔r1 + r1↔{llb1,llb2} + r1↔l3ep{1-4} (bridge topology).
# l3h1↔llb1 / l3h1↔llb2 direct veths are NOT created in vrrp mode (gated in
# upper section) — l3h1 reaches loxilb exclusively via r1's vlan11 bridge.
connect_docker_hosts l3h1 r1
# Bug 1 — l3h1↔r1 IPs + l3h1 → VIP route (llb1/llb2 reverse-path routes
# moved below to after VLAN-11 IPs are configured — see "Bug 1 (continued)").
config_docker_host --host1 l3h1 --host2 r1 --ptype phy --addr 12.12.12.1/24
config_docker_host --host1 r1   --host2 l3h1 --ptype phy --addr 12.12.12.254/24
add_route l3h1 11.11.11.0/24 12.12.12.254
# Note: routes from l3h1 to 31.x/32.x/33.x/34.x removed — those subnets do not
# exist in the bridge topology. l3h1 reaches EPs via r1 → vlan11 (11.11.11.0/24).
connect_docker_hosts r1   llb1
connect_docker_hosts r1   llb2

# Wire all EPs to the shared vlan11 bridge via r1 (ha1 topology — Image 2).
# Each EP gets 11.11.11.3-6/24 on vlan11; gateway = 11.11.11.11 (VIP floats here).
# EPs are ON the 11.11.11.0/24 subnet so no explicit reverse-path routes needed.
connect_docker_hosts r1    l3ep1
connect_docker_hosts r1    l3ep2
connect_docker_hosts r1    l3ep3
connect_docker_hosts r1    l3ep4
create_docker_host_vlan --host1 r1    --host2 l3ep1 --id 11 --ptype untagged
create_docker_host_vlan --host1 r1    --host2 l3ep2 --id 11 --ptype untagged
create_docker_host_vlan --host1 r1    --host2 l3ep3 --id 11 --ptype untagged
create_docker_host_vlan --host1 r1    --host2 l3ep4 --id 11 --ptype untagged
create_docker_host_vlan --host1 l3ep1 --host2 r1    --id 11 --ptype untagged
create_docker_host_vlan --host1 l3ep2 --host2 r1    --id 11 --ptype untagged
create_docker_host_vlan --host1 l3ep3 --host2 r1    --id 11 --ptype untagged
create_docker_host_vlan --host1 l3ep4 --host2 r1    --id 11 --ptype untagged
config_docker_host --host1 l3ep1 --host2 r1 --ptype vlan --id 11 --addr 11.11.11.3/24 --gw 11.11.11.11
config_docker_host --host1 l3ep2 --host2 r1 --ptype vlan --id 11 --addr 11.11.11.4/24 --gw 11.11.11.11
config_docker_host --host1 l3ep3 --host2 r1 --ptype vlan --id 11 --addr 11.11.11.5/24 --gw 11.11.11.11
config_docker_host --host1 l3ep4 --host2 r1 --ptype vlan --id 11 --addr 11.11.11.6/24 --gw 11.11.11.11
# Override EP IPs for install_lb_rules — all EPs are now on vlan11 bridge addresses.
export EP1_IP=11.11.11.3 EP2_IP=11.11.11.4 EP3_IP=11.11.11.5 EP4_IP=11.11.11.6

# Step 6 — VLAN-11 wiring (CRITICAL: r1 MUST create the vlan11
# bridge with BOTH veth peers as ports so VRRP adverts span both llbs;
# missing either create_docker_host_vlan on r1 → split-brain).
create_docker_host_vlan --host1 r1   --host2 llb1 --id 11 --ptype untagged
create_docker_host_vlan --host1 r1   --host2 llb2 --id 11 --ptype untagged
create_docker_host_vlan --host1 llb1 --host2 r1   --id 11 --ptype untagged
create_docker_host_vlan --host1 llb2 --host2 r1   --id 11 --ptype untagged

config_docker_host --host1 r1   --host2 llb1 --ptype vlan --id 11 --addr 11.11.11.254/24
config_docker_host --host1 llb1 --host2 r1   --ptype vlan --id 11 --addr 11.11.11.1/24
config_docker_host --host1 llb2 --host2 r1   --ptype vlan --id 11 --addr 11.11.11.2/24

# Honor keepalived's gratuitous ARP on failover. r1 is the gateway that resolves
# the VIP (11.11.11.11) on vlan11; with the default arp_accept=0 it keeps the
# stale VIP→MAC entry pointing at the dead master until the REACHABLE/STALE
# timeout (~30s) expires, so the migrated VIP looks unreachable for that window.
# arp_accept=1 makes r1 adopt the promoted node's garp immediately. (proxy_arp
# alone does not cover this — that is why post-failover routing regressed.)
sudo ip netns exec r1 sysctl -w net.ipv4.conf.all.arp_accept=1 >/dev/null 2>&1 || true
sudo ip netns exec r1 sysctl -w net.ipv4.conf.vlan11.arp_accept=1 >/dev/null 2>&1 || true

# Disable bridge multicast snooping on r1's vlan11 bridge. With snooping on and
# no IGMP querier (the default here), the bridge drops VRRP advertisement
# multicast (224.0.0.18) between the llb1/llb2 ports, so neither keepalived sees
# the other and BOTH enter MASTER STATE (split-brain) — both plumb the VIP with
# different MACs and routing to 11.11.11.11 becomes non-deterministic. Flooding
# multicast (snooping=0) lets the adverts cross so exactly one node owns the VIP
# and failover migrates it cleanly. NB: must use the netlink path (ip link set
# type bridge) — writing /sys/class/net/.../multicast_snooping inside a netns
# does NOT reliably target the namespaced bridge.
sudo ip netns exec r1 ip link set vlan11 type bridge mcast_snooping 0 2>/dev/null || true
echo "[Phase L vrrp] r1 vlan11 mcast_snooping = $(sudo ip netns exec r1 cat /sys/class/net/vlan11/bridge/multicast_snooping 2>/dev/null) (want 0)"

# Bug 1 (continued) — reverse-path routes on llb1/llb2 to the l3h1 host subnet.
# Moved here from the Patch-A block above because the gateway 11.11.11.254
# requires llb1/llb2 to have an interface in 11.11.11.0/24 first (VLAN-11 IPs
# above). Pre-fix this ran at L320-321 and kernel rejected with
# "Nexthop has invalid gateway" on a clean-state bringup.
add_route llb1 12.12.12.0/24 11.11.11.254
add_route llb2 12.12.12.0/24 11.11.11.254

# NOTE: 11.11.11.11 (the VIP) is NOT assigned statically here — keepalived
# claims it dynamically via VRRP gratuitous-ARP on whichever llb is MASTER.

# Route 11.11.11.11/32 from l3h1 → r1 (via the default route or explicit add).
# l3h1↔r1 veth is configured by common.sh — give l3h1 a host-side address +
# default-gw to r1's veth peer so client traffic to the VIP hits r1 first.
# (The exact host-route detail is r1-internal; l3h1 just needs reachability.)

# Re-generate TLS certificate for VRRP VIP 11.11.11.11.
# Both llbs share the same cert/ bind-mount (-v pwd/cert:/opt/loxilb/cert/).
# Writing to the host cert/ dir updates both containers; the new cert takes
# effect after the binary overlay restart below (loxilb reloads on start).
"$MINICA" --ip-addresses 11.11.11.11
cp 11.11.11.11/cert.pem cert/server.crt
cp 11.11.11.11/key.pem  cert/server.key
cp minica.pem cert/rootCA.crt
docker cp minica.pem l3h1:/tmp/minica.pem

# Service externalIP migrates to 11.11.11.11 under vrrp so
# the LB VIP lives on the keepalived-managed vlan11 interface; failover is
# a gratuitous-ARP redirect, no iptables DNAT rewriting needed.
# install_lb_rules picks up this override
# via its local xip="${LB_EXTERNAL_IP:-10.10.10.254}" expansion.
export LB_EXTERNAL_IP=11.11.11.11

# ──────────────────────────────────────────────────────────────────────
# Step 6-8: Binary overlay.
# Pattern lifted from cicd/vllm-fullproxy/config.sh:249-273
# with two required mutations:
#   1. HOST-side `strings` check (in-container strings is absent).
#      Single check before per-LLB loop;
#      binary is byte-identical post docker cp.
#   2. Remove --cluster/--self/--ka flags from the restart lines — under
#      vrrp HA is externalized to keepalived (internal BFD must NOT
#      compete with external keepalived).
# Spawn-order invariant: (a) pkill BOTH loxilbs, (b) docker cp BOTH,
# (c) host strings gate, (d) start BOTH plain, (e) sleep 5 for cistate
# API readiness — THEN task 06 spawns the sidecars.
# ──────────────────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ ! -f "$REPO_ROOT/loxilb" ]; then
  echo "FATAL: $REPO_ROOT/loxilb not found — run 'make build' first"
  exit 1
fi
# Host-side SOCKPROXY_SYNC marker gate (single check; binary is byte-identical
# after `docker cp` so per-container re-check would be redundant + brittle).
MC=$(strings "$REPO_ROOT/loxilb" 2>/dev/null | grep -c SOCKPROXY_SYNC || echo 0)
if [ "$MC" -lt 3 ]; then
  echo "FATAL: ./loxilb missing SOCKPROXY_SYNC markers (found $MC, need >=3) — make build first"
  exit 1
fi
echo "[Phase L vrrp] host-side SOCKPROXY_SYNC marker count = $MC (>=3 OK)"

docker exec llb1 pkill -9 -f /root/loxilb-io/loxilb/loxilb 2>/dev/null || true
docker exec llb2 pkill -9 -f /root/loxilb-io/loxilb/loxilb 2>/dev/null || true
docker exec llb1 mkdir -p /var/log/loxilb 2>/dev/null || true
docker exec llb2 mkdir -p /var/log/loxilb 2>/dev/null || true
docker cp "$REPO_ROOT/loxilb" llb1:/root/loxilb-io/loxilb/loxilb
docker cp "$REPO_ROOT/loxilb" llb2:/root/loxilb-io/loxilb/loxilb
echo "[Phase L vrrp] llb1 + llb2: binary overlaid from $REPO_ROOT/loxilb"

# Restart loxilb with --cluster/--self ONLY (NO --ka). Two HA layers coexist:
#   • Election: external keepalived owns VIP claim via VRRP adverts (--ka would
#     start BFD election → conflicts with keepalived; correctly omitted).
#   • State sync: --cluster=<peer-vlan11-IP> + --self=<ordinal> wires up the
#     xSync gRPC peer (port 22222 on vlan11/11.11.11.0/24) so sockproxy
#     session map + ratelimiter quota replicate llb1↔llb2. WITHOUT these
#     flags, no peer identity → xSync never starts → restore_rate=0 even
#     though failover and data path both work.
# Stdout redirected to /var/log/loxilb/loxilb-stdout.log because the container
# entrypoint is /bin/bash so `docker logs` is empty (memory:
# loxilb_docker_logs_vs_loxilb_stdout).
docker exec -dt llb1 bash -c '/root/loxilb-io/loxilb/loxilb --cluster=11.11.11.2 --self=0 --blacklist=ellb1r1 > /var/log/loxilb/loxilb-stdout.log 2>&1'
docker exec -dt llb2 bash -c '/root/loxilb-io/loxilb/loxilb --cluster=11.11.11.1 --self=1 --blacklist=ellb2r1 > /var/log/loxilb/loxilb-stdout.log 2>&1'
echo "[Phase L vrrp] llb1 + llb2: loxilb restarted with --cluster/--self for xSync (keepalived still owns VIP election)"
sleep 5  # cistate REST API readiness before sidecars start firing notify.sh POSTs

# ──────────────────────────────────────────────────────────────────────
# Step 9: Keepalived sidecar spawn (INLINE — root
# common.sh parses --with-ka but never spawns ka_$dname). Pattern lifted
# from cicd/k3s-incluster/common.sh:130-136 + 6
# other sibling implementations. Each sidecar shares its loxilb's netns
# via --network=container:$LLB so the in-netns curl in notify.sh hits
# http://0.0.0.0:11111/netlox/v1/config/cistate directly.
# ──────────────────────────────────────────────────────────────────────
KPATH="$(pwd)/keepalived_config"
# Defensive teardown: prior session's ka_llb sidecars survive into the next
# run if rmconfig.sh wasn't invoked (or failed). `docker run --name` would
# then fail with Conflict and leave loxilb without keepalived → cistate
# stays NOT_DEFINED → restore_rate=0. Re-runnable spawn pattern matches
# what other cicd/*/config.sh scripts already do.
docker rm -f ka_llb1 ka_llb2 2>/dev/null || true
sudo mkdir -p /etc/shared/llb1
docker run -u root --cap-add SYS_ADMIN --restart unless-stopped --privileged -dit --network=container:llb1 -v "$KPATH:/container/service/keepalived/assets/" -v "/etc/shared/llb1:/etc/shared" --name ka_llb1 osixia/keepalived:2.0.20

sudo mkdir -p /etc/shared/llb2
docker run -u root --cap-add SYS_ADMIN --restart unless-stopped --privileged -dit --network=container:llb2 -v "$KPATH:/container/service/keepalived/assets/" -v "/etc/shared/llb2:/etc/shared" --name ka_llb2 osixia/keepalived:2.0.20
sleep 3  # VRRP adverts establish, election converges before LB rules install

# Step 10: Re-install LB rules on both llbs — LB rules are not persisted
# across the loxilb restart in step 7. LB_EXTERNAL_IP=11.11.11.11 export
# above is still in scope so the helper POSTs externalIP=11.11.11.11.
install_lb_rules llb1
install_lb_rules llb2
$hexec llb1 curl -s -X POST http://localhost:11111/netlox/v1/config/metrics >/dev/null || true
$hexec llb2 curl -s -X POST http://localhost:11111/netlox/v1/config/metrics >/dev/null || true

# Step 11: cistate convergence poll. read_cistate helper
# definition mirrors the bfd-arm helper at config.sh:353-365 byte-for-byte
# (same instance filter "llb-inst0" so the shared instance name
# aligns the namespaces). Polling primitive re-used — no new
# polling code path invented.
read_cistate() {
  # Default instance name is "llb-inst0" (cmn.CIDefault); the keepalived
  # vrrp_instance uses the same name so this filter
  # works for both bfd-mode (internal cluster role) and vrrp-mode
  # (external keepalived state via notify.sh POST to /cistate).
  $hexec "$1" curl -s 'http://127.0.0.1:11111/netlox/v1/config/cistate/all' 2>/dev/null | \
    python3 -c "import sys,json
try:
  d=json.load(sys.stdin)
  for a in d.get('Attr',[]):
    if a.get('instance')=='llb-inst0':
      print(a.get('state','UNKNOWN'))
      break
except: print('UNKNOWN')" 2>/dev/null || echo UNKNOWN
}

echo "[Phase L vrrp] Waiting up to 30s for VRRP election + cistate POST to converge..."
MASTER_LLB1=""
MASTER_LLB2=""
for i in $(seq 1 30); do
  MASTER_LLB1=$(read_cistate llb1)
  MASTER_LLB2=$(read_cistate llb2)
  if [ -n "$MASTER_LLB1" ] && [ "$MASTER_LLB1" != "UNKNOWN" ] && [ "$MASTER_LLB1" != "NOT_DEFINED" ] && \
     [ -n "$MASTER_LLB2" ] && [ "$MASTER_LLB2" != "UNKNOWN" ] && [ "$MASTER_LLB2" != "NOT_DEFINED" ] && \
     [ "$MASTER_LLB1" != "$MASTER_LLB2" ]; then
    echo "  Converged after ${i}s: llb1=$MASTER_LLB1, llb2=$MASTER_LLB2"
    break
  fi
  sleep 1
done
echo "[Phase L vrrp] llb1 cistate=$MASTER_LLB1, llb2 cistate=$MASTER_LLB2 (expect exactly one MASTER, one BACKUP)"
echo "[Phase L vrrp] topology ready: VIP=11.11.11.11 owned by whichever llb is MASTER"

elif [ "${PHASE_L_HA:-0}" = "1" ]; then

echo "#########################################"
echo "Phase L: switching to 2-loxilb HA topology"
echo "#########################################"

echo "[Phase L] llb1 already running with HA flags (spawned with --extra-args)"
# Flag order per pkg/loxinet/utils.go:KAString2Mode (canonical):
#   --cluster=<PEER_IP>  --self=<ordinal>  --ka=<PEER_IP>:<SELF_IP>
# (--ka first field is RemoteIP, second is SourceIP). llb1 was spawned with
# these flags at the top of this script (gated on PHASE_L_HA=1), so LB rules
# + health-probe state are already established and there's no need to
# restart-in-place (which leaves stale eBPF state on the netns).

echo "[Phase L] Spawning llb2 container (no host-port mappings — uses container IPs)"
# CANNOT use `spawn_docker_host --dock-type loxilb` for llb2 because it always
# publishes host ports 8091/11111/22222 — already owned by llb1 → "port is
# already allocated". llb2 uses its own container IP (10.10.10.253) on the
# l3h1<->llb2 bridge instead; cluster sync to llb1 over port 22222 still
# works because both loxilbs share the docker network.
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
  echo "[Phase L] llb2 netns registered (pid=$llb2_pid)"
else
  echo "WARN: llb2 PID could not be determined; subsequent network setup will fail"
fi

# Append llb2 to global loxilbs array so common.sh helpers know about it.
loxilbs+=("llb2")

connect_docker_hosts l3h1  llb2
connect_docker_hosts l3ep1 llb2
connect_docker_hosts l3ep2 llb2
connect_docker_hosts l3ep3 llb2
connect_docker_hosts l3ep4 llb2

# llb2 takes the .253 last-octet on each subnet (llb1 has .254).
config_docker_host --host1 llb2 --host2 l3h1  --ptype phy --addr 10.10.10.253/24
config_docker_host --host1 llb2 --host2 l3ep1 --ptype phy --addr 31.31.31.253/24
config_docker_host --host1 llb2 --host2 l3ep2 --ptype phy --addr 32.32.32.253/24
config_docker_host --host1 llb2 --host2 l3ep3 --ptype phy --addr 33.33.33.253/24
config_docker_host --host1 llb2 --host2 l3ep4 --ptype phy --addr 34.34.34.253/24

add_route l3ep1 12.12.12.0/24 11.11.11.11
add_route l3ep2 12.12.12.0/24 11.11.11.11
add_route l3ep3 12.12.12.0/24 11.11.11.11
add_route l3ep4 12.12.12.0/24 11.11.11.11

# proxy-ARP + per-EP forwarding sysctls are bfd-specific.
# Under vrrp llb1↔llb2 ARP-resolve via the shared vlan11 bridge directly
# (true L2); proxy-ARP is unneeded and would interfere with VRRP gratuitous-
# ARP advertisements. Wrap the existing block on PHASE_L_HA_MODE != vrrp.
# This wrap is belt-and-braces — the surrounding `elif PHASE_L_HA_MODE=bfd`
# arm already gates it — but the explicit wrap documents the design
# decision and survives any future arm restructuring.
if [ "${PHASE_L_HA_MODE:-bfd}" != "vrrp" ]; then
# Allow llb1 (10.10.10.254) and llb2 (10.10.10.253) to ARP-resolve each other
# even though they're on separate veth pairs into l3h1. Two options here are
# (a) Linux bridge in l3h1 joining both veths, or (b) IP forwarding + proxy
# ARP on l3h1. Bridging proved to interact badly with loxilb's pd_disagg
# (HTTP/0.9 response mangling) so we use proxy-ARP + IPv4 forwarding instead
# — preserves the original L4 path topology that Phase A-K validates.
sudo ip netns exec l3h1 sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sudo ip netns exec l3h1 sysctl -w net.ipv4.conf.all.proxy_arp=1 >/dev/null 2>&1 || true
sudo ip netns exec l3h1 sysctl -w net.ipv4.conf.el3h1llb1.proxy_arp=1 >/dev/null 2>&1 || true
sudo ip netns exec l3h1 sysctl -w net.ipv4.conf.el3h1llb2.proxy_arp=1 >/dev/null 2>&1 || true
# Add /32 host routes on l3h1 pointing to the correct veth so proxy ARP
# replies on the right interface. This lets llb1 think .253 is "via l3h1's
# .1" and l3h1 forwards the packet out the el3h1llb2 veth.
sudo ip -n l3h1 route add 10.10.10.253/32 dev el3h1llb2 proto static 2>/dev/null || true
sudo ip -n l3h1 route add 10.10.10.254/32 dev el3h1llb1 proto static 2>/dev/null || true

# Same forwarding setup for the 4 EP subnets — needed so llb2 can reach the
# EPs after promotion. For each l3ep<n>: enable forwarding + proxy_arp so
# llb1 (.254) and llb2 (.253) can both reach .1 (the mock_vllm) and so the
# EP's reply can route back to either loxilb.
for n in 1 2 3 4; do
  sudo ip netns exec l3ep${n} sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  sudo ip netns exec l3ep${n} sysctl -w net.ipv4.conf.all.proxy_arp=1 >/dev/null 2>&1 || true
  sudo ip netns exec l3ep${n} sysctl -w net.ipv4.conf.el3ep${n}llb1.proxy_arp=1 >/dev/null 2>&1 || true
  sudo ip netns exec l3ep${n} sysctl -w net.ipv4.conf.el3ep${n}llb2.proxy_arp=1 >/dev/null 2>&1 || true
  sub="3${n}.3${n}.3${n}"
  sudo ip -n l3ep${n} route add ${sub}.253/32 dev el3ep${n}llb2 proto static 2>/dev/null || true
  sudo ip -n l3ep${n} route add ${sub}.254/32 dev el3ep${n}llb1 proto static 2>/dev/null || true
done
fi  # PHASE_L_HA_MODE != vrrp (proxy-ARP block)

echo "[Phase L] Starting loxilb on llb2 with HA flags (self=1 ⇒ initial BACKUP, ka peer=.254)"
docker exec -dt llb2 /root/loxilb-io/loxilb/loxilb \
  --cluster=10.10.10.254 --self=1 --ka=10.10.10.254:10.10.10.253 2>&1 || \
  echo "WARN: llb2 HA-flag startup failed"
sleep 3  # loxilb readiness (API up on 11111); cluster role convergence handled below

# Mirror the same 4 LB rules on llb2 + metrics. (In production the HA state
# sync from 70-A would seed LB config too; in CICD we register them explicitly
# so the test focuses on *session* sync, not control-plane sync.)
install_lb_rules llb2
$hexec llb2 curl -s -X POST http://localhost:11111/netlox/v1/config/metrics >/dev/null || true

# Install master-routing on l3h1: iptables DNAT 10.10.10.99 → 10.10.10.254
# initially, rewritten by validation.sh update_master_dnat after each failover.
$dexec l3h1 bash -c 'apt-get update >/dev/null 2>&1 && apt-get install -y iptables >/dev/null 2>&1' || \
  echo "WARN: iptables install on l3h1 failed; Phase L will fall back to direct curls to current-master IP"
$dexec l3h1 iptables -t nat -A OUTPUT -d 10.10.10.99 -j DNAT --to-destination 10.10.10.254 2>/dev/null || \
  echo "WARN: iptables DNAT not installed on l3h1; Phase L will use direct-IP fallback"

# Master role read-back via /netlox/v1/config/cistate/all. Role is elected by
# cluster.go on BFD session establishment (--ka triggers BFD); takes
# KAInitTiVal=5s cool-off + ~3-5s BFD session establishment ≈ ~8-13s minimum
# after loxilb start.
read_cistate() {
  # cluster.go default instance name is "llb-inst0" (cmn.CIDefault), NOT
  # "default". Filter by that instance; treat NOT_DEFINED as the still-
  # initializing pre-election state.
  $hexec "$1" curl -s 'http://127.0.0.1:11111/netlox/v1/config/cistate/all' 2>/dev/null | \
    python3 -c "import sys,json
try:
  d=json.load(sys.stdin)
  for a in d.get('Attr',[]):
    if a.get('instance')=='llb-inst0':
      print(a.get('state','UNKNOWN'))
      break
except: print('UNKNOWN')" 2>/dev/null || echo UNKNOWN
}

# Poll up to 30s for cluster keepalive convergence (both loxilbs report
# MASTER or BACKUP, not empty/UNKNOWN).
echo "[Phase L] Waiting up to 30s for cluster keepalive election to converge..."
MASTER_LLB1=""
MASTER_LLB2=""
for i in $(seq 1 30); do
  MASTER_LLB1=$(read_cistate llb1)
  MASTER_LLB2=$(read_cistate llb2)
  if [ -n "$MASTER_LLB1" ] && [ "$MASTER_LLB1" != "UNKNOWN" ] && [ "$MASTER_LLB1" != "NOT_DEFINED" ] && \
     [ -n "$MASTER_LLB2" ] && [ "$MASTER_LLB2" != "UNKNOWN" ] && [ "$MASTER_LLB2" != "NOT_DEFINED" ] && \
     [ "$MASTER_LLB1" != "$MASTER_LLB2" ]; then
    echo "  Converged after ${i}s: llb1=$MASTER_LLB1, llb2=$MASTER_LLB2"
    break
  fi
  sleep 1
done
echo "[Phase L config] llb1 cistate=$MASTER_LLB1, llb2 cistate=$MASTER_LLB2 (expect llb1=MASTER, llb2=BACKUP via --self ordinal + keepalive election)"

echo "  Phase L topology ready: llb1=$MASTER_LLB1 .254, llb2=$MASTER_LLB2 .253, virtual master 10.10.10.99 → llb1"

fi  # PHASE_L_HA

# Helper function — re-write the l3h1 DNAT rule so subsequent traffic to the
# virtual master IP (10.10.10.99) lands on whichever loxilb is the current master.
# Called from validation.sh Phase L after each failover. NOT phase-gated because
# the helper itself does no work unless invoked.
#
# Falls back gracefully when l3h1 does not have iptables: the function just
# logs a no-op message and validation.sh uses the direct-master-IP curl path.
update_master_dnat() {
  local new_master_ip="$1"
  if [ -z "$new_master_ip" ]; then
    echo "[update_master_dnat] missing new-master IP arg" >&2
    return 1
  fi
  if $dexec l3h1 which iptables >/dev/null 2>&1; then
    $dexec l3h1 iptables -t nat -F OUTPUT 2>/dev/null || true
    $dexec l3h1 iptables -t nat -A OUTPUT -d 10.10.10.99 -j DNAT --to-destination "$new_master_ip" || return 1
    echo "[update_master_dnat] virtual master 10.10.10.99 → $new_master_ip"
  else
    # No iptables — validation.sh Phase L sub-cases must curl directly at
    # $new_master_ip:2022 instead of http://10.10.10.99:2022.
    echo "[update_master_dnat] iptables absent on l3h1; new master IP = $new_master_ip (validation.sh must curl direct)"
  fi
}
