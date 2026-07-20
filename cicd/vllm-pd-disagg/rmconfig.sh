#!/bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../common.sh
exec < /dev/null

$dexec l3ep1 pkill -f 'mock_vllm.py' 2>/dev/null
$dexec l3ep2 pkill -f 'mock_vllm.py' 2>/dev/null
$dexec l3ep3 pkill -f 'mock_vllm.py' 2>/dev/null
$dexec l3ep4 pkill -f 'mock_vllm.py' 2>/dev/null

# Flush iptables DNAT on client (no-op if rule was never installed).
$dexec l3h1 iptables -t nat -F OUTPUT 2>/dev/null || true

disconnect_docker_hosts l3h1  llb1
disconnect_docker_hosts l3ep1 llb1
disconnect_docker_hosts l3ep2 llb1
disconnect_docker_hosts l3ep3 llb1
disconnect_docker_hosts l3ep4 llb1

# Tear down llb2's veth connections too. If llb2 was never
# spawned (PHASE_L_HA != 1) these disconnects + delete are silent no-ops because
# the docker container `llb2` simply does not exist.
disconnect_docker_hosts l3h1  llb2 2>/dev/null || true
disconnect_docker_hosts l3ep1 llb2 2>/dev/null || true
disconnect_docker_hosts l3ep2 llb2 2>/dev/null || true
disconnect_docker_hosts l3ep3 llb2 2>/dev/null || true
disconnect_docker_hosts l3ep4 llb2 2>/dev/null || true

# vrrp mode adds r1 router + ka_llb1 + ka_llb2 sidecars +
# l3h1↔r1 veth. Idempotent removal: 2>/dev/null || true so a teardown
# after a bfd-mode run (where these resources never existed) no-ops cleanly.
disconnect_docker_hosts l3h1 r1 2>/dev/null || true
disconnect_docker_hosts r1   llb1 2>/dev/null || true
disconnect_docker_hosts r1   llb2 2>/dev/null || true
docker rm -f ka_llb1 ka_llb2 2>/dev/null || true
delete_docker_host r1 2>/dev/null || true

delete_docker_host l3h1
delete_docker_host l3ep1
delete_docker_host l3ep2
delete_docker_host l3ep3
delete_docker_host l3ep4
delete_docker_host llb1
delete_docker_host llb2 2>/dev/null || true

rm -rf 10.10.10.254/ minica.pem minica-key.pem 2>/dev/null
