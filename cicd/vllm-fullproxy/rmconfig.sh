#!/bin/bash
source ../common.sh

echo "#########################################"
echo "Cleaning up vllm-fullproxy test"
echo "#########################################"

# Stop vLLM servers
echo "Stopping vLLM servers..."
$dexec l3ep1 killall -9 python python3 > /dev/null 2>&1
$dexec l3ep2 killall -9 python python3 > /dev/null 2>&1

sleep 2

# Tear down llb2's veth connections too. If llb2 was never
# spawned (PHASE_L_HA != 1) these disconnects + delete are silent no-ops
# because the docker container `llb2` simply does not exist.
disconnect_docker_hosts l3h1  llb2 2>/dev/null || true
disconnect_docker_hosts l3ep1 llb2 2>/dev/null || true
disconnect_docker_hosts l3ep2 llb2 2>/dev/null || true

# Delete Docker hosts
echo "Deleting Docker hosts..."
delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3ep1
delete_docker_host l3ep2
delete_docker_host llb2 2>/dev/null || true

# Clean up certificates
echo "Cleaning up certificates..."
rm -rf 10.10.10.254 minica*.pem loxilb.io 2>/dev/null

echo "Cleanup complete"
