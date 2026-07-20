#!/bin/bash
source ../common.sh
echo SCENARIO-ai-sse-quota-cleanup

# Stop backend processes
sudo pkill -f mock_sse_server 2>/dev/null || true
sudo killall -9 node 2>/dev/null || true
sleep 1

## Disconnect and delete virtual hosts
disconnect_docker_hosts llb1 l3h1
disconnect_docker_hosts llb1 l3ep1
disconnect_docker_hosts llb1 l3ep2

delete_docker_host l3ep2
delete_docker_host l3ep1
delete_docker_host l3h1
delete_docker_host llb1

echo SCENARIO-ai-sse-quota-cleanup [OK]
