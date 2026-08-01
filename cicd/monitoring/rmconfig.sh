#!/bin/bash
source ../common.sh
echo SCENARIO-monitoring-cleanup

# Tear down the monitoring stack first (host-network containers)
docker compose -f docker-compose.ci.yml down -v --remove-orphans 2>/dev/null || true
rm -f prometheus-ci.yml /tmp/monitoring-hold.log

# Stop backend processes
sudo pkill -f mock_sse_server 2>/dev/null || true
sudo pkill -f rst_server 2>/dev/null || true
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

echo SCENARIO-monitoring-cleanup [OK]
