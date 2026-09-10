#!/bin/bash
source ../common.sh
echo SCENARIO-ai-model-conflict-cleanup

$hexec l3ep1 sudo killall -9 node 2>/dev/null
$hexec l3ep2 sudo killall -9 node 2>/dev/null
sleep 1

disconnect_docker_hosts llb1 l3h1
disconnect_docker_hosts llb1 l3ep1
disconnect_docker_hosts llb1 l3ep2

delete_docker_host l3ep2
delete_docker_host l3ep1
delete_docker_host l3h1
delete_docker_host llb1

## Remove the PostgreSQL container (started with --rm; stop removes it)
docker stop pg-conflict 2>/dev/null || true

rm -f .state
rm -rf llb1_config

echo SCENARIO-ai-model-conflict-cleanup [OK]
