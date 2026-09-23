#!/bin/bash
source ../common.sh
echo SCENARIO-ai-model-routing-cleanup

stop_helpers
sleep 1

disconnect_docker_hosts llb1 l3h1
disconnect_docker_hosts llb1 l3ep1
disconnect_docker_hosts llb1 l3ep2
disconnect_docker_hosts llb1 l3ep3

delete_docker_host l3ep3
delete_docker_host l3ep2
delete_docker_host l3ep1
delete_docker_host l3h1
delete_docker_host llb1

echo SCENARIO-ai-model-routing-cleanup [OK]
