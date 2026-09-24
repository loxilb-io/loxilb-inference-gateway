#!/bin/bash
source ../common.sh
echo SCENARIO-audit-data-cleanup

stop_helpers
sleep 1

disconnect_docker_hosts llb1 l3h1
disconnect_docker_hosts llb1 l3ep1

delete_docker_host l3ep1
delete_docker_host l3h1
delete_docker_host llb1

docker stop pg-audit-data 2>/dev/null || true

rm -f .state
rm -rf llb1_config

echo SCENARIO-audit-data-cleanup [OK]
