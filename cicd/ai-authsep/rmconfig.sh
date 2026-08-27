#!/bin/bash
cd "$(dirname "$0")"
source ../common.sh
echo SCENARIO-ai-authsep-cleanup

$hexec l3ep1 killall -9 python3 2>/dev/null || true
sleep 1

disconnect_docker_hosts llb1 l3h1
disconnect_docker_hosts llb1 l3ep1

delete_docker_host l3ep1
delete_docker_host l3h1
delete_docker_host llb1

./pg.sh down || true

# The client key and the store password live here; leaving them behind on a
# runner is the kind of thing this scenario exists to object to.
rm -rf llb1_config certs .state

echo SCENARIO-ai-authsep-cleanup [OK]
