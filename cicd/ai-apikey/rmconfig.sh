#!/bin/bash
source ../common.sh
echo SCENARIO-ai-apikey-cleanup

# Stop backend process
$hexec l3ep1 sudo killall -9 node 2>/dev/null

## wait for processes to die
sleep 1

## Disconnect and delete virtual hosts
disconnect_docker_hosts llb1 l3h1
disconnect_docker_hosts llb1 l3ep1

delete_docker_host l3ep1
delete_docker_host l3h1
delete_docker_host llb1

## Remove the PostgreSQL container
docker stop pg-ai 2>/dev/null || true
docker rm   pg-ai 2>/dev/null || true

## Remove config mount dir
rm -rf llb1_config

echo SCENARIO-ai-apikey-cleanup [OK]
