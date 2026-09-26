#!/bin/bash
source ../common.sh
echo SCENARIO-audit-mgmt-cleanup

stop_helpers

## wait for processes to die
sleep 1

## A paused store left behind by an aborted T20 would hang the teardown.
docker unpause pg-audit >/dev/null 2>&1 || true

## Disconnect and delete virtual hosts
disconnect_docker_hosts llb1 l3h1
disconnect_docker_hosts llb1 l3ep1

delete_docker_host l3ep1
delete_docker_host l3h1
delete_docker_host llb1

## Remove the PostgreSQL container
docker stop pg-audit 2>/dev/null || true
docker rm   pg-audit 2>/dev/null || true

## Remove config mount dir and the recorded flag sets
rm -rf llb1_config .state

echo SCENARIO-audit-mgmt-cleanup [OK]
