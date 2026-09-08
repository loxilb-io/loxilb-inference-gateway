#!/bin/bash
cd "$(dirname "$0")"
source ../common.sh
echo SCENARIO-mgmt-profile-sanity-cleanup

disconnect_docker_hosts llb1 c1
disconnect_docker_hosts llb1 c2
disconnect_docker_hosts llb1 c3

delete_docker_host c3
delete_docker_host c2
delete_docker_host c1
delete_docker_host llb1

echo SCENARIO-mgmt-profile-sanity-cleanup [OK]
