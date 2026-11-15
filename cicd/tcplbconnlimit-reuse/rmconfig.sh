#!/bin/bash

source ../common.sh

stop_helpers

disconnect_docker_hosts l3h1 llb1
disconnect_docker_hosts l3h2 llb1
disconnect_docker_hosts l3ep1 llb1
disconnect_docker_hosts l3ep2 llb1

delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3h2
delete_docker_host l3ep1
delete_docker_host l3ep2

echo "#########################################"
echo "Deleted testbed"
echo "#########################################"
