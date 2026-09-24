#!/bin/bash

source ../common.sh

disconnect_docker_hosts l3h1 llb1
disconnect_docker_hosts l3ep1 llb1

delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3ep1

echo "#########################################"
echo "Deleted testbed"
echo "#########################################"
