#!/bin/bash

source ../common.sh

delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3ep1

echo "#########################################"
echo "Deleted testbed"
echo "#########################################"
