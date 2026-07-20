#!/bin/bash

source ../common.sh

# Cleanup: delete /v1 fallback rule added by PREFIX-T1 LPM test
$dexec llb1 loxicmd delete lb 10.10.10.254 --tcp=2020 --path-prefix=/v1 2>/dev/null || true

disconnect_docker_hosts l3h1 llb1
disconnect_docker_hosts l3ep1 llb1
disconnect_docker_hosts l3ep2 llb1
disconnect_docker_hosts l3ep3 llb1

delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3ep1
delete_docker_host l3ep2
delete_docker_host l3ep3

# Generate certificates
rm -rf 10.10.10.254  # LB VIP
rm -rf 10.10.10.1    # Client

echo "#########################################"
echo "Deleted testbed"
echo "#########################################"
