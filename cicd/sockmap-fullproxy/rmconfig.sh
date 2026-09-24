#!/bin/bash
#
# sockmap-fullproxy / rmconfig.sh
#
# Tears down the testbed built by config.sh and clears the artifacts directory.

source ../common.sh
source ./sockmap_common.sh

# Only reaps backend HTTP servers left behind by an aborted validation run.
# A broad pkill is avoided: it can take down the integrated terminal or VS Code
# node processes as well.
sockmap_kill_tcp_servers

disconnect_docker_hosts l3h1  llb1
disconnect_docker_hosts l3ep1 llb1
disconnect_docker_hosts l3ep2 llb1

delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3ep1
delete_docker_host l3ep2

# The API-key store config.sh spawns under SOCKMAP_AI_KEY_STORE=1, and the
# config directory it mounted. Both are no-ops when the store was not started.
sockmap_key_store_down llb1_config

sockmap_clear_artifacts

echo "#########################################"
echo "Deleted testbed (sockmap-fullproxy)"
echo "#########################################"
