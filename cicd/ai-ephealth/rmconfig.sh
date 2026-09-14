#!/bin/bash
source ../common.sh
echo SCENARIO-ai-ephealth-cleanup

# By argv, not killall: hexec is a NETWORK-namespace exec, so every mock shares
# the host pid namespace and a blanket `killall node` would reap another
# scenario's backends too.
sudo pkill -9 -f "[t]cp_server.js server-a" 2>/dev/null
sudo pkill -9 -f "[t]cp_server.js server-b" 2>/dev/null
sleep 1

disconnect_docker_hosts llb1 l3h1
disconnect_docker_hosts llb1 l3ep1
disconnect_docker_hosts llb1 l3ep2

delete_docker_host l3ep2
delete_docker_host l3ep1
delete_docker_host l3h1
delete_docker_host llb1

echo SCENARIO-ai-ephealth-cleanup [OK]
