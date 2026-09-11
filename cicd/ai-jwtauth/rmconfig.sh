#!/bin/bash
source ../common.sh
echo SCENARIO-ai-jwtauth-cleanup

# Matched on the script path, not on "python3": a network namespace shares
# the host PID namespace, so a name-wide kill here would reach every
# unrelated python process on the machine.
sudo pkill -f 'hdr_echo\.py' 2>/dev/null
sleep 1

disconnect_docker_hosts llb1 l3h1
disconnect_docker_hosts llb1 l3ep1
disconnect_docker_hosts llb1 l3ep2

delete_docker_host l3ep2
delete_docker_host l3ep1
delete_docker_host l3h1
delete_docker_host llb1

## Both run with --rm, so a stop removes them — but asynchronously, which
## leaves a caller that checks straight away looking at a phantom. Force the
## removal so teardown is finished when this returns.
docker rm -f kc-aigw    >/dev/null 2>&1 || true
docker rm -f pg-jwtauth >/dev/null 2>&1 || true

rm -f .state .tok_dave .nonce .nonce.last
rm -rf llb1_config

echo SCENARIO-ai-jwtauth-cleanup [OK]
