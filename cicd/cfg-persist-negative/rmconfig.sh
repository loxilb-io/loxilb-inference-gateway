#!/bin/bash
# rmconfig.sh — idempotent SCOPED teardown for cfg-persist-negative.
# The artifacts/ directory is deliberately left in place: CI uploads it
# as run evidence after teardown; config.sh clears stale artifacts.

source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"

disconnect_docker_hosts l3h1  llb1
disconnect_docker_hosts l3ep1 llb1

delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3ep1

sudo rm -rf "${CFGDIR}/llb1_config" "${CFGDIR}/.certs-stage" >/dev/null 2>&1 || true

echo "cfg-persist-negative topology deleted"
