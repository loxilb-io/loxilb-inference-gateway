#!/bin/bash
# rmconfig.sh — idempotent SCOPED teardown for cfg-persist-roundtrip.
# Per-container teardown only (never a host-wide netns sweep or a
# process-name-wide kill); safe after a partial or failed config.sh.
# The artifacts/ directory is deliberately left in place: CI uploads it
# as run evidence after teardown; config.sh clears stale artifacts.

source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"

disconnect_docker_hosts l3h1  llb1
disconnect_docker_hosts l3ep1 llb1
disconnect_docker_hosts l3ep2 llb1
disconnect_docker_hosts l3ep3 llb1

delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3ep1
delete_docker_host l3ep2
delete_docker_host l3ep3

# Root-owned stages + gateway-written config volume (holds managed cert
# material and the node-local OTLP header secrets from the TLS fixtures).
sudo rm -rf "${CFGDIR}/.kvprofiles-stage" "${CFGDIR}/.certs-stage" "${CFGDIR}/llb1_config" >/dev/null 2>&1 || true

echo "cfg-persist-roundtrip topology deleted"
