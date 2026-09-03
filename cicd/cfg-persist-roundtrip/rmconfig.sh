#!/bin/bash
# rmconfig.sh — idempotent SCOPED teardown for cfg-persist-roundtrip.
# Per-container teardown only (never a host-wide netns sweep or a
# process-name-wide kill); safe after a partial or failed config.sh.

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

# Root-owned stage + gateway-written config volume + run artifacts.
sudo rm -rf "${CFGDIR}/.kvprofiles-stage" "${CFGDIR}/llb1_config" \
    "${CFGDIR}/artifacts" >/dev/null 2>&1 || true

echo "cfg-persist-roundtrip topology deleted"
