#!/bin/bash
# rmconfig.sh — idempotent SCOPED teardown for the kv-profile-admission
# scenario. Teardown is per-container — never a host-wide netns sweep or a
# process-name-wide kill (those reap unrelated PIDs/netns on shared
# runners). Safe to re-run after a partial or failed config.sh.

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

# Root-owned registry stages (created by config.sh, mounted read-only).
sudo rm -rf "${CFGDIR}/.kvprofiles-stage" "${CFGDIR}/.tokenizers-stage" >/dev/null 2>&1 || true

echo "kv-profile-admission topology deleted"
