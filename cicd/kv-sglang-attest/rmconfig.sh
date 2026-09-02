#!/bin/bash
# rmconfig.sh — tear down the kv-sglang-attest topology.
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
source "${CFGDIR}/lib.sh" 2>/dev/null || true

type kvsgl_sim_pids >/dev/null 2>&1 && sims_stop

disconnect_docker_hosts l3h1  llb1
disconnect_docker_hosts l3ep1 llb1
disconnect_docker_hosts l3ep2 llb1

delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3ep1
delete_docker_host l3ep2

sudo rm -rf "${CFGDIR}/.stage-full" "${CFGDIR}/.tokenizers-stage"
rm -f "${CFGDIR}/.sim-pids"

echo "kv-sglang-attest rmconfig done"
