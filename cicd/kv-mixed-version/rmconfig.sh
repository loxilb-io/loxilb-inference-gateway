#!/bin/bash
# rmconfig.sh — kv-mixed-version teardown (idempotent).
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"

# Simulators run as host python inside the EP netns — kill by recorded pid
# (children included: nohup'd sudo wraps the python).
# External kill/pkill are DISABLED stubs on the CI host — signal via the
# shell BUILTIN against /proc-scanned pids or simulators survive teardown
# (SIGSTOPped ones included) and leak across runs.
for d in /proc/[0-9]*/cmdline; do
    if tr "\0" " " < "$d" 2>/dev/null | grep -q "vllm_attest_sim.py"; then
        p="${d#/proc/}"; p="${p%/cmdline}"
        kill -CONT "$p" 2>/dev/null
        kill -9 "$p" 2>/dev/null
    fi
done
rm -f "${CFGDIR}/.sim-pids"

disconnect_docker_hosts l3h1  llb1
disconnect_docker_hosts l3h1  llb2
disconnect_docker_hosts l3ep1 llb1
disconnect_docker_hosts l3ep1 llb2
disconnect_docker_hosts l3ep2 llb1
disconnect_docker_hosts l3ep2 llb2

delete_docker_host llb1
delete_docker_host llb2
delete_docker_host l3h1
delete_docker_host l3ep1
delete_docker_host l3ep2

sudo rm -rf "${CFGDIR}/.stage-full" "${CFGDIR}/.stage-divergent" "${CFGDIR}/.tokenizers-stage" \
            "${CFGDIR}/.stage-corrupt" "${CFGDIR}/.llb2-bridge-ip"

echo "kv-mixed-version rmconfig done"
