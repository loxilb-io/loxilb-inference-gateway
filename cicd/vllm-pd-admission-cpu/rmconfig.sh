#!/bin/bash
# rmconfig.sh — idempotent SCOPED teardown for the vllm-pd-admission-cpu testbed.
#
# disconnect_docker_hosts / delete_docker_host already tolerate already-gone hosts, so this
# is safe to re-run after a partial or failed config.sh / validation.sh. Teardown is SCOPED
# per-container — NEVER a host-wide network-namespace sweep or a process-name-wide kill.
# `ip netns exec` is a NETWORK namespace, not a pid namespace, so the EP hosts share the
# runner's pid namespace and a pattern kill would reap other scenarios' backends.
#
# This script is called BETWEEN PHASES, not only at the end: validation.sh tears the bed
# down and re-runs config.sh with a different queue depth, because both admission knobs are
# read getenv-once at process start. So it has to leave NOTHING behind that would make the
# second config.sh read as a stale-state failure — in particular the fault stubs, which
# hold the EP :80 REDIRECT and would otherwise survive into the next phase and make a
# healthy pool look permanently hung.

source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
FAULT_SWAP="${CFGDIR}/../vllm-kvcache-routing-cpu/pd-fault-swap.sh"

# Restore every prefill EP netns to its reflect-echo default before the netns is torn down.
# `off` is idempotent and is a successful no-op on an EP that was never switched, so this
# is safe on a bed that never ran a fault. It must run BEFORE delete_docker_host, since it
# needs the netns to still exist.
if [[ -x "${FAULT_SWAP}" ]]; then
    for ns in l3ep1 l3ep3 l3ep5; do
        if ip netns list 2>/dev/null | grep -qw "${ns}"; then
            "${FAULT_SWAP}" "${ns}" off >/dev/null 2>&1 || true
        fi
    done
fi

disconnect_docker_hosts l3h1  llb1
disconnect_docker_hosts l3ep1 llb1
disconnect_docker_hosts l3ep2 llb1
disconnect_docker_hosts l3ep3 llb1
disconnect_docker_hosts l3ep4 llb1
disconnect_docker_hosts l3ep5 llb1
disconnect_docker_hosts l3ep6 llb1

delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3ep1
delete_docker_host l3ep2
delete_docker_host l3ep3
delete_docker_host l3ep4
delete_docker_host l3ep5
delete_docker_host l3ep6

# Runtime artifacts dropped by validation.sh (holder pidfiles, probe code files, the
# per-phase metric baselines). Scoped to this directory by name.
rm -f "${CFGDIR}"/.adm-* >/dev/null 2>&1 || true

echo "#########################################"
echo "Deleted vllm-pd-admission-cpu testbed (6 EPs + client + llb1; fault stubs restored)"
echo "#########################################"
