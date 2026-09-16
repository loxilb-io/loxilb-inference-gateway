#!/bin/bash
# rmconfig.sh — ai-qos-ha-sync teardown (idempotent).
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"

# The echo backend runs as host python inside the EP netns. hexec is a
# network namespace, NOT a pid namespace, so a name-matched kill would reap
# other scenarios' backends too — match on this scenario's own argv label.
# External kill/pkill are DISABLED stubs on the CI host; signal via the
# shell builtin against /proc-scanned pids.
for d in /proc/[0-9]*/cmdline; do
    if tr "\0" " " < "$d" 2>/dev/null | grep -q "hdr_echo.py qos-ha-echo"; then
        p="${d#/proc/}"; p="${p%/cmdline}"
        kill -CONT "$p" 2>/dev/null
        kill -9 "$p" 2>/dev/null
    fi
done

disconnect_docker_hosts l3h1  llb1
disconnect_docker_hosts l3h1  llb2
disconnect_docker_hosts l3ep1 llb1
disconnect_docker_hosts l3ep1 llb2

delete_docker_host llb1
delete_docker_host llb2
delete_docker_host l3h1
delete_docker_host l3ep1

docker rm -f pg-qos-ha >/dev/null 2>&1

rm -f "${CFGDIR}/.keys" "${CFGDIR}/.fresh" "${CFGDIR}/.llb1-bridge-ip" "${CFGDIR}/.llb2-bridge-ip"
rm -rf "${CFGDIR}/llb1_config" "${CFGDIR}/llb2_config"

echo "ai-qos-ha-sync rmconfig done"
