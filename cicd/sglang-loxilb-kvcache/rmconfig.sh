#!/bin/bash
# rmconfig.sh — idempotent SCOPED teardown for the sglang-loxilb-kvcache two-VIP testbed.
#
# PAIRED-RESOURCE AUDIT (everything config.sh creates, removed here — and NOTHING else):
#   * publishers  — kv_event_publisher.py processes launched under the ANCHORED tag kvpub99
#                   (`exec -a kvpub99`); killed per-resolved-PID below. validation.sh's own
#                   publishers (union / negative-control / restart / zero-hit legs) use the
#                   SAME tag, so they are covered too. NEVER a process-name-wide sweep
#                   (a host-wide kill would reap unrelated PIDs on the runner).
#   * containers  — llb1 (loxilb, both rules die with it — rule teardown runs
#                   KvSubscriberStopAll per rule, the clean-teardown surface validation.sh
#                   asserts via the Go log before ever reaching this teardown),
#                   l3h1 (client), l3ep1..l3ep4 (VIP-A P/D EPs), l3ep5..l3ep7 (VIP-B EPs).
#                   reflect-echo containers are --rm, so deletion stops the server too.
#   * veth links  — disconnect_docker_hosts per pair (tolerates already-gone hosts).
#   * temp files  — .kvpub-*.json / .kvpub-*.log / .fr*-*.json scratch dropped by config.sh
#                   and validation.sh in THIS directory.
#   * VIP-C       — the zero-hit-watchdog throwaway rule is created AND deleted by
#                   validation.sh leg 7; if a failed run leaked it, it lives inside llb1 and
#                   dies with the container here (no host-side residue).
#
# disconnect_docker_hosts / delete_docker_host tolerate already-gone hosts, so this is safe
# to re-run after a partial or failed config.sh / validation.sh.

source ../common.sh

PUB_TAG="kvpub99"

# Resolve this suite's publisher PIDs by the unique anchored tag and kill exactly those
# PIDs (scoped per-PID kill — never a name-wide killall).
for pid in $(pgrep -f "${PUB_TAG}" 2>/dev/null); do
    kill "${pid}" >/dev/null 2>&1 || true
done

disconnect_docker_hosts l3h1  llb1
disconnect_docker_hosts l3ep1 llb1
disconnect_docker_hosts l3ep2 llb1
disconnect_docker_hosts l3ep3 llb1
disconnect_docker_hosts l3ep4 llb1
disconnect_docker_hosts l3ep5 llb1
disconnect_docker_hosts l3ep6 llb1
disconnect_docker_hosts l3ep7 llb1

delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3ep1
delete_docker_host l3ep2
delete_docker_host l3ep3
delete_docker_host l3ep4
delete_docker_host l3ep5
delete_docker_host l3ep6
delete_docker_host l3ep7

# Clean up the scratch corpora/logs config.sh + validation.sh dropped in this dir.
rm -f "$(dirname "$0")"/.kvpub-*.json "$(dirname "$0")"/.kvpub-*.log >/dev/null 2>&1 || true

echo "#########################################"
echo "Deleted sglang-loxilb-kvcache testbed (7 EPs + client + llb1; publisher tag=${PUB_TAG} killed)"
echo "#########################################"
