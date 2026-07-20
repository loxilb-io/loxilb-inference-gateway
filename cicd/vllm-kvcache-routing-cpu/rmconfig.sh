#!/bin/bash
# rmconfig.sh — idempotent SCOPED teardown for the vllm-kvcache-routing-cpu testbed.
#
# disconnect_docker_hosts / delete_docker_host already tolerate already-gone hosts (they guard on
# existence and swallow docker errors), so this is safe to re-run after a partial or failed
# config.sh / validation.sh. Teardown is SCOPED per-container — NEVER a host-wide network-namespace
# sweep or a process-name-wide kill (a host-wide sweep reaps unrelated
# PIDs/netns across the runner). The reflect-echo backends are --rm so deleting them stops the server too.
#
# Also kill the backgrounded kv_event_publisher.py by its ANCHORED tag (kvpub80) — the
# tag was set via `exec -a kvpub80` at launch so a tag lookup matches ONLY this suite's publisher PIDs,
# never an unrelated python3 process on the runner. We resolve the exact PIDs by the unique anchored
# tag and kill THOSE PIDs — a scoped per-PID kill, never a process-name-wide sweep.

source ../common.sh

PUB_TAG="kvpub80"

# Resolve this suite's publisher PIDs by the unique anchored tag and kill exactly those PIDs (scoped).
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

delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3ep1
delete_docker_host l3ep2
delete_docker_host l3ep3
delete_docker_host l3ep4
delete_docker_host l3ep5
delete_docker_host l3ep6

# Clean up any temp per-EP corpus files the publisher driver dropped in this dir.
rm -f "$(dirname "$0")"/.kvpub-*.json "$(dirname "$0")"/.kvpub-baseline.log >/dev/null 2>&1 || true

echo "#########################################"
echo "Deleted vllm-kvcache-routing-cpu testbed (6 EPs + client + llb1; publisher tag=${PUB_TAG} killed)"
echo "#########################################"
