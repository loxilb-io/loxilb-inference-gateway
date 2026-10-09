#!/bin/bash
source ../common.sh

PUB_TAG="${PUB_TAG:-kvpubsec}"
for pid in $(pgrep -f "${PUB_TAG}" 2>/dev/null); do
    kill "${pid}" >/dev/null 2>&1 || true
done
docker rm -f llbpo >/dev/null 2>&1 || true

disconnect_docker_hosts l3h1  llb1
disconnect_docker_hosts l3h2  llb1
for ep in l3ep1 l3ep2 l3ep3 l3ep4 l3ep5 l3ep6; do disconnect_docker_hosts $ep llb1; done

delete_docker_host llb1
delete_docker_host l3h1
delete_docker_host l3h2
for ep in l3ep1 l3ep2 l3ep3 l3ep4 l3ep5 l3ep6; do delete_docker_host $ep; done

rm -f "$(dirname "$0")"/.kvpub-* "$(dirname "$0")"/.c7-* "$(dirname "$0")"/.c8.* \
      "$(dirname "$0")"/.test_*.log >/dev/null 2>&1 || true

echo "#########################################"
echo "Deleted security-kv-coexist testbed (llb1, l3h1, l3h2, 6 EPs; publisher tag=${PUB_TAG} killed)"
echo "#########################################"
