#!/bin/bash
# rmconfig.sh — idempotent SCOPED teardown for appliance-dispatch.
# Per-container only; safe after a partial or failed config.sh. artifacts/ is
# left in place for CI to upload; config.sh clears stale ones.
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"

delete_docker_host llb1

sudo rm -rf "${CFGDIR}/.cli-under-test" >/dev/null 2>&1 || true

echo "appliance-dispatch topology deleted"
