#!/bin/bash
# config.sh - host snapshot before anything starts, then the client and the
# three h2c mocks (the gateway container is started per arm by validation.sh).
source "$(dirname "$0")/lib.sh"
mkdir -p "$EVID/host"
for n in $NAMES; do
  docker inspect "$n" >/dev/null 2>&1 && { say "FATAL: $n already exists; run rmconfig.sh"; exit 1; }
done
"$SCN_DIR/hostcheck.sh" prerun "$EVID/host" || exit 1
start_hosts || { say "FATAL: hosts"; exit 1; }
say "client and mocks up: $(docker ps --format '{{.Names}}' | grep -c "^$P") containers"
