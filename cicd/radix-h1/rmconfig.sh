#!/bin/bash
# rmconfig.sh - remove the five containers (anonymous volumes included) and
# compare the host with the prerun snapshot.
source "$(dirname "$0")/lib.sh"
remove_containers
sleep 2
"$SCN_DIR/hostcheck.sh" postremoval "$EVID/host" | tee "$EVID/hostcheck-postremoval.txt"
