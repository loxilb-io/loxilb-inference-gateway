#!/bin/bash
# run.sh - config, validation and removal; the containers are removed on
# every exit path, so nothing is left running unattended.
D=$(cd "$(dirname "$0")" && pwd)
trap '"$D/rmconfig.sh"' EXIT
"$D/config.sh" || exit 1
"$D/validation.sh"     # its exit status is the run's (rmconfig.sh runs on exit)
