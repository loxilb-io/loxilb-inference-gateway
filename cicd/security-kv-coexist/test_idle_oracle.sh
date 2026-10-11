#!/bin/bash
# A falling gauge cannot satisfy the idle-reap oracle; the owning event must
# arrive, and a missing event must remain a failed threshold.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
fixture='{}'
llb_curl() { printf '%s\n' "$fixture"; }
for fixture in '{}' '{"result":"not found"}' '{"activeConnections":null}' '{"activeConnections":false}' '{"activeConnections":-1}' 'not-json'; do
    [[ $(lb_stats_active) == -1 ]]
done
fixture='{"activeConnections":0}'; [[ $(lb_stats_active) == 0 ]]
fixture='{"ActiveConnections":1}'; [[ $(lb_stats_active) == 1 ]]
llb_curl() { return 22; }
[[ $(lb_stats_active) == -1 ]]
idle_test_root=$(mktemp -d)
trap 'rm -rf "$idle_test_root"' EXIT
printf '0\n' > "$idle_test_root/calls"
sleep() { :; }
dp_log_count() {
    local n
    n=$(cat "$idle_test_root/calls")
    n=$((n + 1)); printf '%s\n' "$n" > "$idle_test_root/calls"
    if ((n >= 3)); then echo 1; else echo 0; fi
}
# Gauge is already zero before the event; the helper must still poll 3 times.
lb_stats_active() { echo 0; }
observed=$(wait_dp_log_count_ge IDLE_TIMEOUT 1 5)
[[ $observed == 1 && $(cat "$idle_test_root/calls") == 3 ]]
dp_log_count() { echo 0; }
observed=$(wait_dp_log_count_ge IDLE_TIMEOUT 1 3)
[[ $observed == 0 ]]
echo 'idle oracle: HTTP/missing/invalid gauge is unknown; explicit zero retained; owning event required; missing event fails PASS'
