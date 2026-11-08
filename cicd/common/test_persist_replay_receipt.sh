#!/bin/bash
# Exercise the shared boot oracle, including a stale success log while BGP
# remains pending. HTTP availability or a partial boot must never pass it.
set -euo pipefail
case_root=$(mktemp -d)
trap 'rm -rf "$case_root"' EXIT
PLIB_ARTIFACTS="$case_root/artifacts"
source "$(dirname "$0")/persist_lib.sh"
complete='{"ready":true,"boot":{"snapshot_found":true,"succeeded":true,"degraded":false,"legacy_fallback":false}}'
fixture=$complete
http=200
legacy_log=1
sleep() { :; }
# Old log receipts can be stale or absent; the actual API is authoritative.
docker() { return "$legacy_log"; }
plib_curl() {
    local out=""
    while (($#)); do
        if [[ "$1" == "-o" ]]; then out=$2; shift; fi
        shift
    done
    local n
    n=$(cat "$case_root/attempts")
    n=$((n + 1)); echo "$n" > "$case_root/attempts"
    if [[ "${transition:-0}" == "1" && "$n" -ge 3 ]]; then
        printf '%s' "$complete" > "$out"; printf 200
    else
        printf '%s' "$fixture" > "$out"; printf '%s' "$http"
    fi
}
failures=0
check() {
    local name=$1 expected=$2 actual=0
    echo 0 > "$case_root/attempts"
    wait_replay_receipt fixture > "$case_root/$name.log" 2>&1 || actual=1
    if [[ "$actual" != "$expected" ]]; then
        echo "FAIL: $name result=$actual expected=$expected"; failures=$((failures + 1))
    else
        echo "PASS: $name"
    fi
}
check complete-without-old-log 0
http=503;fixture='{"ready":false,"boot":{"snapshot_found":true,"succeeded":true,"degraded":false,"legacy_fallback":false},"reasons":["dependency api-key-db unavailable"]}'
check complete-with-independent-dependency-degraded 0
http=200;fixture='{"ready":true,"boot":{"snapshot_found":true,"succeeded":false,"degraded":false,"legacy_fallback":false}}'
check node-ready-does-not-prove-replay 1
fixture=$complete
# An old success marker must not make any invalid API receipt pass.
legacy_log=0
http=503;fixture='{"ready":false,"boot":{"snapshot_found":true,"succeeded":false,"degraded":true,"legacy_fallback":false},"reasons":["bgp_domain_pending"]}'
check pending-with-stale-log 1
http=200
check pending-on-200 1
fixture='{"ready":true,"boot":{"snapshot_found":false,"succeeded":false,"degraded":false,"legacy_fallback":false}}'
check cold-ready-is-not-replay 1
fixture='{"ready":true,"boot":{"snapshot_found":true,"succeeded":true,"degraded":true,"legacy_fallback":false}}'
check degraded 1
fixture='{"ready":true,"boot":{"snapshot_found":true,"succeeded":true,"degraded":false,"legacy_fallback":true}}'
check legacy-fallback 1
fixture='{"ready":true,"boot":{"snapshot_found":true,"succeeded":true,"degraded":false,"legacy_fallback":false,"quarantine_path":"snapshot.json.failed-1"}}'
check quarantined-success-is-not-replay 1
fixture='{"ready":true,"boot":{"snapshot_found":true,"succeeded":"true","degraded":false,"legacy_fallback":false}}'
check malformed-boolean 1
fixture='not-json'
check malformed-json 1
fixture='{}'
check missing-fields 1
fixture=$complete;http=000
check unavailable-with-success-body 1
http=500
check server-error-with-success-body 1
http=503;fixture='{"ready":false,"boot":{"snapshot_found":true,"succeeded":false,"degraded":true,"legacy_fallback":false}}';transition=1
check pending-then-complete 0
[[ $(cat "$case_root/attempts") == 3 ]] || { echo 'FAIL: pending receipt was not polled until complete'; failures=$((failures + 1)); }
[[ "$failures" == 0 ]] || exit 1
echo 'persist replay receipt oracle: 15 cases PASS'
