#!/bin/bash
# Exercise the actual GET/deep-diff oracle: defaults are compatible, budgets
# and unknown desired-state fields must never be discarded as runtime stats.
set -euo pipefail
case_root=$(mktemp -d)
trap 'rm -rf "$case_root"' EXIT
PLIB_ARTIFACTS="$case_root/artifacts"
source "$(dirname "$0")/persist_lib.sh"
PLIB_DOMAINS=securityrate
fixture='{}'
plib_curl() {
    local out=''
    while (($#)); do
        if [[ $1 == -o ]]; then out=$2; break; fi
        shift
    done
    printf '%s\n' "$fixture" > "$out"
}
capture() {
    fixture=$2
    mkdir -p "$case_root/$1"
    plib_dump_domain fixture securityrate "$case_root/$1"
}
capture legacy '{"securityrateAttr":[{"whitelistIps":null}]}'
capture zero '{"securityrateAttr":[{"whitelistIps":null,"aggregateSynThreshold":0,"aggregateConnRatePerSec":0,"aggregateUdpPktThreshold":0,"aggregateUdpBandwidthMB":0}]}'
deep_diff "$case_root/legacy" "$case_root/zero" defaults
capture positive '{"securityrateAttr":[{"whitelistIps":null,"aggregateSynThreshold":120,"aggregateConnRatePerSec":130,"aggregateUdpPktThreshold":140,"aggregateUdpBandwidthMB":2}]}'
capture traffic '{"securityrateAttr":[{"whitelistIps":null,"aggregateSynThreshold":120,"aggregateConnRatePerSec":130,"aggregateUdpPktThreshold":140,"aggregateUdpBandwidthMB":2,"udpPassed":140,"udpBlocked":360,"udpBytesPassed":6720,"udpBytesBlocked":17280,"trackingFailures":7,"unsupportedPacketBlocked":8,"aggregateSynBlocked":9,"aggregateConnBlocked":10,"aggregateUdpBlocked":360}]}'
deep_diff "$case_root/positive" "$case_root/traffic" counters
for field in aggregateSynThreshold aggregateConnRatePerSec aggregateUdpPktThreshold aggregateUdpBandwidthMB; do
    changed=$(jq --arg f "$field" '.securityrateAttr[0][$f] = 0' <<< '{"securityrateAttr":[{"whitelistIps":null,"aggregateSynThreshold":120,"aggregateConnRatePerSec":130,"aggregateUdpPktThreshold":140,"aggregateUdpBandwidthMB":2}]}')
    capture changed "$changed"
    if deep_diff "$case_root/positive" "$case_root/changed" "$field" > /dev/null; then
        echo "FAIL: lost $field escaped the oracle"; exit 1
    fi
done
capture unknown '{"securityrateAttr":[{"whitelistIps":null,"newDesiredPolicy":1}]}'
if deep_diff "$case_root/legacy" "$case_root/unknown" unknown > /dev/null; then
    echo 'FAIL: unknown policy escaped the oracle'; exit 1
fi
capture empty '{"securityrateAttr":[]}'
if deep_diff "$case_root/legacy" "$case_root/empty" empty > /dev/null; then
    echo 'FAIL: missing policy escaped the oracle'; exit 1
fi
echo 'persist securityrate oracle: legacy defaults, positive budgets, traffic counters, loss and unknown-field detection PASS'
