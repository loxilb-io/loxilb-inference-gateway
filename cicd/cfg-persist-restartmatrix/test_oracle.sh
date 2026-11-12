#!/bin/bash
# No Docker or live speaker required: exercise the actual restart-matrix
# expectation and shared deep diff, including regressions that MUST fail.
set -euo pipefail
case_root=$(mktemp -d)
trap 'rm -rf "$case_root"' EXIT
export PLIB_ARTIFACTS="$case_root/artifacts"
source "$(dirname "$0")/../common/persist_lib.sh"
source "$(dirname "$0")/oracle.sh"

mkdir -p "$case_root/base"
for domain in $PLIB_DOMAINS; do
    printf '[]\n' > "$case_root/base/$domain.json"
done
jq -nS '{schema_version:"1.13",generation:7,domains:{bgp_global:{local_as:65001},bgp_neighbors:[{remote_ip:"192.0.2.2",remote_as:65002}]}}' > "$case_root/base/snapshotdoc.json"
cp -R "$case_root/base" "$case_root/original"
bgp_adoption_is "$case_root/base/snapshotdoc.json" false
expect_bgp_adoption "$case_root/base" "$case_root/expected"
deep_diff "$case_root/original" "$case_root/base" unchanged-baseline
# Every field participates, including unknown desired-state fields.
jq -S '.bgp_api_adopted = true' "$case_root/base/snapshotdoc.json" > "$case_root/adopted.json"
cmp "$case_root/adopted.json" "$case_root/expected/snapshotdoc.json"
cp -R "$case_root/expected" "$case_root/recovered"
cp -R "$case_root/recovered" "$case_root/reboot"
for phase in recovered reboot; do
    bgp_adoption_is "$case_root/$phase/snapshotdoc.json" true
    deep_diff "$case_root/expected" "$case_root/$phase" "$phase"
done
if deep_diff "$case_root/base" "$case_root/recovered" old-baseline > /dev/null; then
    echo 'FAIL: the old oracle ignored adoption'; exit 1
fi
reject_diff() {
    if deep_diff "$case_root/expected" "$case_root/changed" "$1" > /dev/null; then
        echo "FAIL: $1 escaped the deep-diff oracle"; exit 1
    fi
}
# Both phases require the marker. Omission, false, null and string booleans
# cannot pass either the explicit ownership check or the configuration diff.
for phase in recovered reboot; do
    for mutation in 'del(.bgp_api_adopted)' '.bgp_api_adopted = false' '.bgp_api_adopted = null' '.bgp_api_adopted = "true"'; do
        rm -rf "$case_root/changed"
        cp -R "$case_root/$phase" "$case_root/changed"
        jq -S "$mutation" "$case_root/$phase/snapshotdoc.json" > "$case_root/changed/snapshotdoc.json"
        if bgp_adoption_is "$case_root/changed/snapshotdoc.json" true; then
            echo "FAIL: $phase accepted invalid adoption: $mutation"; exit 1
        fi
        reject_diff "$phase-adoption"
    done
done
# The scope of the exception is exactly the top-level ownership marker:
# lost or edited BGP, other domains and unknown metadata remain failures.
for mutation in '.domains.bgp_global.local_as = 65003' '.domains.bgp_neighbors = []' '.newDesiredPolicy = 1'; do
    jq -S "$mutation" "$case_root/expected/snapshotdoc.json" > "$case_root/changed/snapshotdoc.json"
    reject_diff desired-state
done
cp "$case_root/expected/snapshotdoc.json" "$case_root/changed/snapshotdoc.json"
printf '[{"rule":"lost-or-edited"}]\n' > "$case_root/changed/firewall.json"
reject_diff firewall
rm "$case_root/changed/firewall.json"
reject_diff missing-domain
# Boot replay still compares the unadopted documents without an exception.
if expect_bgp_adoption "$case_root/recovered" "$case_root/already-adopted"; then
    echo 'FAIL: an already adopted baseline hid the transition'; exit 1
fi
if expect_bgp_adoption "$case_root/base" "$case_root/base"; then
    echo 'FAIL: expected-state generation overwrote the baseline'; exit 1
fi
deep_diff "$case_root/original" "$case_root/base" final-baseline
jq -S '.bgp_api_adopted = false' "$case_root/base/snapshotdoc.json" > "$case_root/explicit-false.json"
bgp_adoption_is "$case_root/explicit-false.json" false
for invalid in null '"false"'; do
    jq -S --argjson value "$invalid" '.bgp_api_adopted = $value' "$case_root/base/snapshotdoc.json" > "$case_root/invalid.json"
    if bgp_adoption_is "$case_root/invalid.json" false; then
        echo "FAIL: malformed unadopted marker $invalid passed"; exit 1
    fi
done
echo 'persist adoption oracle: explicit restore, reboot retention, strict desired-state diff and negative cases PASS'
