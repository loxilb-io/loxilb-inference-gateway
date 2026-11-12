#!/bin/bash
# Scenario-specific ownership expectations. The shared canonical oracle keeps
# the adoption marker: boot replay must preserve it, and only the committed
# interactive restore is allowed to change it.

bgp_adoption_is() { # <snapshot.json> <true|false>
    jq -e --argjson expected "$2" '
        (if has("bgp_api_adopted") then .bgp_api_adopted else false end) == $expected
    ' "$1" > /dev/null
}

expect_bgp_adoption() { # <baseline canonical dir> <expected canonical dir>
    local baseline=$1 expected=$2 domain
    # The scenario starts unadopted; do not let a stale/already adopted fixture
    # hide the transition this leg is meant to prove.
    bgp_adoption_is "$baseline/snapshotdoc.json" false || return 1
    [[ "$baseline" != "$expected" ]] || return 1
    mkdir -p "$expected" || return 1
    for domain in $PLIB_DOMAINS; do
        if [[ "$domain" == snapshotdoc ]]; then
            jq -S '.bgp_api_adopted = true' "$baseline/$domain.json" > "$expected/$domain.json" || return 1
        else
            cp "$baseline/$domain.json" "$expected/$domain.json" || return 1
        fi
    done
}
