#!/bin/bash
# validation.sh — SGLang adapter ladder cases (see README.md).
#
# Every case: (re)start the simulators in the case's mode, create the
# strict sglang rule, wait for the expected ladder verdict through the
# kvexactstatus sub-resource, assert typed reasons/log markers, delete the
# rule, stop the sims. Each case gets a FRESH ladder — no state bleeds.

source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
source "${CFGDIR}/lib.sh"
code=0

LB="netlox/v1/config/loadbalancer"
VIP="10.10.10.254"
PORT=8080
MODEL="Qwen/Qwen3-0.6B"
PROF="qwen3-06b-completions-v1"
EPS='{ "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1, "ep_role": 1 }, { "endpointIP": "32.32.32.1", "targetPort": 80, "weight": 1, "ep_role": 2 }'

chk() { # chk <label> <extended-regex> <value>
    local label="$1" want="$2" got="$3"
    if [[ "$got" =~ $want ]]; then
        echo "  [OK] $label"
    else
        echo "  [FAILED] $label — want /$want/ got '$got'"
        code=1
    fi
}

jfield() { echo "$1" | jq -r "$2" 2>/dev/null; }

post_rule() { # post_rule <dp-rank-count> -> "HTTPCODE|body"
    local ranks="$1" body http
    body=$(cat <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}", "port": ${PORT}, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "${VIP}",
    "pd_disagg_mode": true, "probeRetries": 1,
    "kvExactMode": 1, "kvZmqPort": 5557, "kvBlockSize": 16,
    "kvDpRankCount": ${ranks},
    "kvEngineType": "sglang", "model_name": "${MODEL}",
    "kvExactApiMode": "completions", "kvModelProfile": "${PROF}"
  },
  "endpoints": [ ${EPS} ]
}
JSON
)
    http=$($hexec llb1 curl -s -m 10 -o /tmp/kvsgl-resp.json -w "%{http_code}" \
        -X POST "http://localhost:11111/${LB}" -H 'Content-Type: application/json' -d "${body}")
    echo "${http}|$(tr -d '\n' < /tmp/kvsgl-resp.json 2>/dev/null)"
}

del_rule() {
    $hexec llb1 curl -s -m 10 -o /dev/null -X DELETE \
        "http://localhost:11111/${LB}/externalipaddress/${VIP}/port/${PORT}/protocol/tcp"
}

kvstatus() {
    $hexec llb1 curl -s -m 5 \
        "http://localhost:11111/${LB}/externalipaddress/${VIP}/port/${PORT}/protocol/tcp/kvexactstatus"
}

wait_enforced() { # <state-regex> <timeout-s> -> last enforcedState
    local want="$1" tmo="$2" st got=""
    local deadline=$((SECONDS + tmo))
    while (( SECONDS < deadline )); do
        st=$(kvstatus)
        got=$(jfield "$st" '.kvExactStatusAttr[0].enforcedState')
        [[ "$got" =~ $want ]] && { echo "$got"; return 0; }
        sleep 2
    done
    echo "$got"
}

wait_reason() { # <substr> <timeout-s> -> last reasons string
    local want="$1" tmo="$2" got=""
    local deadline=$((SECONDS + tmo))
    while (( SECONDS < deadline )); do
        got=$(jfield "$(kvstatus)" '.kvExactStatusAttr[0].reasonCodes | join(",")')
        [[ "$got" == *"$want"* ]] && { echo "$got"; return 0; }
        sleep 2
    done
    echo "$got"
}

log_count() { # <marker-regex> -> total matches across llb1's log surfaces
    # The gateway writes through two sinks (tk.LogIt file logger + logrus
    # stderr); which one a line lands in depends on the subsystem, and the
    # entrypoint may redirect either. Count BOTH; callers assert on the
    # before/after delta so history never satisfies a case.
    local a b
    a=$(docker logs llb1 2>&1 | grep -cE "$1")
    b=$(docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' | grep -cE "$1")
    echo $((a + b))
}

# case_setup <fail-mode> <dp-ranks>: fresh sims + fresh rule.
case_setup() {
    sims_stop
    sims_start "$1" "$2"
    local r
    r=$(post_rule "$2")
    chk "rule create HTTP 200" '^200\|' "$r"
}

case_teardown() {
    del_rule
    sims_stop
    sleep 2
}

echo "#########################################"
echo "T1: positive ladder, dp=1 -> READY"
echo "#########################################"
T1_BASE=$(log_count 'sglang echo ep .*1 rank\(s\) echoed')
case_setup "" 1
got=$(wait_enforced '^READY$' 90)
chk "T1 enforcedState READY" '^READY$' "$got"
chk "T1 rank-attribution logged" '^1$' \
    "$(( $(log_count 'sglang echo ep .*1 rank\(s\) echoed') > T1_BASE ))"
st=$(kvstatus)
chk "T1 goFenced false" '^false$' "$(jfield "$st" '.kvExactStatusAttr[0].enforcement.goFenced')"
case_teardown

echo "#########################################"
echo "T2: positive ladder, dp=2 -> READY with 2-rank coverage"
echo "#########################################"
T2_BASE=$(log_count 'sglang echo ep .*2 rank\(s\) echoed.*ranks \[0 1\]')
case_setup "" 2
got=$(wait_enforced '^READY$' 120)
chk "T2 enforcedState READY" '^READY$' "$got"
chk "T2 2-rank attribution logged" '^1$' \
    "$(( $(log_count 'sglang echo ep .*2 rank\(s\) echoed.*ranks \[0 1\]') > T2_BASE ))"
case_teardown

echo "#########################################"
echo "T3: tokenize-drift -> holds PROFILE_VALIDATED, token_mismatch"
echo "#########################################"
case_setup "tokenize-drift" 1
got=$(wait_reason 'token_mismatch' 60)
chk "T3 reason token_mismatch" 'token_mismatch' "$got"
chk "T3 never READY" '^(PROFILE_VALIDATED)$' "$(jfield "$(kvstatus)" '.kvExactStatusAttr[0].enforcedState')"
case_teardown

echo "#########################################"
echo "T4: no-echo -> holds TOKEN_PARITY_VERIFIED, challenge_timeout"
echo "#########################################"
case_setup "no-echo" 1
got=$(wait_reason 'challenge_timeout' 120)
chk "T4 reason challenge_timeout" 'challenge_timeout' "$got"
chk "T4 holds at TOKEN_PARITY_VERIFIED" '^TOKEN_PARITY_VERIFIED$' \
    "$(jfield "$(kvstatus)" '.kvExactStatusAttr[0].enforcedState')"
case_teardown

echo "#########################################"
echo "T5: wrong-echo -> challenge_timeout (corrupt chain never matches)"
echo "#########################################"
case_setup "wrong-echo" 1
got=$(wait_reason 'challenge_timeout' 120)
chk "T5 reason challenge_timeout" 'challenge_timeout' "$got"
case_teardown

echo "#########################################"
echo "T6: rank-lie (dp=2) -> subscriber rejects, challenge starves"
echo "#########################################"
T6_BASE=$(log_count 'rank identity mismatch')
case_setup "rank-lie" 2
got=$(wait_reason 'challenge_timeout' 180)
chk "T6 reason challenge_timeout" 'challenge_timeout' "$got"
chk "T6 rank-identity rejection logged" '^1$' \
    "$(( $(log_count 'rank identity mismatch') > T6_BASE ))"
case_teardown

echo "#########################################"
echo "T7: rank-split (dp=2) -> adapter refuses the split echo"
echo "#########################################"
T7_BASE=$(log_count 'echoed from 2 rank streams')
case_setup "rank-split" 2
got=$(wait_reason 'challenge_failed' 120)
chk "T7 reason challenge_failed" 'challenge_failed' "$got"
chk "T7 split-echo refusal logged" '^1$' \
    "$(( $(log_count 'echoed from 2 rank streams') > T7_BASE ))"
case_teardown

echo "#########################################"
echo "T8: geometry-lie -> engine_geometry_mismatch BEFORE any challenge"
echo "#########################################"
case_setup "geometry-lie" 1
got=$(wait_reason 'engine_geometry_mismatch' 60)
chk "T8 reason engine_geometry_mismatch" 'engine_geometry_mismatch' "$got"
chk "T8 holds at TOKEN_PARITY_VERIFIED" '^TOKEN_PARITY_VERIFIED$' \
    "$(jfield "$(kvstatus)" '.kvExactStatusAttr[0].enforcedState')"
case_teardown

echo "#########################################"
echo "T9: revision-lie -> identity_mismatch (manifest revision read-back)"
echo "#########################################"
case_setup "revision-lie" 1
got=$(wait_reason 'identity_mismatch' 60)
chk "T9 reason identity_mismatch" 'identity_mismatch' "$got"
chk "T9 holds at PROFILE_VALIDATED" '^PROFILE_VALIDATED$' \
    "$(jfield "$(kvstatus)" '.kvExactStatusAttr[0].enforcedState')"
case_teardown

echo "#########################################"
if [[ $code == 0 ]]; then
    echo "kv-sglang-attest: ALL CASES PASSED"
else
    echo "kv-sglang-attest: FAILURES (see [FAILED] lines above)"
fi
exit $code
