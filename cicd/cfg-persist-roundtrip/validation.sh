#!/bin/bash
# validation.sh — cfg-persist-roundtrip: the persisted configuration must
# survive an in-place gateway restart FIELD-identically.
#
# Oracle discipline (see cicd/common/persist_lib.sh): every domain is
# dumped via its GET API before and after the restart, jq-canonicalized
# with explicit volatile-field stripping, and deep-diffed — a probe re-run
# is a supplementary datapath check, never the primary verdict. Restart
# probes wait for the boot replay receipt (retrying boot restores roll
# config back between attempts; early probes give phantom verdicts).
source ../common.sh
source ../common/persist_lib.sh
echo SCENARIO-cfg-persist-roundtrip

code=0
pass() { echo "  [OK] $1"; }
fail() { echo "  [FAILED] $1"; code=1; }

VIP=20.20.20.1
PVIP=10.10.10.254
BODY='{"model":"test-model","prompt":"hi","max_tokens":4}'

#################################################################################
echo "=== persist: response contract + on-disk file ==="
#################################################################################
if persist_and_verify llb1; then
    pass "persist: 200 + result ok + sha256 checksum matches on-disk snapshot.json"
else
    fail "persist contract"
fi
sum1=$(jq -r '.checksum' < "$PLIB_ARTIFACTS/persist-response.json")

#################################################################################
echo "=== persist: idle re-persist is checksum-stable (no counter churn) ==="
#################################################################################
# Persisted state carries desired config only — a second persist with no
# config change in between must produce the identical document (modulo the
# capture timestamp, which participates in the checksum; so compare the
# domains payload, not the raw checksum).
plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/snap-idle-1.json"
sleep 2
plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/snap-idle-2.json"
d1=$(jq -S '.domains' < "$PLIB_ARTIFACTS/snap-idle-1.json" | sha256sum | cut -d' ' -f1)
d2=$(jq -S '.domains' < "$PLIB_ARTIFACTS/snap-idle-2.json" | sha256sum | cut -d' ' -f1)
if [[ -n "$d1" && "$d1" == "$d2" ]]; then
    pass "idle captures are domain-payload identical (no runtime-counter churn)"
else
    fail "idle captures differ ($d1 vs $d2) — runtime state is leaking into the document"
fi

#################################################################################
echo "=== kvexactbinding: captured + visible to restore planning ==="
#################################################################################
nbind=$(jq -r '.domains.kvexactbinding | length' < "$PLIB_ARTIFACTS/snap-idle-1.json")
if [[ "$nbind" == "1" ]]; then
    pass "snapshot carries the KV binding (kvexactbinding=1)"
else
    fail "snapshot kvexactbinding count=$nbind, want 1"
fi
prof=$(jq -r '.domains.kvexactbinding[0].modelProfileId' < "$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$prof" == "qwen3-06b-completions-v1" ]] \
    && pass "binding carries the profile identity" \
    || fail "binding profile=$prof"

# Restore dry-run of the captured document must PLAN the binding domain
# (this was the invisible-domain hole: to_apply used to be 0).
rc=$(plib_curl llb1 -o "$PLIB_ARTIFACTS/dryrun-response.json" -w "%{http_code}" \
    -X POST "$PLIB_API/config/restore?mode=dry-run" \
    -H 'Content-Type: application/json' --data-binary @"$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$rc" == "200" ]] && pass "dry-run restore of own capture -> 200" || fail "dry-run -> HTTP $rc"
toapply=$(jq -r '.plan[]? | select(.domain=="kvexactbinding") | .to_apply' < "$PLIB_ARTIFACTS/dryrun-response.json")
[[ "$toapply" == "1" ]] \
    && pass "restore PLAN sees the binding (to_apply=1)" \
    || fail "restore PLAN kvexactbinding to_apply=$toapply, want 1"

#################################################################################
echo "=== canonical capture BEFORE restart ==="
#################################################################################
if canonical_get_all llb1 "$PLIB_ARTIFACTS/before"; then
    pass "canonical GET dump (before)"
else
    fail "canonical GET dump (before)"
fi

# Datapath baselines (must hold both before AND after the restart).
resp=$($hexec l3h1 curl -s -m 5 "http://${VIP}:2020/" 2>/dev/null | head -3)
echo "$resp" | grep -q 'X-Echo-Backend' \
    && pass "L4 VIP routes to an echo backend (before)" \
    || fail "L4 VIP probe (before): $resp"
# No key store runs in this topology, so the auth plane fails CLOSED on
# the missing store (503) rather than 401 -- either way, a keyless
# request must be REFUSED, and the refusal class must survive restart.
rc_before=$($hexec l3h1 curl -s -m 5 -o /dev/null -w "%{http_code}" -X POST \
    "http://${PVIP}:8080/v1/completions" -H 'Content-Type: application/json' -d "$BODY" 2>/dev/null)
[[ "$rc_before" == "401" || "$rc_before" == "503" ]] \
    && pass "api-key-required VIP refuses keyless request (before, $rc_before)" \
    || fail "api-key probe (before) HTTP $rc_before, want a 401/503 refusal"

#################################################################################
echo "=== persist + in-place restart (replay receipt polled) ==="
#################################################################################
persist_and_verify llb1 >/dev/null || fail "pre-restart persist"

# RED-TWIN hook (inert unless PLIB_RED_MUTATE=1): mutate the live config
# AFTER the canonical before-capture and re-persist, so the restart comes
# back different from the captured baseline -- the deep-diff oracle MUST
# fail. Run deliberately (never in a green gate) to prove the oracle can
# fire; a harness whose asserts cannot go red proves nothing.
if [[ "$PLIB_RED_MUTATE" == "1" ]]; then
    echo "  RED-TWIN: deleting the firewall rule + re-persisting after the baseline capture"
    plib_curl llb1 -o /dev/null -X DELETE \
        "$PLIB_API/config/firewall?sourceIP=77.77.77.7%2F32&destinationIP=20.20.20.1%2F32"
    persist_and_verify llb1 >/dev/null
fi
if restart_inplace_keep llb1 -b; then
    pass "in-place restart + boot replay receipt"
else
    fail "in-place restart / replay receipt"
fi
plib_wait_api llb1 || fail "API after restart"

#################################################################################
echo "=== canonical deep-diff AFTER restart ==="
#################################################################################
canonical_get_all llb1 "$PLIB_ARTIFACTS/after" || fail "canonical GET dump (after)"
if deep_diff "$PLIB_ARTIFACTS/before" "$PLIB_ARTIFACTS/after" restart; then
    pass "every domain deep-equal across restart (field-level, canonicalized)"
else
    fail "domain content drifted across restart (diff artifacts kept)"
fi

#################################################################################
echo "=== BGP neighbor transport survived (non-default port + multihop) ==="
#################################################################################
neigh=$(plib_curl llb1 "$PLIB_API/config/bgp/neigh/all" | jq -r '.bgpNeiAttr[]? | select(.ipAddress=="10.10.10.1")')
rp=$(echo "$neigh" | jq -r '.remotePort')
mh=$(echo "$neigh" | jq -r '.multiHop')
[[ "$rp" == "1790" ]] \
    && pass "neighbor remotePort survived restart (1790)" \
    || fail "neighbor remotePort=$rp after restart, want 1790"
[[ "$mh" == "true" ]] \
    && pass "neighbor multihop survived restart" \
    || fail "neighbor multiHop=$mh after restart, want true"
# Second oracle: the running BGP speaker itself, not just the config echo
# (gobgpd serves its API on the non-default port 50052 here; the JSON view
# carries the transport config the text view omits).
gb=$(docker exec llb1 gobgp -p 50052 -j neighbor 10.10.10.1 2>/dev/null)
srp=$(echo "$gb" | jq -r '.transport.remote_port')
smh=$(echo "$gb" | jq -r '.ebgp_multihop.enabled')
[[ "$srp" == "1790" && "$smh" == "true" ]] \
    && pass "gobgp speaker confirms port 1790 + multihop on the wire config" \
    || fail "gobgp speaker transport: remote_port=$srp multihop=$smh, want 1790/true"

#################################################################################
echo "=== datapath probes AFTER restart ==="
#################################################################################
resp=$($hexec l3h1 curl -s -m 5 "http://${VIP}:2020/" 2>/dev/null | head -3)
echo "$resp" | grep -q 'X-Echo-Backend' \
    && pass "L4 VIP still routes after restart" \
    || fail "L4 VIP probe (after): $resp"
rc_after=$($hexec l3h1 curl -s -m 5 -o /dev/null -w "%{http_code}" -X POST \
    "http://${PVIP}:8080/v1/completions" -H 'Content-Type: application/json' -d "$BODY" 2>/dev/null)
if [[ ( "$rc_after" == "401" || "$rc_after" == "503" ) && "$rc_after" == "$rc_before" ]]; then
    pass "api-key enforcement still refuses keyless requests after restart ($rc_after, same class as before)"
else
    fail "api-key probe (after) HTTP $rc_after (before was $rc_before), want the same 401/503 refusal"
fi

#################################################################################
echo "=== kvexactbinding survived the restart ==="
#################################################################################
plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/snap-after.json"
nbind=$(jq -r '.domains.kvexactbinding | length' < "$PLIB_ARTIFACTS/snap-after.json")
[[ "$nbind" == "1" ]] \
    && pass "KV binding present after restart" \
    || fail "KV binding count=$nbind after restart, want 1"
gen_b=$(jq -S '.domains.kvexactbinding[0]' < "$PLIB_ARTIFACTS/snap-idle-1.json")
gen_a=$(jq -S '.domains.kvexactbinding[0]' < "$PLIB_ARTIFACTS/snap-after.json")
[[ -n "$gen_b" && "$gen_b" == "$gen_a" ]] \
    && pass "binding identity + generations field-identical across restart" \
    || fail "binding drifted across restart"

plib_collect_logs llb1
exit $code
