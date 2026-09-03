#!/bin/bash
# validation.sh — cfg-persist-negative: failure semantics of the
# persistence pipeline. Every leg stages a hostile condition and asserts
# the REFUSAL/quarantine behavior — never the happy path:
#
#   partial-doc  a document covering only one domain, committed with
#                default selection, must not wipe the domains it omits
#   unknown-field / wrong-schema  hostile documents are refused before
#                anything is planned or wiped (strict decode + gates)
#   truncated / corrupted snapshot.json  boot must quarantine the file
#                loudly (snapshot.json.failed-*) and never silently boot
#                empty on a file that could later be overwritten
#
# Recovery from each quarantine leg goes through the real operator path:
# a REST commit restore of the last good document.
source ../common.sh
source ../common/persist_lib.sh
echo SCENARIO-cfg-persist-negative

code=0
pass() { echo "  [OK] $1"; }
fail() { echo "  [FAILED] $1"; code=1; }

VIP=20.20.20.1
CFG=llb1_config

fw_count() {
    plib_curl llb1 "$PLIB_API/config/firewall/all" | jq '[.fwAttr[]?] | length'
}
session_count() {
    plib_curl llb1 "$PLIB_API/config/session/all" | jq '[.sessionAttr[]?] | length'
}
lb_count() {
    plib_curl llb1 "$PLIB_API/config/loadbalancer/all" | jq '[.lbAttr[]?] | length'
}
quarantine_count() {
    sudo sh -c "ls $CFG/snapshot.json.failed-* 2>/dev/null | wc -l"
}

#################################################################################
echo "=== baseline: persist + keep a known-good document ==="
#################################################################################
persist_and_verify llb1 || fail "baseline persist"
plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/good.json"
[[ $(sudo jq -r '.kind' "$PLIB_ARTIFACTS/good.json" 2>/dev/null) == "loxilb-snapshot" ]] \
    && pass "known-good document captured" || fail "good capture"

#################################################################################
echo "=== partial document must not wipe omitted domains ==="
#################################################################################
# Capture ONLY the loadbalancer domain, then commit it with default
# selection. Firewall and session state must survive untouched.
plib_curl llb1 "$PLIB_API/config/snapshot?components=loadbalancer" -o "$PLIB_ARTIFACTS/partial-lb.json"
inc=$(sudo jq -c '.included_domains' "$PLIB_ARTIFACTS/partial-lb.json")
[[ "$inc" == '["loadbalancer"]' ]] \
    && pass "partial capture declares its coverage ($inc)" \
    || fail "partial capture included_domains=$inc"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/partial-lb.json")
[[ "$rc" == "200" ]] && pass "partial commit restore -> 200" || fail "partial restore HTTP $rc"
[[ "$(fw_count)" == "1" ]] \
    && pass "firewall survived a restore that never covered it" \
    || fail "firewall wiped by a partial document (count=$(fw_count))"
[[ "$(session_count)" == "1" ]] \
    && pass "session survived a restore that never covered it" \
    || fail "session wiped by a partial document (count=$(session_count))"
[[ "$(lb_count)" == "1" ]] \
    && pass "covered domain applied" || fail "lb count=$(lb_count)"

# Explicitly requesting a domain the document does not cover must refuse.
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/partial-lb.json" "&components=firewall")
[[ "$rc" == "400" ]] \
    && pass "restore of an uncovered component refused (400)" \
    || fail "uncovered component restore -> HTTP $rc, want 400"

#################################################################################
echo "=== hostile documents refused before anything mutates ==="
#################################################################################
fw_before=$(fw_count)

sudo jq '. + {bogus_field_from_the_future: true}' "$PLIB_ARTIFACTS/good.json" > "$PLIB_ARTIFACTS/unknown-field.json"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/unknown-field.json")
[[ "$rc" == "400" ]] \
    && pass "unknown top-level field refused by strict decode (400)" \
    || fail "unknown-field document -> HTTP $rc, want 400"

sudo jq '.schema_version = "99.0"' "$PLIB_ARTIFACTS/good.json" > "$PLIB_ARTIFACTS/badschema.json"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/badschema.json")
[[ "$rc" == "400" ]] \
    && pass "wrong-schema document fails closed (400; version+checksum gates unit-pinned)" \
    || fail "schema-99 document -> HTTP $rc, want 400"

[[ "$(fw_count)" == "$fw_before" ]] \
    && pass "refused documents mutated nothing" \
    || fail "state changed after refused restores"

#################################################################################
echo "=== truncated snapshot.json quarantines at boot ==="
#################################################################################
persist_and_verify llb1 >/dev/null || fail "re-persist before truncation"
q0=$(quarantine_count)
sudo truncate -s 120 "$CFG/snapshot.json"
plib_start_gw llb1 || fail "gateway did not come back after truncated-snapshot boot"
plib_wait_api llb1 || fail "API after truncated-snapshot boot"
[[ "$(quarantine_count)" == "$((q0+1))" ]] \
    && pass "truncated snapshot quarantined (snapshot.json.failed-*)" \
    || fail "no quarantine artifact for the truncated snapshot"
docker exec llb1 grep -aq "boot snapshot: restore failed" /tmp/loxilb.out \
    && pass "boot failure logged loudly" || fail "no loud boot-failure log"
[[ "$(lb_count)" == "0" ]] \
    && pass "no partial/ghost config after quarantine (clean empty boot, loudly reported)" \
    || fail "unexpected config present after quarantined boot"

# Operator recovery path: commit the last good document.
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/good.json")
[[ "$rc" == "200" && "$(fw_count)" == "1" && "$(lb_count)" == "1" ]] \
    && pass "recovery via REST restore of the good document" \
    || fail "recovery restore failed (HTTP $rc fw=$(fw_count) lb=$(lb_count))"

#################################################################################
echo "=== corrupted (bit-flipped) snapshot.json quarantines at boot ==="
#################################################################################
persist_and_verify llb1 >/dev/null || fail "re-persist before corruption"
q0=$(quarantine_count)
# Flip one digit inside the embedded checksum (compact JSON, no spaces)
# -> the checksum gate fires at boot.
sudo perl -pi -e 's/"checksum":"sha256:./"checksum":"sha256:X/' "$CFG/snapshot.json"
sudo grep -q '"checksum":"sha256:X' "$CFG/snapshot.json" || fail "corruption injection did not take"
plib_start_gw llb1 || fail "gateway did not come back after corrupted-snapshot boot"
plib_wait_api llb1 || fail "API after corrupted-snapshot boot"
[[ "$(quarantine_count)" == "$((q0+1))" ]] \
    && pass "corrupted snapshot quarantined" \
    || fail "no quarantine artifact for the corrupted snapshot"
docker exec llb1 grep -aq "checksum" /tmp/loxilb.out \
    && pass "checksum mismatch reported" || fail "no checksum-mismatch report"

rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/good.json")
[[ "$rc" == "200" && "$(fw_count)" == "1" && "$(lb_count)" == "1" ]] \
    && pass "recovery via REST restore after corruption" \
    || fail "recovery restore failed (HTTP $rc)"

# The recovered state must actually serve.
resp=$($hexec l3h1 curl -s -m 5 "http://${VIP}:2020/" 2>/dev/null | head -3)
echo "$resp" | grep -q 'X-Echo-Backend' \
    && pass "recovered L4 VIP routes traffic" || fail "recovered VIP probe: $resp"

plib_collect_logs llb1
exit $code
