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

#################################################################################
echo "=== cert restore refuses divergent on-disk material (digest gate) ==="
#################################################################################
# The snapshot carries {cert_id, digest} only; a restore must verify the
# node's managed material against the digest BEFORE re-registering. A
# gateway must never come up silently serving different TLS material than
# its desired state declares.
plib_curl llb1 "$PLIB_API/config/snapshot?components=cert" -o "$PLIB_ARTIFACTS/cert-only.json"
[[ $(jq -r '.domains.cert[0].cert_id' < "$PLIB_ARTIFACTS/cert-only.json") == "ng-cert1" ]] \
    && pass "cert-only partial document captured" || fail "cert-only capture"

# Drift the material (APPEND keeps the PEM parseable: the leg targets the
# digest gate, not the PEM parser).
sudo sh -c "printf '# drift\n' >> $CFG/certs/ng-cert1/server.crt"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/cert-only.json")
res=$(jq -r '.result' < "$PLIB_ARTIFACTS/restore-response.json")
errs=$(jq -r '(.errors // []) | join(" ")' < "$PLIB_ARTIFACTS/restore-response.json")
if [[ "$rc" == "500" && "$res" == "rolled_back" && "$errs" == *"diverges from the captured digest"* ]]; then
    pass "divergent material refused at apply (500, rolled back, loud digest error)"
else
    fail "divergent-material restore: HTTP $rc result=$res errors=$errs"
fi

# Repair with the ORIGINAL bytes -> same digest as the document -> the
# same restore must now succeed.
sudo cp "${PLIB_ARTIFACTS}/../.certs-stage/ng.crt" "$CFG/certs/ng-cert1/server.crt"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/cert-only.json")
[[ "$rc" == "200" ]] \
    && pass "restore succeeds once the material matches the digest again" \
    || fail "post-repair restore HTTP $rc"

#################################################################################
echo "=== cross-node cert restore fails loudly on missing material ==="
#################################################################################
# API DELETE is the operation that removes managed material; afterwards
# this node looks exactly like a DIFFERENT node receiving the document:
# the material must be re-provisioned, never invented from the snapshot.
rc=$(plib_curl llb1 -o /dev/null -w "%{http_code}" -X DELETE "$PLIB_API/config/cert/ng-cert1")
[[ "$rc" == "204" ]] && pass "API delete removed the cert" || fail "cert delete HTTP $rc"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/cert-only.json")
res=$(jq -r '.result' < "$PLIB_ARTIFACTS/restore-response.json")
errs=$(jq -r '(.errors // []) | join(" ")' < "$PLIB_ARTIFACTS/restore-response.json")
if [[ "$rc" == "500" && "$errs" == *"managed material missing"* && "$errs" == *"re-provision"* ]]; then
    pass "missing-material restore fails loudly (500, re-provision guidance)"
else
    fail "missing-material restore: HTTP $rc result=$res errors=$errs"
fi

# Operator re-provisions the SAME material -> digest matches -> restore ok.
CERT_BODY=$(jq -n --arg id "ng-cert1" \
    --rawfile crt "${PLIB_ARTIFACTS}/../.certs-stage/ng.crt" \
    --rawfile key "${PLIB_ARTIFACTS}/../.certs-stage/ng.key" \
    '{certId: $id, certPem: $crt, keyPem: $key}')
rc=$(plib_curl llb1 -o "$PLIB_ARTIFACTS/cert-reprovision.json" -w "%{http_code}" \
    -X POST "$PLIB_API/config/cert" -H 'Content-Type: application/json' -d "$CERT_BODY")
[[ "$rc" == "201" ]] && pass "material re-provisioned via the API" || fail "re-provision HTTP $rc"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/cert-only.json")
[[ "$rc" == "200" ]] \
    && pass "restore succeeds after re-provisioning (digest re-verified)" \
    || fail "post-reprovision restore HTTP $rc"

#################################################################################
echo "=== duplicate L7 policy id is a 409 conflict ==="
#################################################################################
# (Runs last: it adds an LB, which would disturb the count-based asserts
# above.) Same id with different content and a second policy on an LB
# that already carries one must both refuse with 409 -- restore-order
# winners must never be decided by silent overwrite.
rc=$($hexec llb1 curl -s -m 10 -o /tmp/cfgn-post.json -w "%{http_code}" \
    -X POST "$PLIB_API/config/loadbalancer" -H 'Content-Type: application/json' -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 8090, "protocol": "tcp",
    "sel": 0, "mode": 4, "name": "ng-l7", "host": "10.10.10.254"
  },
  "endpoints": [ { "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1 } ]
}')
[[ "$rc" == "200" || "$rc" == "204" ]] && pass "proxy LB for the policy legs" || fail "ng-l7 LB HTTP $rc"
NG_LBID=$(plib_curl llb1 "$PLIB_API/config/loadbalancer/all" \
    | jq -r '.lbAttr[] | select(.serviceArguments.name=="ng-l7") | .serviceArguments.id')
[[ -n "$NG_LBID" && "$NG_LBID" != "null" ]] || fail "could not resolve ng-l7 stable id"

pol_post() { # pol_post <id> <path> <status> — echoes http code
    plib_curl llb1 -o "$PLIB_ARTIFACTS/l7pol-post.json" -w "%{http_code}" \
        -X POST "$PLIB_API/config/l7policy" -H 'Content-Type: application/json' -d "{
  \"id\": \"$1\", \"lbId\": \"${NG_LBID}\",
  \"rules\": [ { \"position\": 1,
    \"matchSets\": [ { \"conditions\": [
      { \"field\": \"PATH\", \"op\": \"STARTS_WITH\", \"value\": \"$2\" } ] } ],
    \"action\": { \"kind\": \"REJECT\", \"reject\": { \"statusCode\": $3 } } } ]
}"
}
rc=$(pol_post ng-pol1 /x 403)
[[ "$rc" == "204" ]] && pass "first policy accepted" || fail "first policy HTTP $rc"
rc=$(pol_post ng-pol1 /y 451)
[[ "$rc" == "409" ]] \
    && pass "same id, different content -> 409 (no silent overwrite)" \
    || fail "conflicting duplicate id HTTP $rc, want 409"
rc=$(pol_post ng-pol2 /z 403)
[[ "$rc" == "409" ]] \
    && pass "second policy on an occupied LB -> 409 (one policy per LB)" \
    || fail "second policy on occupied LB HTTP $rc, want 409"

plib_collect_logs llb1
exit $code
