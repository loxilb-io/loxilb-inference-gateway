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
    # ls -d: a quarantined artifact can be a DIRECTORY (the read-failure
    # leg plants one), and a bare ls would list its contents (zero lines
    # for an empty dir) instead of the entry itself.
    sudo sh -c "ls -d $CFG/snapshot.json.failed-* 2>/dev/null | wc -l"
}

#################################################################################
echo "=== baseline: persist + keep a known-good document ==="
#################################################################################
persist_and_verify llb1 || fail "baseline persist"
plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/good.json"
[[ $(sudo jq -r '.kind' "$PLIB_ARTIFACTS/good.json" 2>/dev/null) == "loxilb-snapshot" ]] \
    && pass "known-good document captured" || fail "good capture"
# Readiness baseline: a healthy gateway answers 200 ready=true and the
# status surface reports the persist we just made (generation+checksum).
rrc=$(plib_curl llb1 -o "$PLIB_ARTIFACTS/ready-baseline.json" -w "%{http_code}" "$PLIB_API/status/ready")
rready=$(jq -r '.ready' < "$PLIB_ARTIFACTS/ready-baseline.json")
rpgen=$(jq -r '.last_persist.generation // 0' < "$PLIB_ARTIFACTS/ready-baseline.json")
[[ "$rrc" == "200" && "$rready" == "true" && "$rpgen" -ge 1 ]] \
    && pass "healthy gateway is READY and reports its last persist (gen $rpgen)" \
    || fail "baseline readiness: HTTP $rrc ready=$rready last_persist.gen=$rpgen"

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
if [[ "$rc" == "500" && "$res" == "rolled-back" && "$errs" == *"diverges from the captured digest"* ]]; then
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

restore_dryrun() { # restore_dryrun <docfile> — echoes http code, body in artifacts
    plib_curl llb1 -o "$PLIB_ARTIFACTS/restore-response.json" -w "%{http_code}" \
        -X POST "$PLIB_API/config/restore?mode=dry-run" \
        -H 'Content-Type: application/json' --data-binary @"$1"
}

#################################################################################
echo "=== doc requiring the api-key store refuses on a store-less node ==="
#################################################################################
# recovery_dependencies (schema 1.4): a document captured on a node with
# the data-plane API-key store wired declares it REQUIRED; restoring that
# document onto a node without the store must refuse BEFORE anything is
# planned or wiped, naming the dependency. The store here is unreachable
# ON PURPOSE: both DB stores dial in the background and the dependency
# contract is deliberately configured-check, not reachability, so a store
# outage can never hold a restore (or boot replay) hostage.
persist_and_verify llb1 >/dev/null || fail "persist before the dependency legs"
if restart_inplace_keep llb1 --aikey-db-host 127.0.0.1 --aikey-db-name ngdepdb; then
    pass "restart with the API-key store wired (degraded dial is by design)"
else
    fail "restart with the API-key store wired"
fi
plib_wait_api llb1 || fail "API after wired restart"
plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/dep-akdb.json"
ak=$(jq -r '.recovery_dependencies[]? | select(.type=="api-key-db") | "\(.id) \(.required)"' \
    < "$PLIB_ARTIFACTS/dep-akdb.json")
[[ "$ak" == "ngdepdb true" ]] \
    && pass "wired store declared REQUIRED in the captured manifest" \
    || fail "api-key-db manifest entry '$ak', want 'ngdepdb true'"
rc=$(restore_dryrun "$PLIB_ARTIFACTS/dep-akdb.json")
[[ "$rc" == "200" ]] \
    && pass "dry-run passes while the store is wired (refusals below are dep-driven)" \
    || fail "wired dry-run HTTP $rc, want 200"
restart_inplace_keep llb1 || fail "restart back to the store-less shape"
plib_wait_api llb1 || fail "API after store-less restart"
fw0=$(fw_count); lb0=$(lb_count); q0=$(quarantine_count)
rc=$(restore_dryrun "$PLIB_ARTIFACTS/dep-akdb.json")
errs=$(jq -r '(.errors // []) | join(" ")' < "$PLIB_ARTIFACTS/restore-response.json")
[[ "$rc" == "400" && "$errs" == *"dependency api-key-db"* && "$errs" == *"none is configured"* ]] \
    && pass "dry-run preflights the missing store (400, names the dependency)" \
    || fail "store-less dry-run: HTTP $rc errors=$errs"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/dep-akdb.json")
res=$(jq -r '.result' < "$PLIB_ARTIFACTS/restore-response.json")
errs=$(jq -r '(.errors // []) | join(" ")' < "$PLIB_ARTIFACTS/restore-response.json")
if [[ "$rc" == "400" && "$errs" == *"dependency api-key-db"* && "$res" != "rolled-back" ]]; then
    pass "commit refused pre-wipe (400 -- no rollback happened, nothing was touched)"
else
    fail "store-less commit: HTTP $rc result=$res errors=$errs"
fi
[[ "$(fw_count)" == "$fw0" && "$(lb_count)" == "$lb0" ]] \
    && pass "refusal mutated nothing (fw/lb counts unchanged)" \
    || fail "state changed across a dependency refusal (fw=$(fw_count)/$fw0 lb=$(lb_count)/$lb0)"
[[ "$(quarantine_count)" == "$q0" ]] \
    && pass "REST refusal does not quarantine the on-disk snapshot" \
    || fail "REST dependency refusal quarantined snapshot.json"

#################################################################################
echo "=== KV-bound document onto a profile-less host fails closed ==="
#################################################################################
# Publish a trusted profile registry (under the host-mounted /etc/loxilb),
# restart so the boot load picks it up, and bind a KV-exact rule against
# it: the captured binding is what makes the contract + profile registries
# REQUIRED in the manifest. Stripping the registry and restoring the same
# document must then refuse up front -- KV rules without their profiles
# would route on unverifiable identities.
TOK_SRC="../common/kv_hash/fixtures/tokenizers/Qwen__Qwen3-0.6B/tokenizer.json"
KVSTAGE="$CFG/kvprofiles"
[[ -f "$TOK_SRC" ]] || fail "tokenizer fixture missing: $TOK_SRC"
TOK_SHA=$(sha256sum "$TOK_SRC" | cut -d' ' -f1)
sudo mkdir -p "$KVSTAGE/artifacts/sha256"
sudo cp "$TOK_SRC" "$KVSTAGE/artifacts/sha256/${TOK_SHA}"
sudo tee "$KVSTAGE/ng-kv-completions-v1.yaml" >/dev/null <<EOF
profileId: ng-kv-completions-v1
baseModel: Qwen/Qwen3-0.6B
tokenizerArtifact: sha256/${TOK_SHA}
tokenizerSha256: ${TOK_SHA}
supportedApis:
  - completions
aliasPolicy: base_model_only
EOF
sudo chmod 0755 "$KVSTAGE" "$KVSTAGE/artifacts" "$KVSTAGE/artifacts/sha256"
sudo chmod 0644 "$KVSTAGE"/*.yaml "$KVSTAGE/artifacts/sha256/"*
restart_inplace_keep llb1 || fail "restart with the profile registry provisioned"
plib_wait_api llb1 || fail "API after profiled restart"
rc=$(plib_curl llb1 -o "$PLIB_ARTIFACTS/kv-lb-post.json" -w "%{http_code}" \
    -X POST "$PLIB_API/config/loadbalancer" -H 'Content-Type: application/json' -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 8091, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "10.10.10.254",
    "pd_disagg_mode": true, "probeRetries": 1,
    "kvExactMode": 1, "kvZmqPort": 5558, "kvBlockSize": 16,
    "kvEngineType": "vllm", "model_name": "Qwen/Qwen3-0.6B",
    "kvExactApiMode": "completions", "kvModelProfile": "ng-kv-completions-v1"
  },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1, "ep_role": 1 },
    { "endpointIP": "31.31.31.1", "targetPort": 81, "weight": 1, "ep_role": 2 }
  ]
}')
[[ "$rc" == "200" || "$rc" == "204" ]] \
    && pass "KV-exact rule bound against the published profile" \
    || fail "KV-exact rule HTTP $rc ($(cat "$PLIB_ARTIFACTS/kv-lb-post.json" 2>/dev/null))"
plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/dep-kv.json"
nb=$(jq -r '.domains.kvexactbinding | length' < "$PLIB_ARTIFACTS/dep-kv.json")
[[ "$nb" == "1" ]] \
    && pass "captured document carries the KV binding" \
    || fail "captured kvexactbinding count=$nb, want 1"
kvreq=$(jq -r '.recovery_dependencies[]? | select(.type=="kv-model-profiles") | .required' \
    < "$PLIB_ARTIFACTS/dep-kv.json")
ecreq=$(jq -r '.recovery_dependencies[]? | select(.type=="engine-contracts") | .required' \
    < "$PLIB_ARTIFACTS/dep-kv.json")
[[ "$kvreq" == "true" && "$ecreq" == "true" ]] \
    && pass "captured binding makes both registries REQUIRED" \
    || fail "manifest required flags: kv-model-profiles=$kvreq engine-contracts=$ecreq"
rc=$(restore_dryrun "$PLIB_ARTIFACTS/dep-kv.json")
[[ "$rc" == "200" ]] \
    && pass "dry-run passes while the registry is published (green counterpart)" \
    || fail "profiled dry-run HTTP $rc, want 200"
# Strip the registry; the restart replays the persisted document (which
# never carried the KV rule), leaving a genuinely profile-less node.
sudo rm -rf "$KVSTAGE"
restart_inplace_keep llb1 || fail "restart back to the profile-less shape"
plib_wait_api llb1 || fail "API after profile-less restart"
fw0=$(fw_count); lb0=$(lb_count); q0=$(quarantine_count)
rc=$(restore_dryrun "$PLIB_ARTIFACTS/dep-kv.json")
errs=$(jq -r '(.errors // []) | join(" ")' < "$PLIB_ARTIFACTS/restore-response.json")
[[ "$rc" == "400" && "$errs" == *"dependency kv-model-profiles"* \
   && "$errs" == *"no model-profile registry generation is published"* ]] \
    && pass "dry-run preflights the missing registry (400, names the dependency)" \
    || fail "profile-less dry-run: HTTP $rc errors=$errs"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/dep-kv.json")
res=$(jq -r '.result' < "$PLIB_ARTIFACTS/restore-response.json")
errs=$(jq -r '(.errors // []) | join(" ")' < "$PLIB_ARTIFACTS/restore-response.json")
if [[ "$rc" == "400" && "$errs" == *"dependency kv-model-profiles"* && "$res" != "rolled-back" ]]; then
    pass "KV-bound commit refused pre-wipe on the profile-less host"
else
    fail "profile-less commit: HTTP $rc result=$res errors=$errs"
fi
[[ "$(fw_count)" == "$fw0" && "$(lb_count)" == "$lb0" && "$(quarantine_count)" == "$q0" ]] \
    && pass "refusal mutated nothing and quarantined nothing" \
    || fail "state changed across the KV dependency refusal"

#################################################################################
echo "=== boot replay quarantines on a missing required dependency ==="
#################################################################################
# The same KV-bound document planted as snapshot.json: dependency failures
# are NOT startup-class, so the boot replay must quarantine immediately --
# never retry-loop against a store that is not coming, and never half-apply.
q0=$(quarantine_count)
sudo cp "$PLIB_ARTIFACTS/dep-kv.json" "$CFG/snapshot.json"
plib_start_gw llb1 || fail "gateway did not come back after dep-failing boot"
plib_wait_api llb1 || fail "API after dep-failing boot"
[[ "$(quarantine_count)" == "$((q0+1))" ]] \
    && pass "dep-failing snapshot quarantined at boot (fail closed)" \
    || fail "no quarantine artifact for the dep-failing snapshot"
docker exec llb1 grep -aq "boot snapshot: restore failed" /tmp/loxilb.out \
    && pass "boot failure logged loudly" || fail "no loud boot-failure log"
docker exec llb1 grep -aq "dependency kv-model-profiles" /tmp/loxilb.out \
    && pass "boot log names the missing dependency" \
    || fail "dependency not named in the boot log"
[[ "$(lb_count)" == "0" ]] \
    && pass "clean empty boot after dep quarantine (no half-applied config)" \
    || fail "unexpected config present after dep-quarantined boot"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/good.json")
[[ "$rc" == "200" && "$(fw_count)" == "1" && "$(lb_count)" == "1" ]] \
    && pass "recovery via REST restore of the good document" \
    || fail "recovery restore failed (HTTP $rc fw=$(fw_count) lb=$(lb_count))"
resp=$($hexec l3h1 curl -s -m 5 "http://${VIP}:2020/" 2>/dev/null | head -3)
echo "$resp" | grep -q 'X-Echo-Backend' \
    && pass "recovered L4 VIP routes traffic" || fail "recovered VIP probe: $resp"

#################################################################################
echo "=== boot quarantines an UNREADABLE snapshot.json (read-failure branch) ==="
#################################################################################
# A directory planted where the snapshot file belongs makes os.ReadFile
# fail with a real I/O error (EISDIR) -- the read-failure branch, distinct
# from the parse/pipeline failures above. It must quarantine like every
# other boot failure: left in place, the next persist would overwrite the
# only forensic copy of whatever is wrong on disk.
q0=$(quarantine_count)
sudo rm -rf "$CFG/snapshot.json"
sudo mkdir "$CFG/snapshot.json"
plib_start_gw llb1 || fail "gateway did not come back after unreadable-snapshot boot"
plib_wait_api llb1 || fail "API after unreadable-snapshot boot"
[[ "$(quarantine_count)" == "$((q0+1))" ]] \
    && pass "unreadable snapshot quarantined at boot (read-failure branch)" \
    || fail "no quarantine artifact for the unreadable snapshot"
docker exec llb1 grep -aq "boot snapshot: read" /tmp/loxilb.out \
    && pass "read failure logged loudly" || fail "no read-failure log line"
[[ "$(lb_count)" == "0" ]] \
    && pass "clean empty boot after the read-failure quarantine" \
    || fail "unexpected config after read-failure boot"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/good.json")
[[ "$rc" == "200" && "$(lb_count)" == "1" ]] \
    && pass "recovery via REST restore after the read-failure quarantine" \
    || fail "recovery restore failed (HTTP $rc lb=$(lb_count))"

#################################################################################
echo "=== compat boot profile: legacy fallback runs and is loudly degraded ==="
#################################################################################
# A failing snapshot AND a legacy lbconfig.txt both present, snapshot
# newer (arbitration picks it). The default compat profile must
# quarantine the snapshot, then fall back to the *.txt replay -- and say
# so loudly, because the replayed config may be older than what the
# quarantined snapshot carried.
cat > "$PLIB_ARTIFACTS/legacy-lb.txt" <<'EOF'
{
  "lbAttr": [
    {
      "serviceArguments": {
        "externalIP": "20.20.20.1", "port": 2021, "protocol": "tcp",
        "sel": 0, "mode": 0, "BGP": false, "Monitor": false,
        "inactiveTimeOut": 240, "block": 0
      },
      "secondaryIPs": null,
      "endpoints": [
        { "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1, "state": "active", "counter": "" }
      ]
    }
  ]
}
EOF
q0=$(quarantine_count)
sudo cp "$PLIB_ARTIFACTS/legacy-lb.txt" "$CFG/lbconfig.txt"
sudo touch -t 202601010000 "$CFG/lbconfig.txt"
sudo cp "$PLIB_ARTIFACTS/dep-kv.json" "$CFG/snapshot.json"
plib_start_gw llb1 || fail "gateway did not come back on the compat-fallback boot"
plib_wait_api llb1 || fail "API after compat-fallback boot"
[[ "$(quarantine_count)" == "$((q0+1))" ]] \
    && pass "failing snapshot quarantined before the compat fallback" \
    || fail "no quarantine artifact on the compat-fallback boot"
docker exec llb1 grep -aq "compat profile: falling back" /tmp/loxilb.out \
    && pass "compat fallback logged as degraded" || fail "no compat-fallback log line"
lb_legacy=$(plib_curl llb1 "$PLIB_API/config/loadbalancer/all" | jq '[.lbAttr[]? | select(.serviceArguments.port==2021)] | length')
[[ "$lb_legacy" == "1" && "$(lb_count)" == "1" ]] \
    && pass "legacy *.txt replay ran under compat (the port-2021 rule is live)" \
    || fail "compat fallback state: lb=$(lb_count) legacy-rule=$lb_legacy"

#################################################################################
echo "=== strict boot profile: NO legacy fallback after a failed restore ==="
#################################################################################
# Same double-artifact setup, booted with --config-boot-profile strict:
# replaying stale *.txt artifacts over a failed restore would run the
# gateway on older configuration while looking alive, so strict must boot
# EMPTY (quarantine + loud log), leaving recovery to the operator.
q0=$(quarantine_count)
sudo cp "$PLIB_ARTIFACTS/legacy-lb.txt" "$CFG/lbconfig.txt"
sudo touch -t 202601010000 "$CFG/lbconfig.txt"
sudo cp "$PLIB_ARTIFACTS/dep-kv.json" "$CFG/snapshot.json"
plib_start_gw llb1 --config-boot-profile strict || fail "gateway did not come back on the strict boot"
plib_wait_api llb1 || fail "API after strict boot"
[[ "$(quarantine_count)" == "$((q0+1))" ]] \
    && pass "failing snapshot quarantined under strict" \
    || fail "no quarantine artifact on the strict boot"
docker exec llb1 grep -aq "strict profile: snapshot restore failed; legacy fallback disabled" /tmp/loxilb.out \
    && pass "strict profile logged the disabled fallback" || fail "no strict-profile log line"
[[ "$(lb_count)" == "0" ]] \
    && pass "strict boot is EMPTY: the legacy lbconfig.txt was NOT replayed" \
    || fail "strict boot applied config anyway (lb=$(lb_count))"
# No silent READY: the degraded strict boot must answer 503 ready=false
# with the boot record naming the degradation.
rrc=$(plib_curl llb1 -o "$PLIB_ARTIFACTS/ready-degraded.json" -w "%{http_code}" "$PLIB_API/status/ready")
rready=$(jq -r '.ready' < "$PLIB_ARTIFACTS/ready-degraded.json")
rdeg=$(jq -r '.boot.degraded' < "$PLIB_ARTIFACTS/ready-degraded.json")
rwhy=$(jq -r '(.reasons // []) | join(" ")' < "$PLIB_ARTIFACTS/ready-degraded.json")
[[ "$rrc" == "503" && "$rready" == "false" && "$rdeg" == "true" && "$rwhy" == *"restore failed"* ]] \
    && pass "degraded strict boot is NOT ready (503, reason names the failed restore)" \
    || fail "degraded readiness: HTTP $rrc ready=$rready degraded=$rdeg reasons=$rwhy"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/good.json")
[[ "$rc" == "200" && "$(lb_count)" == "1" ]] \
    && pass "operator recovery via REST restore works under strict" \
    || fail "strict recovery restore failed (HTTP $rc lb=$(lb_count))"
# The commit restore is the designed exit from degraded: READY flips back.
rrc=$(plib_curl llb1 -o "$PLIB_ARTIFACTS/ready-recovered.json" -w "%{http_code}" "$PLIB_API/status/ready")
rready=$(jq -r '.ready' < "$PLIB_ARTIFACTS/ready-recovered.json")
rmode=$(jq -r '.last_restore.mode // ""' < "$PLIB_ARTIFACTS/ready-recovered.json")
[[ "$rrc" == "200" && "$rready" == "true" && "$rmode" == "commit" ]] \
    && pass "commit-restore recovery flips READY back on (last_restore mode commit)" \
    || fail "post-recovery readiness: HTTP $rrc ready=$rready last_restore.mode=$rmode"
resp=$($hexec l3h1 curl -s -m 5 "http://${VIP}:2020/" 2>/dev/null | head -3)
echo "$resp" | grep -q 'X-Echo-Backend' \
    && pass "recovered VIP routes traffic after the strict-boot recovery" \
    || fail "post-strict recovery VIP probe: $resp"
# Drop the planted legacy artifact so later boots arbitrate on the
# snapshot alone (the write-through above re-persisted the good state).
sudo rm -f "$CFG/lbconfig.txt"

#################################################################################
echo "=== boot arbitration: a persisted lineage outranks a NEWER legacy mtime ==="
#################################################################################
# snapshot.json now carries a lineage generation (the recovery commit's
# write-through). A hand-dropped lbconfig.txt with a FRESHER mtime (cp
# without -p, clock skew) must NOT flip the boot source any more: the
# lineage wins, mtimes only arbitrate for pre-generation snapshots.
fgen=$(sudo cat "$CFG/snapshot.json" | jq -r '.generation // 0')
[[ "$fgen" -ge 1 ]] || fail "expected a lineage generation on snapshot.json, got $fgen"
sudo cp "$PLIB_ARTIFACTS/legacy-lb.txt" "$CFG/lbconfig.txt"   # fresh mtime, NEWER than the snapshot
plib_start_gw llb1 || fail "gateway did not come back on the arbitration boot"
plib_wait_api llb1 || fail "API after arbitration boot"
wait_replay_receipt llb1
docker exec llb1 grep -aq "persisted lineage wins" /tmp/loxilb.out \
    && pass "arbitration log names the lineage authority" \
    || fail "no lineage-wins log line"
lb2020=$(plib_curl llb1 "$PLIB_API/config/loadbalancer/all" | jq '[.lbAttr[]? | select(.serviceArguments.port==2020)] | length')
lb2021=$(plib_curl llb1 "$PLIB_API/config/loadbalancer/all" | jq '[.lbAttr[]? | select(.serviceArguments.port==2021)] | length')
[[ "$lb2020" == "1" && "$lb2021" == "0" ]] \
    && pass "boot restored the snapshot lineage, not the fresher legacy txt" \
    || fail "arbitration state: port-2020=$lb2020 port-2021=$lb2021"
sudo rm -f "$CFG/lbconfig.txt"

#################################################################################
echo "=== node-secret loss: encrypted document refused pre-wipe, quarantined at boot ==="
#################################################################################
# Snapshot secret values (the IPsec PSK below) are encrypted under
# CFG/snapshot-node.secret. Replacing/losing that secret must be LOUD in
# both directions: the boot replay quarantines the now-undecryptable
# snapshot instead of half-applying, and a REST restore of the foreign
# document is refused BEFORE anything is wiped -- live config survives.
NGPSK="ng-psk-negative-fixture"
rc=$(plib_curl llb1 -o /dev/null -w "%{http_code}" -X POST "$PLIB_API/config/ipsec/tunnels" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"ng-tun1\",\"localIp\":\"31.31.31.250\",\"remoteIp\":\"31.31.31.249\",\"authMode\":\"psk\",\"psk\":\"$NGPSK\",\"localId\":\"ng-a\",\"remoteId\":\"ng-b\",\"ikeVersion\":\"ikev2\",\"tunnelMode\":\"tunnel\",\"auto\":\"add\"}")
[[ "$rc" == "204" || "$rc" == "200" ]] \
    && pass "ipsec PSK tunnel staged (encrypted-value subject)" \
    || fail "ipsec tunnel POST: HTTP $rc"
persist_and_verify llb1 \
    && pass "persist carries the tunnel" || fail "persist with ipsec tunnel"
if sudo grep -q 'enc:v1:' "$CFG/snapshot.json" && ! sudo grep -q "$NGPSK" "$CFG/snapshot.json"; then
    pass "persisted document carries the PSK encrypted, never plaintext"
else
    fail "snapshot.json plaintext/ciphertext posture wrong"
fi
sudo cat "$CFG/snapshot.json" > "$PLIB_ARTIFACTS/enc-under-old-secret.json"
# The secret backup deliberately stays OUT of PLIB_ARTIFACTS: uploading
# the secret next to the ciphertext document would hand evidence readers
# the decryption key.
NGSECBAK=$(mktemp /tmp/ng-node-secret.XXXXXX)
sudo cat "$CFG/snapshot-node.secret" > "$NGSECBAK"

# Replace the node secret with a fresh, VALID-format one (the corrupt-file
# case is a unit-level refusal; this is the ops-relevant "wrong node" /
# re-provisioned case) and reboot onto the now-undecryptable snapshot.
q0=$(quarantine_count)
python3 -c "print('ab'*32)" | sudo tee "$CFG/snapshot-node.secret" >/dev/null
sudo chmod 600 "$CFG/snapshot-node.secret"
plib_start_gw llb1 || fail "gateway did not come back after the wrong-secret boot"
plib_wait_api llb1 || fail "API after wrong-secret boot"
[[ "$(quarantine_count)" == "$((q0+1))" ]] \
    && pass "undecryptable snapshot quarantined at boot (fail closed)" \
    || fail "no quarantine artifact for the wrong-secret boot"
docker exec llb1 grep -aq "snapshot-node.secret" /tmp/loxilb.out \
    && pass "boot log names the node secret file (operator-actionable)" \
    || fail "node secret not named in the boot log"
[[ "$(lb_count)" == "0" ]] \
    && pass "clean empty boot after the wrong-secret quarantine" \
    || fail "unexpected config after wrong-secret boot"

# Pre-wipe refusal on the RUNNING node: seed live state, then push the
# old-secret document -- it must be refused with the live state untouched
# (a mid-apply failure would have wiped and rolled back instead).
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/good.json")
[[ "$rc" == "200" && "$(lb_count)" == "1" ]] \
    && pass "canary state restored under the new secret" \
    || fail "canary restore: HTTP $rc lb=$(lb_count)"
q1=$(quarantine_count)
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/enc-under-old-secret.json")
body=$(cat "$PLIB_ARTIFACTS/restore-response.json")
if [[ "$rc" == "400" ]] && echo "$body" | grep -q "snapshot-node.secret"; then
    pass "old-secret document refused pre-wipe (HTTP 400, names the secret file)"
else
    fail "old-secret restore: HTTP $rc body=$(echo "$body" | head -c 200)"
fi
[[ "$(lb_count)" == "1" && "$(quarantine_count)" == "$q1" ]] \
    && pass "live state survived the refusal untouched (nothing wiped)" \
    || fail "refusal side effects: lb=$(lb_count) quarantines moved"

# Recovery through the real operator path: put the original secret back,
# reboot, and REST-restore the old-secret document -- everything decrypts
# again, down to strongSwan holding the plaintext PSK.
sudo cp "$NGSECBAK" "$CFG/snapshot-node.secret"
sudo chmod 600 "$CFG/snapshot-node.secret"
plib_start_gw llb1 || fail "gateway did not come back after secret recovery"
plib_wait_api llb1 || fail "API after secret recovery"
# This boot has a VALID snapshot.json (the canary write-through, no
# secret values) to replay -- the write gate holds mutating calls (503)
# until it settles, so wait for the receipt before restoring.
wait_replay_receipt llb1 || fail "canary snapshot never settled on the recovery boot"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/enc-under-old-secret.json")
[[ "$rc" == "200" ]] \
    && pass "old-secret document restores once its secret is back" \
    || fail "recovery restore: HTTP $rc"
docker exec llb1 grep -aq "$NGPSK" /etc/ipsec.secrets \
    && pass "recovered tunnel handed strongSwan the plaintext PSK" \
    || fail "strongSwan secrets missing the PSK after recovery"
rm -f "$NGSECBAK"
resp=$($hexec l3h1 curl -s -m 5 "http://${VIP}:2020/" 2>/dev/null | head -3)
echo "$resp" | grep -q 'X-Echo-Backend' \
    && pass "recovered VIP routes traffic after the secret-recovery boot" \
    || fail "recovered VIP probe: $resp"

#################################################################################
echo "=== injected capture failure: persist refused, old snapshot kept, auto-persist surfaced ==="
#################################################################################
# LOXI_TEST_FAULT=capture-domain-error:firewall makes every capture fail
# on the firewall Get. A manual persist must answer 5xx with the previous
# snapshot.json untouched, and a config change whose auto-persist then
# fails must surface on the readiness API instead of dying silently.
sum_before=$(sudo jq -r '.checksum' "$CFG/snapshot.json")
PLIB_GW_ENV="LOXI_TEST_FAULT=capture-domain-error:firewall" plib_start_gw llb1 \
    || fail "gateway did not come back with the capture fault armed"
plib_wait_api llb1 || fail "API with capture fault armed"
wait_replay_receipt llb1 || fail "boot replay under capture fault (apply path is unfaulted)"
rc=$(plib_curl llb1 -o "$PLIB_ARTIFACTS/persist-fault.json" -w "%{http_code}" -X POST "$PLIB_API/config/persist")
[[ "$rc" == "500" ]] \
    && pass "manual persist fails loudly when a domain capture fails (500)" \
    || fail "faulted persist: HTTP $rc, want 500"
[[ "$(sudo jq -r '.checksum' "$CFG/snapshot.json")" == "$sum_before" ]] \
    && pass "previous snapshot.json survived the failed persist" \
    || fail "snapshot.json changed under a failed capture"
rc=$(plib_curl llb1 -o /dev/null -w "%{http_code}" -X POST "$PLIB_API/config/firewall" \
    -H 'Content-Type: application/json' \
    -d '{"ruleArguments":{"sourceIP":"7.7.7.7/32","destinationIP":"6.6.6.6/32"},"opts":{"drop":true}}')
[[ "$rc" == "200" || "$rc" == "204" ]] || fail "canary firewall add: HTTP $rc"
sleep 6   # let the auto-persist debounce fire and fail
rrc=$(plib_curl llb1 -o "$PLIB_ARTIFACTS/ready-autopersist.json" -w "%{http_code}" "$PLIB_API/status/ready")
rready=$(jq -r '.ready' < "$PLIB_ARTIFACTS/ready-autopersist.json")
rreason=$(jq -r '(.reasons // []) | join(" ")' < "$PLIB_ARTIFACTS/ready-autopersist.json")
if [[ "$rrc" == "503" && "$rready" == "false" ]] && echo "$rreason" | grep -qi "auto-persist"; then
    pass "auto-persist failure surfaces as NOT-READY with an auto-persist reason"
else
    fail "readiness under auto-persist failure: HTTP $rrc ready=$rready reasons=$rreason"
fi
PLIB_GW_ENV="" plib_start_gw llb1 || fail "gateway did not come back fault-free"
plib_wait_api llb1 || fail "API after clearing the capture fault"
wait_replay_receipt llb1 || fail "clean replay after capture-fault leg"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/good.json")
[[ "$rc" == "200" && "$(fw_count)" == "1" ]] \
    && pass "recovered to the good document after the capture-fault leg" \
    || fail "capture-fault recovery: HTTP $rc fw=$(fw_count)"

#################################################################################
echo "=== deterministic persist crashes: previous snapshot survives both points ==="
#################################################################################
# The fault hook kills the process at the exact points a real crash could
# hit: after the temp write and just before the rename. Both must leave
# the previous snapshot.json byte-identical, leave the orphan temp file
# unconsumed, and boot back cleanly from the old snapshot.
for point in persist-after-temp-write persist-before-rename; do
    sum0=$(sudo jq -r '.checksum' "$CFG/snapshot.json")
    PLIB_GW_ENV="LOXI_TEST_FAULT=$point" plib_start_gw llb1 \
        || fail "gateway did not come back with $point armed"
    plib_wait_api llb1 || fail "API with $point armed"
    wait_replay_receipt llb1 || fail "boot replay with $point armed (persist path untouched at boot)"
    plib_curl llb1 -o /dev/null -m 10 -X POST "$PLIB_API/config/persist" 2>/dev/null
    sleep 2
    if docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1; then
        fail "$point: gateway survived the crash point (fault did not fire)"
    else
        pass "$point: persist crashed the process at the injected point"
    fi
    [[ "$(sudo jq -r '.checksum' "$CFG/snapshot.json")" == "$sum0" ]] \
        && pass "$point: previous snapshot.json byte-survived the crash" \
        || fail "$point: snapshot.json changed across the crash"
    tmpn=$(sudo sh -c "ls $CFG/.snapshot.json-*.tmp 2>/dev/null | wc -l")
    [[ "$tmpn" -ge 1 ]] \
        && pass "$point: orphan temp file left behind, never consumed" \
        || fail "$point: no orphan temp file after the crash"
    sudo rm -f "$CFG"/.snapshot.json-*.tmp
    PLIB_GW_ENV="" plib_start_gw llb1 || fail "gateway did not boot after the $point crash"
    plib_wait_api llb1 || fail "API after the $point crash"
    wait_replay_receipt llb1 || fail "boot from the previous snapshot after $point"
    [[ "$(lb_count)" == "1" ]] \
        && pass "$point: booted from the previous valid snapshot" \
        || fail "$point: lb=$(lb_count) after crash reboot"
done

#################################################################################
echo "=== injected mid-apply failure rolls back; double fault surfaces ROLLBACK-FAILED ==="
#################################################################################
# restore-mid-apply:firewall fails the forward APPLY of the firewall
# domain: the pipeline must roll back to the preserved pre-state and say
# rolled-back. The -double variant fails the rollback re-apply too and
# must surface ROLLBACK-FAILED -- never a silent ok. The armed fault
# would also fire on a boot replay that applies firewall, so these boots
# run WITHOUT a snapshot (that interaction is the quarantine legs' story,
# not this one).
sudo rm -f "$CFG/snapshot.json"
PLIB_GW_ENV="LOXI_TEST_FAULT=restore-mid-apply:firewall" plib_start_gw llb1 \
    || fail "gateway did not come back with the mid-apply fault armed"
plib_wait_api llb1 || fail "API with mid-apply fault armed"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/good.json")
rres=$(jq -r '.result' < "$PLIB_ARTIFACTS/restore-response.json")
[[ "$rc" == "500" && "$rres" == "rolled-back" ]] \
    && pass "mid-apply fault -> 500 rolled-back" \
    || fail "mid-apply restore: HTTP $rc result=$rres"
[[ "$(fw_count)" == "0" && "$(lb_count)" == "0" ]] \
    && pass "rollback restored the (empty) pre-state deep-equal" \
    || fail "post-rollback state: fw=$(fw_count) lb=$(lb_count), want 0/0"

sudo rm -f "$CFG/snapshot.json"
PLIB_GW_ENV="LOXI_TEST_FAULT=restore-mid-apply-double:firewall" plib_start_gw llb1 \
    || fail "gateway did not come back with the double fault armed"
plib_wait_api llb1 || fail "API with double fault armed"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/good.json")
rres=$(jq -r '.result' < "$PLIB_ARTIFACTS/restore-response.json")
[[ "$rc" == "500" && "$rres" == "ROLLBACK-FAILED" ]] \
    && pass "double fault -> ROLLBACK-FAILED surfaced, not a silent ok" \
    || fail "double-fault restore: HTTP $rc result=$rres"

PLIB_GW_ENV="" plib_start_gw llb1 || fail "gateway did not come back fault-free after NG-10"
plib_wait_api llb1 || fail "API after the fault legs"
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/good.json")
[[ "$rc" == "200" && "$(lb_count)" == "1" && "$(fw_count)" == "1" ]] \
    && pass "clean recovery after the fault-injection legs" \
    || fail "fault-leg recovery: HTTP $rc lb=$(lb_count) fw=$(fw_count)"
resp=$($hexec l3h1 curl -s -m 5 "http://${VIP}:2020/" 2>/dev/null | head -3)
echo "$resp" | grep -q 'X-Echo-Backend' \
    && pass "VIP routes traffic after the fault-injection legs" \
    || fail "post-fault VIP probe: $resp"

#################################################################################
echo "=== concurrency storm: the gate serializes, nothing tears ==="
#################################################################################
# Persists, captures, a commit restore and config mutations all fired at
# once, three rounds. The contract: the snapshot endpoints serialize on
# the gate and answer 409 when it is held, every OTHER mutating call is
# frozen with 503 while a restore holds it, and nothing anywhere answers
# 5xx. A round that produced no rejection at all never contended the gate
# -- three such rounds fail the leg rather than pass it vacuously.
STORM="$PLIB_ARTIFACTS/ng08"
mkdir -p "$STORM"
storm_round() { # storm_round <round> — fire the whole storm, wait for all of it
    local r=$1 i
    rm -f "$STORM/r$r-"*.code
    for i in 1 2 3; do
        ( plib_curl llb1 -o "$STORM/r$r-persist-$i.body" -w "%{http_code}" \
            -X POST "$PLIB_API/config/persist" > "$STORM/r$r-persist-$i.code" ) &
    done
    for i in 1 2; do
        ( plib_curl llb1 -o "$STORM/r$r-capture-$i.body" -w "%{http_code}" \
            "$PLIB_API/config/snapshot" > "$STORM/r$r-capture-$i.code" ) &
    done
    ( plib_curl llb1 -o "$STORM/r$r-restore.body" -w "%{http_code}" \
        -X POST "$PLIB_API/config/restore?mode=commit" \
        -H 'Content-Type: application/json' --data-binary @"$PLIB_ARTIFACTS/good.json" \
        > "$STORM/r$r-restore.code" ) &
    for i in $(seq 1 6); do
        ( plib_curl llb1 -o /dev/null -w "%{http_code}" \
            -X POST "$PLIB_API/config/firewall" -H 'Content-Type: application/json' \
            -d "{\"ruleArguments\":{\"sourceIP\":\"9.$r.0.$i/32\",\"destinationIP\":\"6.6.6.6/32\"},\"opts\":{\"drop\":true}}" \
            > "$STORM/r$r-mutate-$i.code" ) &
    done
    wait
}
q_storm=$(quarantine_count)
storm_contract_ok=1
storm_rejections=0
for r in 1 2 3; do
    storm_round "$r"
    for f in "$STORM/r$r-persist-"*.code "$STORM/r$r-capture-"*.code "$STORM/r$r-restore.code"; do
        c=$(cat "$f" 2>/dev/null)
        case "$c" in
        200) ;;
        409) storm_rejections=$((storm_rejections + 1)) ;;
        *)  fail "storm round $r: $(basename "$f" .code) answered HTTP $c (contract: 200 or 409)"
            storm_contract_ok=0 ;;
        esac
    done
    for f in "$STORM/r$r-mutate-"*.code; do
        c=$(cat "$f" 2>/dev/null)
        case "$c" in
        200|204) ;;
        503) storm_rejections=$((storm_rejections + 1)) ;;
        *)  fail "storm round $r: mutation $(basename "$f" .code) answered HTTP $c (contract: 200/204 or 503)"
            storm_contract_ok=0 ;;
        esac
    done
done
[[ "$storm_contract_ok" == 1 ]] \
    && pass "3 storm rounds: every response inside the gate contract (no 5xx, no torn semantics)" \
    || fail "storm rounds broke the response-code contract"
[[ "$storm_rejections" -ge 1 ]] \
    && pass "the gate actually rejected concurrent callers ($storm_rejections rejections across 3 rounds)" \
    || fail "no 409/503 in 3 storm rounds: the gate was never contended, so the leg proved nothing"
# The gate must not leak: a plain persist after the storm has to succeed.
sleep 6   # let the storm's auto-persist debounce drain first
if persist_and_verify llb1; then
    pass "gate released after the storm: a fresh persist succeeds"
else
    fail "persist after the storm failed (gate leak or unpersistable state)"
fi
rc=$(restore_dryrun llb1 "$CFG/snapshot.json")
rres=$(jq -r '.result' < "$PLIB_ARTIFACTS/restore-response.json")
[[ "$rc" == "200" && "$rres" == "ok" ]] \
    && pass "post-storm snapshot.json parses, checksum-verifies and plans cleanly" \
    || fail "post-storm document integrity: HTTP $rc result=$rres"
[[ "$(quarantine_count)" == "$q_storm" ]] \
    && pass "the storm produced no quarantine artifacts" \
    || fail "storm quarantined a snapshot: $(quarantine_count) artifacts, was $q_storm"
# Whatever the storm left must survive a restart deep-equal: a capture torn
# by a concurrent mutation would surface here as a post-reboot diff.
canonical_get_all llb1 "$PLIB_ARTIFACTS/ng08-before" || fail "post-storm canonical dump"
restart_inplace_keep llb1 || fail "restart after the storm"
canonical_get_all llb1 "$PLIB_ARTIFACTS/ng08-after" || fail "post-restart canonical dump"
deep_diff "$PLIB_ARTIFACTS/ng08-before" "$PLIB_ARTIFACTS/ng08-after" ng08 \
    && pass "post-storm state round-trips a restart deep-equal (nothing tore)" \
    || fail "post-storm state changed across the restart (torn capture)"

#################################################################################
echo "=== SIGKILL inside the auto-persist debounce: integrity always, loss documented ==="
#################################################################################
# Ten rounds, each killing the gateway at a different offset inside the 3s
# auto-persist quiet window. The contract here is INTEGRITY, not no-loss:
# a mutation that never made it out of the debounce is DOCUMENTED loss, so
# the asserts are that snapshot.json is always a parseable, checksum-valid
# document, that the boot never quarantines it, and that the pre-existing
# state always comes back. A round is allowed to keep or lose its own
# mutation -- never anything else.
ng11_ok=1
ng11_kept=0
for i in $(seq 1 10); do
    delay=$(awk -v n="$i" 'BEGIN{printf "%.1f", 0.2 + (n-1)*0.3}')   # 0.2s .. 2.9s
    fw_before=$(fw_count)
    rc=$(plib_curl llb1 -o /dev/null -w "%{http_code}" -X POST "$PLIB_API/config/firewall" \
        -H 'Content-Type: application/json' \
        -d "{\"ruleArguments\":{\"sourceIP\":\"8.8.$i.1/32\",\"destinationIP\":\"6.6.6.6/32\"},\"opts\":{\"drop\":true}}")
    if [[ "$rc" != "200" && "$rc" != "204" ]]; then
        fail "SIGKILL round $i: mutation refused (HTTP $rc)"; ng11_ok=0; break
    fi
    q_round=$(quarantine_count)
    sleep "$delay"
    docker exec llb1 pkill -9 -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1
    for _ in $(seq 1 10); do
        docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1 || break
        sleep 1
    done
    if ! sudo test -s "$CFG/snapshot.json"; then
        fail "SIGKILL round $i (kill at ${delay}s): snapshot.json missing or empty on disk"
        ng11_ok=0; break
    fi
    plib_start_gw llb1 || { fail "SIGKILL round $i: gateway did not come back"; ng11_ok=0; break; }
    plib_wait_api llb1 || { fail "SIGKILL round $i: API never returned"; ng11_ok=0; break; }
    if ! wait_replay_receipt llb1; then
        fail "SIGKILL round $i (kill at ${delay}s): boot never replayed the snapshot"; ng11_ok=0; break
    fi
    if [[ "$(quarantine_count)" != "$q_round" ]]; then
        fail "SIGKILL round $i (kill at ${delay}s): boot quarantined the snapshot (corruption)"; ng11_ok=0; break
    fi
    rc=$(restore_dryrun llb1 "$CFG/snapshot.json")
    rres=$(jq -r '.result' < "$PLIB_ARTIFACTS/restore-response.json")
    if [[ "$rc" != "200" || "$rres" != "ok" ]]; then
        fail "SIGKILL round $i (kill at ${delay}s): snapshot.json not a valid document (HTTP $rc result=$rres)"
        ng11_ok=0; break
    fi
    if [[ "$(lb_count)" != "1" ]]; then
        fail "SIGKILL round $i (kill at ${delay}s): pre-existing LB state lost (lb=$(lb_count), want 1)"
        ng11_ok=0; break
    fi
    fw_after=$(fw_count)
    if [[ "$fw_after" == "$((fw_before + 1))" ]]; then
        ng11_kept=$((ng11_kept + 1))
    elif [[ "$fw_after" != "$fw_before" ]]; then
        fail "SIGKILL round $i (kill at ${delay}s): firewall count $fw_after, want $fw_before or $((fw_before + 1)) (torn state)"
        ng11_ok=0; break
    fi
done
if [[ "$ng11_ok" == 1 ]]; then
    pass "10 SIGKILL rounds across the debounce window: snapshot.json always a valid document"
    pass "10 SIGKILL rounds: no quarantine, boot replay settled, pre-existing state intact every time"
    echo "  (mutations that survived their kill: $ng11_kept/10 -- loss inside the debounce is documented behavior, not a defect)"
fi

plib_collect_logs llb1
exit $code
