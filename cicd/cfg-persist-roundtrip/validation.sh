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
echo "=== snapshot document: new domains + secret split ==="
#################################################################################
# The four newest domains must be IN the document as desired state -- and
# the two secret-bearing ones must carry references only: header VALUES
# live in the node-local otlp-headers.json, PEM/keys only under
# llb1_config/certs/. A snapshot that embeds either is a defect, never a
# convenience.
tr_ep=$(jq -r '.domains.tracing.endpoint' < "$PLIB_ARTIFACTS/snap-idle-1.json")
tr_names=$(jq -c '.domains.tracing.header_names' < "$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$tr_ep" == "127.0.0.1:4317" && "$tr_names" == '["X-API-Key"]' ]] \
    && pass "tracing domain captured (endpoint + header NAME)" \
    || fail "tracing domain endpoint=$tr_ep header_names=$tr_names"
if grep -q 'rt-otlp-secret' "$PLIB_ARTIFACTS/snap-idle-1.json"; then
    fail "OTLP header VALUE leaked into the snapshot document"
else
    pass "OTLP header value absent from the document (secret split)"
fi
if sudo test -f llb1_config/otlp-headers.json \
   && [[ "$(sudo stat -c %a llb1_config/otlp-headers.json)" == "600" ]] \
   && sudo grep -q 'rt-otlp-secret' llb1_config/otlp-headers.json; then
    pass "header value persisted node-locally (otlp-headers.json, 0600)"
else
    fail "node-local otlp-headers.json missing/wrong mode/missing value"
fi

cert_id=$(jq -r '.domains.cert[0].cert_id' < "$PLIB_ARTIFACTS/snap-idle-1.json")
cert_dig=$(jq -r '.domains.cert[0].digest' < "$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$cert_id" == "rt-cert1" && "$cert_dig" == sha256:* ]] \
    && pass "cert domain captured as {cert_id, digest} metadata" \
    || fail "cert domain: id=$cert_id digest=$cert_dig"
if grep -q 'PRIVATE KEY\|BEGIN CERTIFICATE' "$PLIB_ARTIFACTS/snap-idle-1.json"; then
    fail "PEM material leaked into the snapshot document"
else
    pass "no PEM material in the document (cert secret split)"
fi

corig=$(jq -c '.domains.cors.origins' < "$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$corig" == '["http://rt-allowed.example"]' ]] \
    && pass "cors domain captured (explicit allowlist)" \
    || fail "cors domain origins=$corig"
npol=$(jq -r '.domains.l7policy | length' < "$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$npol" == "1" ]] \
    && pass "l7policy domain captured (1 policy)" \
    || fail "l7policy domain count=$npol, want 1"

#################################################################################
echo "=== recovery_dependencies manifest: declared, honest, deterministic ==="
#################################################################################
# Schema 1.4: the document names every external store a recovery of it
# depends on -- identity only (type/id/generation/digest), never store
# content. This topology pins all three content-scoped entries: the KV
# binding makes the contract + profile registries REQUIRED, the managed
# cert makes the cert store REQUIRED; no database is wired, so no DB entry
# may appear. (The negative suite proves the REQUIRED flags bite.)
sv=$(jq -r '.schema_version' < "$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$sv" == "1.5" ]] \
    && pass "document rides schema 1.5" \
    || fail "schema_version=$sv, want 1.5"
dep_types=$(jq -c '[.recovery_dependencies[].type]' < "$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$dep_types" == '["cert-store","engine-contracts","kv-model-profiles"]' ]] \
    && pass "manifest declares exactly the wired stores, (type,id)-sorted" \
    || fail "manifest types=$dep_types, want cert-store/engine-contracts/kv-model-profiles"
dep_req=$(jq -c '[.recovery_dependencies[].required]' < "$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$dep_req" == '[true,true,true]' ]] \
    && pass "captured binding + cert make every entry REQUIRED" \
    || fail "manifest required flags=$dep_req, want all true"
ec_gen=$(jq -r '.recovery_dependencies[] | select(.type=="engine-contracts") | .generation' \
    < "$PLIB_ARTIFACTS/snap-idle-1.json")
ec_dig=$(jq -r '.recovery_dependencies[] | select(.type=="engine-contracts") | .digest' \
    < "$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$ec_gen" =~ ^[0-9]+$ && "$ec_dig" == sha256:* ]] \
    && pass "engine-contracts entry carries the compiled generation + digest" \
    || fail "engine-contracts entry gen=$ec_gen digest=$ec_dig"
kv_id=$(jq -r '.recovery_dependencies[] | select(.type=="kv-model-profiles") | .id' \
    < "$PLIB_ARTIFACTS/snap-idle-1.json")
kv_gen=$(jq -r '.recovery_dependencies[] | select(.type=="kv-model-profiles") | .generation' \
    < "$PLIB_ARTIFACTS/snap-idle-1.json")
kv_dig=$(jq -r '.recovery_dependencies[] | select(.type=="kv-model-profiles") | .digest' \
    < "$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$kv_id" == "/etc/loxilb/kvprofiles" && "$kv_gen" =~ ^[0-9]+$ && "$kv_dig" == sha256:* ]] \
    && pass "kv-model-profiles entry carries source root + published generation + set digest" \
    || fail "kv-model-profiles entry id=$kv_id gen=$kv_gen digest=$kv_dig"
cs_dig=$(jq -r '.recovery_dependencies[] | select(.type=="cert-store") | .digest' \
    < "$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$cs_dig" == sha256:* ]] \
    && pass "cert-store entry summarizes the captured cert set (digest)" \
    || fail "cert-store entry digest=$cs_dig"
# Identity must never carry store content or credentials: every manifest
# field is type/id/generation/digest/required -- nothing else.
dep_extra=$(jq -r '[.recovery_dependencies[] | keys[]] | unique - ["type","id","generation","digest","required"] | length' \
    < "$PLIB_ARTIFACTS/snap-idle-1.json")
[[ "$dep_extra" == "0" ]] \
    && pass "manifest entries carry identity fields only" \
    || fail "manifest entries carry $dep_extra unexpected field(s)"
# Determinism rides the same idle-capture pair as the domains leg: an
# unchanged gateway must declare the identical manifest.
dep_m1=$(jq -S '.recovery_dependencies' < "$PLIB_ARTIFACTS/snap-idle-1.json")
dep_m2=$(jq -S '.recovery_dependencies' < "$PLIB_ARTIFACTS/snap-idle-2.json")
[[ -n "$dep_m1" && "$dep_m1" == "$dep_m2" ]] \
    && pass "manifest identical across idle captures (deterministic)" \
    || fail "manifest churned between idle captures"

#################################################################################
echo "=== persist response contract: identity, coverage, dependency status ==="
#################################################################################
# POST /config/persist answers with the persisted document's identity
# (schema/generation/checksum), its coverage, and the dependency manifest
# with capture-time statuses, so automation can verify what was saved
# without re-reading the file.
persist_and_verify llb1 || fail "persist for the response-contract legs failed"
presp="$PLIB_ARTIFACTS/persist-response.json"
psv=$(jq -r '.schema_version' < "$presp")
[[ "$psv" == "1.5" ]] \
    && pass "persist response carries the persisted document's schema (1.5)" \
    || fail "persist response schema_version=$psv, want 1.5"
pgen1=$(jq -r '.generation' < "$presp")
[[ "$pgen1" =~ ^[0-9]+$ && "$pgen1" -ge 1 ]] \
    && pass "persist response carries a lineage generation ($pgen1)" \
    || fail "persist response generation=$pgen1, want a positive integer"
fgen=$(sudo cat llb1_config/snapshot.json | jq -r '.generation')
[[ "$fgen" == "$pgen1" ]] \
    && pass "on-disk snapshot carries the same generation as the response" \
    || fail "file generation $fgen != response generation $pgen1"
persist_and_verify llb1 || fail "second persist for the monotonicity leg failed"
pgen2=$(jq -r '.generation' < "$presp")
[[ "$pgen2" == "$((pgen1 + 1))" ]] \
    && pass "back-to-back persists increment the generation ($pgen1 -> $pgen2)" \
    || fail "generation went $pgen1 -> $pgen2, want exactly +1"
pcov=$(jq -r '.included_domains | index("loadbalancer") != null and length >= 17' < "$presp")
[[ "$pcov" == "true" ]] \
    && pass "persist response declares full domain coverage" \
    || fail "persist response included_domains=$(jq -c '.included_domains' < "$presp")"
pdep_types=$(jq -c '[.external_dependencies[].type]' < "$presp")
[[ "$pdep_types" == '["cert-store","engine-contracts","kv-model-profiles"]' ]] \
    && pass "persist response reports the manifest's dependency identities" \
    || fail "persist response dependency types=$pdep_types"
pdep_status=$(jq -c '[.external_dependencies[].status] | unique' < "$presp")
[[ "$pdep_status" == '["ready"]' ]] \
    && pass "capture-time dependency statuses all ready (no DB wired here)" \
    || fail "persist response dependency statuses=$pdep_status, want all ready"
pwarn=$(jq -c '.warnings' < "$presp")
[[ "$pwarn" == "[]" ]] \
    && pass "clean save reports no warnings" \
    || fail "persist response warnings=$pwarn, want []"

#################################################################################
echo "=== L7 policy / CORS / TLS-SNI datapath baselines (before) ==="
#################################################################################
# With a policy ATTACHED, the routing table is authoritative: the matched
# route answers its OWN status (451 here, non-default on purpose) and a
# non-matching path gets the Gateway-API no-match default 404
# (sockproxy_l7policy.c route dispatch). A LOST policy flips both probes
# to plain forwarding -- the pair pins presence AND field fidelity.
rc_blk=$($hexec l3h1 curl -s -m 5 -o /dev/null -w "%{http_code}" "http://${PVIP}:8082/blocked" 2>/dev/null)
[[ "$rc_blk" == "451" ]] \
    && pass "L7 REJECT enforced with its configured status (before, 451)" \
    || fail "GET /blocked -> HTTP $rc_blk, want 451"
rc_open=$($hexec l3h1 curl -s -m 5 -o /dev/null -w "%{http_code}" "http://${PVIP}:8082/open" 2>/dev/null)
[[ "$rc_open" == "404" ]] \
    && pass "non-matching path gets the no-match default (before, 404)" \
    || fail "GET /open -> HTTP $rc_open, want the 404 no-match default"

cors_probe() { # cors_probe <origin> — prints the allow-origin grant (empty = none)
    plib_curl llb1 -D - -o /dev/null -X OPTIONS -H "Origin: $1" "$PLIB_API/version" 2>/dev/null \
        | tr -d '\r' | awk -F': ' 'tolower($1)=="access-control-allow-origin" {print $2}'
}
g_ok=$(cors_probe "http://rt-allowed.example")
g_evil=$(cors_probe "http://rt-evil.example")
[[ "$g_ok" == "http://rt-allowed.example" ]] \
    && pass "allowlisted origin granted (before)" \
    || fail "allowlisted origin grant='$g_ok' (before)"
[[ -z "$g_evil" ]] \
    && pass "unlisted origin gets NO grant -- no reflection (before)" \
    || fail "unlisted origin was granted '$g_evil' (before)"

sni_subject() { # prints the leaf-cert subject served for SNI rt-sni.test
    $hexec l3h1 bash -c \
        "echo | openssl s_client -servername rt-sni.test -connect ${PVIP}:8443 2>/dev/null | openssl x509 -noout -subject" 2>/dev/null
}
subj=$(sni_subject)
echo "$subj" | grep -q 'rt-sni.test' \
    && pass "SNI handshake serves the managed cert (before)" \
    || fail "SNI handshake subject '$subj' (before)"

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
    echo "  RED-TWIN: mutating fw + l7policy + cors + otlp secret after the baseline capture"
    plib_curl llb1 -o /dev/null -X DELETE \
        "$PLIB_API/config/firewall?sourceIP=77.77.77.7%2F32&destinationIP=20.20.20.1%2F32"
    # Each mutation targets one NEW assert class: the policy delete must
    # trip the RT-07 enforcement leg, the cors delete the grant leg, the
    # secret-file removal the node-local survival leg (persist rewrites
    # only snapshot.json, so the file stays gone across the restart).
    plib_curl llb1 -o /dev/null -X DELETE "$PLIB_API/config/l7policy/id/rt-l7pol1"
    plib_curl llb1 -o /dev/null -X DELETE "$PLIB_API/config/cors/http%3A%2F%2Frt-allowed.example"
    sudo rm -f llb1_config/otlp-headers.json
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
echo "=== L7 REJECT still rejects after restart ==="
#################################################################################
rc_blk=$($hexec l3h1 curl -s -m 5 -o /dev/null -w "%{http_code}" "http://${PVIP}:8082/blocked" 2>/dev/null)
[[ "$rc_blk" == "451" ]] \
    && pass "L7 REJECT survived the restart field-faithfully (451, not default 403)" \
    || fail "GET /blocked after restart -> HTTP $rc_blk, want 451"
rc_open=$($hexec l3h1 curl -s -m 5 -o /dev/null -w "%{http_code}" "http://${PVIP}:8082/open" 2>/dev/null)
[[ "$rc_open" == "404" ]] \
    && pass "no-match default intact after restart (404 -- policy still attached)" \
    || fail "GET /open after restart -> HTTP $rc_open, want 404 (200 would mean the policy detached)"

#################################################################################
echo "=== CORS allowlist survived the restart (no fail-open, no reflection) ==="
#################################################################################
g_ok=$(cors_probe "http://rt-allowed.example")
g_evil=$(cors_probe "http://rt-evil.example")
[[ "$g_ok" == "http://rt-allowed.example" ]] \
    && pass "allowlisted origin still granted after restart" \
    || fail "allowlisted origin grant='$g_ok' after restart"
[[ -z "$g_evil" ]] \
    && pass "unlisted origin still refused after restart (no fail-open to *)" \
    || fail "unlisted origin granted '$g_evil' after restart"

#################################################################################
echo "=== OTLP export config + node-local header secret survived ==="
#################################################################################
plib_curl llb1 "$PLIB_API/config/trace/otlp" -o "$PLIB_ARTIFACTS/otlp-after.json"
o_ep=$(jq -r '.endpoint' < "$PLIB_ARTIFACTS/otlp-after.json")
[[ "$o_ep" == "127.0.0.1:4317" ]] \
    && pass "OTLP endpoint survived the restart" \
    || fail "OTLP endpoint after restart '$o_ep'"
if sudo test -f llb1_config/otlp-headers.json \
   && sudo grep -q 'rt-otlp-secret' llb1_config/otlp-headers.json; then
    pass "node-local header secret survived (value re-joinable by name)"
else
    fail "otlp-headers.json missing/empty after restart"
fi

#################################################################################
echo "=== managed cert re-registered at boot: SNI handshake (the reboot probe) ==="
#################################################################################
subj=$(sni_subject)
echo "$subj" | grep -q 'rt-sni.test' \
    && pass "SNI handshake still serves the managed cert after restart" \
    || fail "SNI handshake subject '$subj' after restart"

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
# The manifest is built from process-stable identities (compiled contract
# constants, the reloaded profile generation, the cert set), so an
# unchanged gateway must re-declare the identical manifest after a restart.
dep_ma=$(jq -S '.recovery_dependencies' < "$PLIB_ARTIFACTS/snap-after.json")
[[ -n "$dep_ma" && "$dep_ma" == "$dep_m1" ]] \
    && pass "recovery_dependencies manifest identical across restart" \
    || fail "recovery_dependencies manifest drifted across restart"

#################################################################################
echo "=== configured-EMPTY cors: deny-all survives a restart (no re-seed) ==="
#################################################################################
# Removing the last origin must leave DENY-ALL, and a restart must NOT
# quietly re-seed the factory-open default: configured-empty and
# unconfigured are different desired states and the document must keep
# them apart. (This leg mutates config, so it runs after every
# deep-diff/baseline assert, and re-persists before its restart.)
plib_curl llb1 -o /dev/null -X DELETE "$PLIB_API/config/cors/http%3A%2F%2Frt-allowed.example"
g_ok=$(cors_probe "http://rt-allowed.example")
[[ -z "$g_ok" && "$(cors_probe http://rt-evil.example)" == "" ]] \
    && pass "allowlist emptied -> deny-all live (no grant for anyone)" \
    || fail "deny-all not in effect after removing the last origin (grant='$g_ok')"
persist_and_verify llb1 >/dev/null || fail "persist of the deny-all config"
corig=$(sudo jq -c '.domains.cors' llb1_config/snapshot.json)
[[ "$corig" == '{"origins":[]}' ]] \
    && pass "document captures configured-EMPTY (not unconfigured/absent)" \
    || fail "deny-all captured as $corig"
if restart_inplace_keep llb1 -b; then
    pass "second in-place restart (deny-all document)"
else
    fail "second restart / replay receipt"
fi
plib_wait_api llb1 || fail "API after second restart"
g_ok=$(cors_probe "http://rt-allowed.example")
g_star=$(plib_curl llb1 -D - -o /dev/null -X OPTIONS "$PLIB_API/version" 2>/dev/null \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="access-control-allow-origin" {print $2}')
if [[ -z "$g_ok" && "$g_star" != "*" ]]; then
    pass "deny-all survived the restart -- no re-seed to factory-open"
else
    fail "cors re-seeded after restart (origin grant='$g_ok', wildcard='$g_star')"
fi

plib_collect_logs llb1
exit $code
